"""Phase A assessment persistence — isolated ledgers and mocked providers only.

Never opens data/ledger.sqlite. Never calls paid APIs.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from secrets import token_hex
from unittest import mock

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.ledger import (
    OFFICIAL_ASSESSMENT_OUTCOMES,
    Ledger,
    assessment_failure_message,
    refuse_test_ledger,
)
from app.main import create_app
from app.validation import validate_assessment

DUMMY_OPENAI = "test-openai-key"
DUMMY_PARALLEL = "test-parallel-key"


def _ledger(directory: Path, name: str = "ledger.sqlite") -> str:
    path = Path(directory) / name
    refuse_test_ledger(path)
    return str(path)


def _settings(**overrides) -> Settings:
    data = dict(
        openai_api_key=DUMMY_OPENAI,
        parallel_api_key=DUMMY_PARALLEL,
        parallel_mcp_url="https://search.parallel.ai/mcp",
        openai_model_default="gpt-4.1-mini",
        openai_model_complex="gpt-4.1",
        allowed_origins="",
    )
    data.update(overrides)
    if "ledger_path" not in data:
        raise RuntimeError("ledger_path required")
    return Settings(**data)


def _json_response(payload, status=200):
    return httpx.Response(status, json=payload)


def _auth(client: TestClient, email: str | None = None, password: str = "correct-horse-battery") -> dict:
    email = email or f"user-{token_hex(4)}@example.com"
    assert client.post("/api/auth/register", json={"email": email, "password": password}).status_code == 200
    logged = client.post("/api/auth/login", json={"email": email, "password": password})
    assert logged.status_code == 200
    client.headers["X-CSRF-Token"] = logged.json()["csrfToken"]
    return {"email": email, "password": password, **logged.json()}


def _create(client: TestClient, text: str = "A claim to check.") -> str:
    _auth(client)
    response = client.post("/api/investigations", json={"input": text, "kind": "claim"})
    assert response.status_code == 200
    return response.json()["investigationId"]


def _openai_ok(assessment: str = "UNRESOLVED"):
    content = json.dumps({
        "assessment": assessment,
        "findings": [
            {"type": "support", "text": "Stored sentence match.", "sources": [0]},
        ],
        "originalMaterial": {"established": False, "description": "", "source": None},
        "why": {},
        "uncertainty": [],
    })

    def handler(request: httpx.Request) -> httpx.Response:
        return _json_response({"choices": [{"message": {"content": content}}]})

    return handler


def _search_one():
    def handler(_request: httpx.Request) -> httpx.Response:
        return _json_response({
            "results": [{
                "url": "https://www.cdc.gov/diabetes",
                "title": "Diabetes facts",
                "publish_date": "2024-01-15",
                "excerpts": ["Warm water is not a cure."],
            }],
            "session_id": "stored",
        })

    return handler


def test_schema_check_constraints_and_unique_snapshot(tmp_path):
    path = Path(_ledger(tmp_path))
    ledger = Ledger(path)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON")
    # Seed owner + investigation + snapshot for FK tests.
    conn.execute("INSERT INTO users (id, created_at, email, password_hash) VALUES ('u1', 't', 'a@b.c', 'x')")
    conn.execute(
        "INSERT INTO investigations (id, owner_id, kind, input_text, created_at) VALUES ('i1', 'u1', 'claim', 'c', 't')"
    )
    conn.execute(
        """
        INSERT INTO assessment_snapshots (
            id, investigation_id, owner_id, token_hash, snapshot_json, created_at, expires_at, consumed_at
        ) VALUES ('s1', 'i1', 'u1', 'th1', '{}', 't', '2099-01-01T00:00:00+00:00', 't')
        """
    )
    conn.commit()

    # Completed requires outcomes.
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            """
            INSERT INTO assessment_results (
                id, investigation_id, owner_id, snapshot_id, status,
                model_assessment, facing_assessment, failure_code, failure_message,
                why_json, uncertainty_json, original_material_json, created_at
            ) VALUES ('r0', 'i1', 'u1', 's1', 'completed', NULL, NULL, NULL, NULL, '{}', '[]', '{}', 't')
            """
        )

    conn.execute(
        """
        INSERT INTO assessment_results (
            id, investigation_id, owner_id, snapshot_id, status,
            model_assessment, facing_assessment, failure_code, failure_message,
            why_json, uncertainty_json, original_material_json, created_at
        ) VALUES ('r1', 'i1', 'u1', 's1', 'completed', 'VERIFIED', 'UNRESOLVED', NULL, NULL, '{}', '[]', '{}', 't')
        """
    )
    conn.commit()

    # Unique snapshot
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            """
            INSERT INTO assessment_results (
                id, investigation_id, owner_id, snapshot_id, status,
                model_assessment, facing_assessment, failure_code, failure_message,
                why_json, uncertainty_json, original_material_json, created_at
            ) VALUES ('r2', 'i1', 'u1', 's1', 'failed', NULL, NULL, 'no_model', 'x', NULL, NULL, NULL, 't')
            """
        )

    # Failed requires null outcomes + failure_code
    conn.execute(
        """
        INSERT INTO assessment_snapshots (
            id, investigation_id, owner_id, token_hash, snapshot_json, created_at, expires_at, consumed_at
        ) VALUES ('s2', 'i1', 'u1', 'th2', '{}', 't', '2099-01-01T00:00:00+00:00', 't')
        """
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            """
            INSERT INTO assessment_results (
                id, investigation_id, owner_id, snapshot_id, status,
                model_assessment, facing_assessment, failure_code, failure_message,
                why_json, uncertainty_json, original_material_json, created_at
            ) VALUES ('r3', 'i1', 'u1', 's2', 'failed', 'UNRESOLVED', 'UNRESOLVED', 'no_model', 'x', NULL, NULL, NULL, 't')
            """
        )
    conn.execute(
        """
        INSERT INTO assessment_results (
            id, investigation_id, owner_id, snapshot_id, status,
            model_assessment, facing_assessment, failure_code, failure_message,
            why_json, uncertainty_json, original_material_json, created_at
        ) VALUES ('r4', 'i1', 'u1', 's2', 'failed', NULL, NULL, 'no_model', 'safe', NULL, NULL, NULL, 't')
        """
    )
    conn.commit()

    # Cross-owner FK rejected
    conn.execute("INSERT INTO users (id, created_at, email, password_hash) VALUES ('u2', 't', 'c@d.e', 'x')")
    conn.execute(
        "INSERT INTO investigations (id, owner_id, kind, input_text, created_at) VALUES ('i2', 'u2', 'claim', 'c', 't')"
    )
    conn.execute(
        """
        INSERT INTO assessment_snapshots (
            id, investigation_id, owner_id, token_hash, snapshot_json, created_at, expires_at, consumed_at
        ) VALUES ('s3', 'i2', 'u2', 'th3', '{}', 't', '2099-01-01T00:00:00+00:00', 't')
        """
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            """
            INSERT INTO assessment_results (
                id, investigation_id, owner_id, snapshot_id, status,
                model_assessment, facing_assessment, failure_code, failure_message,
                why_json, uncertainty_json, original_material_json, created_at
            ) VALUES ('r5', 'i1', 'u1', 's3', 'completed', 'UNRESOLVED', 'UNRESOLVED', NULL, NULL, '{}', '[]', '{}', 't')
            """
        )
    conn.close()
    assert assessment_failure_message("no_model")
    assert OFFICIAL_ASSESSMENT_OUTCOMES >= {"VERIFIED", "UNRESOLVED"}


def test_successful_persist_model_vs_facing_and_recovery_apis(tmp_path):
    calls = {"openai": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["openai"] += 1
        content = json.dumps({
            "assessment": "VERIFIED",
            "findings": [{"type": "support", "text": "Warm water is not a cure.", "sources": [0]}],
            "originalMaterial": {"established": True, "description": "x", "source": 0},
            "why": {"supporting": "ignored"},
            "uncertainty": ["ignored"],
        })
        return _json_response({"choices": [{"message": {"content": content}}]})

    app = create_app(
        settings=_settings(ledger_path=_ledger(tmp_path)),
        openai_transport=httpx.MockTransport(handler),
        parallel_transport=httpx.MockTransport(_search_one()),
    )
    with TestClient(app) as client:
        investigation_id = _create(client, "Warm water cures diabetes.")
        assert client.post(
            f"/api/investigations/{investigation_id}/search",
            json={"queries": ["warm water"]},
        ).status_code == 200
        sealed = client.post(f"/api/investigations/{investigation_id}/seal")
        assert sealed.status_code == 200
        token = sealed.json()["assessmentToken"]
        response = client.post(
            f"/api/investigations/{investigation_id}/assess",
            json={"assessmentToken": token},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["assessment"] == "UNRESOLVED"  # facing
        assert "modelAssessment" not in body
        assert body["assessmentResultId"]
        assert body["snapshotId"]
        assert body["assessedAt"]
        assert calls["openai"] == 1

        # DB stores model VERIFIED and facing UNRESOLVED
        path = Path(_settings(ledger_path=_ledger(tmp_path)).ledger_path) if False else None
        del path
        db = sqlite3.connect(str(Path(tmp_path) / "ledger.sqlite"))
        db.row_factory = sqlite3.Row
        row = db.execute("SELECT model_assessment, facing_assessment, status FROM assessment_results").fetchone()
        assert row["status"] == "completed"
        assert row["model_assessment"] == "VERIFIED"
        assert row["facing_assessment"] == "UNRESOLVED"
        findings = db.execute("SELECT COUNT(*) AS c FROM findings").fetchone()["c"]
        assert findings >= 1
        db.close()

        latest = client.get(f"/api/investigations/{investigation_id}/assessments/latest")
        assert latest.status_code == 200
        assert latest.json()["assessment"] == "UNRESOLVED"
        assert latest.json()["assessmentResultId"] == body["assessmentResultId"]
        assert "modelAssessment" not in latest.json()

        by_snap = client.get(
            f"/api/investigations/{investigation_id}/assessments/{body['snapshotId']}"
        )
        assert by_snap.status_code == 200
        assert by_snap.json()["assessmentResultId"] == body["assessmentResultId"]

        history = client.get(f"/api/investigations/{investigation_id}/assessments")
        assert history.status_code == 200
        assert len(history.json()["assessments"]) == 1

        # Used token does not re-call provider; recovery via GET
        reused = client.post(
            f"/api/investigations/{investigation_id}/assess",
            json={"assessmentToken": token},
        )
        assert reused.status_code == 400 or reused.json().get("code") == "assessment_token_used"
        assert calls["openai"] == 1
        recovered = client.get(f"/api/investigations/{investigation_id}/assessments/latest")
        assert recovered.status_code == 200
        assert recovered.json()["assessmentResultId"] == body["assessmentResultId"]
        assert calls["openai"] == 1


def test_provider_failure_persists_failed_without_findings(tmp_path):
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "boom"})

    app = create_app(
        settings=_settings(ledger_path=_ledger(tmp_path)),
        openai_transport=httpx.MockTransport(handler),
        parallel_transport=httpx.MockTransport(_search_one()),
    )
    with TestClient(app) as client:
        investigation_id = _create(client)
        client.post(f"/api/investigations/{investigation_id}/search", json={"queries": ["a"]})
        token = client.post(f"/api/investigations/{investigation_id}/seal").json()["assessmentToken"]
        response = client.post(
            f"/api/investigations/{investigation_id}/assess",
            json={"assessmentToken": token},
        )
        assert response.status_code >= 400
        assert response.json().get("code") in {"upstream_error", "no_model", "server_unavailable"}

        latest = client.get(f"/api/investigations/{investigation_id}/assessments/latest")
        assert latest.status_code == 404

        history = client.get(f"/api/investigations/{investigation_id}/assessments")
        assert history.status_code == 200
        rows = history.json()["assessments"]
        assert len(rows) == 1
        assert rows[0]["status"] == "failed"
        assert rows[0]["failureCode"]
        assert rows[0]["assessment"] is None
        assert rows[0]["findings"] == []

        db = sqlite3.connect(str(Path(tmp_path) / "ledger.sqlite"))
        assert db.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0
        row = db.execute("SELECT model_assessment, facing_assessment, failure_code FROM assessment_results").fetchone()
        assert row[0] is None and row[1] is None and row[2]
        db.close()


def test_persist_failure_returns_503_without_second_provider_call(tmp_path):
    from app.ledger import LedgerError

    calls = {"openai": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["openai"] += 1
        return _json_response({
            "choices": [{"message": {"content": json.dumps({
                "assessment": "UNRESOLVED",
                "findings": [],
                "originalMaterial": {"established": False, "description": "", "source": None},
                "why": {},
                "uncertainty": [],
            })}}]
        })

    def boom(self, *args, **kwargs):
        raise LedgerError("The evidence ledger is unavailable.", failure_code="persist_failed")

    app = create_app(
        settings=_settings(ledger_path=_ledger(tmp_path, "persist-fail.sqlite")),
        openai_transport=httpx.MockTransport(handler),
        parallel_transport=httpx.MockTransport(_search_one()),
    )
    with mock.patch.object(Ledger, "save_completed_assessment", boom):
        with TestClient(app) as client:
            investigation_id = _create(client)
            client.post(f"/api/investigations/{investigation_id}/search", json={"queries": ["a"]})
            token = client.post(f"/api/investigations/{investigation_id}/seal").json()["assessmentToken"]
            response = client.post(
                f"/api/investigations/{investigation_id}/assess",
                json={"assessmentToken": token},
            )
            assert response.status_code == 503
            assert response.json()["code"] == "assessment_persist_failed"
            assert calls["openai"] == 1


def test_immutability_triggers_and_authorized_deletion(tmp_path):
    path = Path(_ledger(tmp_path, "immutable.sqlite"))
    ledger = Ledger(path)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("INSERT INTO users (id, created_at, email, password_hash) VALUES ('u1', 't', 'a@b.c', 'hash')")
    conn.execute(
        "INSERT INTO investigations (id, owner_id, kind, input_text, created_at) VALUES ('i1', 'u1', 'claim', 'c', 't')"
    )
    conn.execute(
        """
        INSERT INTO assessment_snapshots (
            id, investigation_id, owner_id, token_hash, snapshot_json, created_at, expires_at, consumed_at
        ) VALUES ('s1', 'i1', 'u1', 'th1', '{}', 't', '2099-01-01T00:00:00+00:00', 't')
        """
    )
    conn.execute(
        """
        INSERT INTO assessment_results (
            id, investigation_id, owner_id, snapshot_id, status,
            model_assessment, facing_assessment, failure_code, failure_message,
            why_json, uncertainty_json, original_material_json, created_at
        ) VALUES ('r1', 'i1', 'u1', 's1', 'completed', 'UNRESOLVED', 'UNRESOLVED', NULL, NULL, '{}', '[]', '{}', 't')
        """
    )
    conn.execute(
        """
        INSERT INTO findings (
            id, assessment_result_id, position, finding_type, evidence_status, alignment_reason, text, source_indexes_json
        ) VALUES ('f1', 'r1', 0, 'caution', 'not_established', NULL, 'text', '[]')
        """
    )
    conn.commit()
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE assessment_results SET facing_assessment = 'CONTRADICTED' WHERE id = 'r1'")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE findings SET text = 'changed' WHERE id = 'f1'")
    conn.close()

    assert ledger.delete_investigation("u1", "i1") is True
    conn = sqlite3.connect(path)
    assert conn.execute("SELECT COUNT(*) FROM assessment_results").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0
    conn.close()


def test_cross_owner_access_denied(tmp_path):
    app = create_app(
        settings=_settings(ledger_path=_ledger(tmp_path)),
        openai_transport=httpx.MockTransport(_openai_ok()),
        parallel_transport=httpx.MockTransport(_search_one()),
    )
    with TestClient(app) as client:
        investigation_id = _create(client)
        client.post(f"/api/investigations/{investigation_id}/search", json={"queries": ["a"]})
        token = client.post(f"/api/investigations/{investigation_id}/seal").json()["assessmentToken"]
        assert client.post(
            f"/api/investigations/{investigation_id}/assess",
            json={"assessmentToken": token},
        ).status_code == 200

        # Second user
        client.cookies.clear()
        client.headers.pop("X-CSRF-Token", None)
        _auth(client, email=f"other-{token_hex(4)}@example.com")
        assert client.get(f"/api/investigations/{investigation_id}/assessments/latest").status_code == 404
        assert client.get(f"/api/investigations/{investigation_id}/assessments").status_code == 404


def test_reassessment_creates_supersession(tmp_path):
    app = create_app(
        settings=_settings(ledger_path=_ledger(tmp_path)),
        openai_transport=httpx.MockTransport(_openai_ok("INSUFFICIENT_EVIDENCE")),
        parallel_transport=httpx.MockTransport(_search_one()),
    )
    with TestClient(app) as client:
        investigation_id = _create(client)
        # First assess without sources -> insufficient
        token1 = client.post(f"/api/investigations/{investigation_id}/seal").json()["assessmentToken"]
        r1 = client.post(
            f"/api/investigations/{investigation_id}/assess",
            json={"assessmentToken": token1},
        )
        assert r1.status_code == 200
        assert r1.json()["assessment"] == "INSUFFICIENT_EVIDENCE"

        client.post(f"/api/investigations/{investigation_id}/search", json={"queries": ["a"]})
        token2 = client.post(f"/api/investigations/{investigation_id}/seal").json()["assessmentToken"]
        r2 = client.post(
            f"/api/investigations/{investigation_id}/assess",
            json={"assessmentToken": token2},
        )
        assert r2.status_code == 200
        assert r1.json()["assessmentResultId"] != r2.json()["assessmentResultId"]

        db = sqlite3.connect(str(Path(tmp_path) / "ledger.sqlite"))
        rows = db.execute("SELECT prior_result_id, successor_result_id, reason FROM assessment_supersessions").fetchall()
        assert len(rows) == 1
        assert rows[0][2] == "reassessment"
        assert rows[0][0] == r1.json()["assessmentResultId"]
        assert rows[0][1] == r2.json()["assessmentResultId"]
        # Prior row unchanged
        facing = db.execute(
            "SELECT facing_assessment FROM assessment_results WHERE id = ?",
            (r1.json()["assessmentResultId"],),
        ).fetchone()[0]
        assert facing == "INSUFFICIENT_EVIDENCE"
        db.close()


def test_validate_assessment_still_returns_facing_and_model():
    snapshot = {
        "primaryClaim": "Warm water cures diabetes.",
        "sources": [{"snippet": "Warm water is not a cure.", "url": "https://www.cdc.gov/x", "quality": {"tier": "HIGH"}}],
    }
    result = validate_assessment({"assessment": "VERIFIED", "findings": []}, snapshot)
    assert result["assessment"] == "UNRESOLVED"
    assert result["modelAssessment"] == "VERIFIED"


def test_account_deletion_removes_assessment_rows(tmp_path):
    password = "correct-horse-battery"
    app = create_app(
        settings=_settings(ledger_path=_ledger(tmp_path)),
        openai_transport=httpx.MockTransport(_openai_ok()),
        parallel_transport=httpx.MockTransport(_search_one()),
    )
    with TestClient(app) as client:
        _auth(client, password=password)
        investigation_id = client.post(
            "/api/investigations", json={"input": "claim", "kind": "claim"}
        ).json()["investigationId"]
        client.post(f"/api/investigations/{investigation_id}/search", json={"queries": ["a"]})
        token = client.post(f"/api/investigations/{investigation_id}/seal").json()["assessmentToken"]
        assert client.post(
            f"/api/investigations/{investigation_id}/assess",
            json={"assessmentToken": token},
        ).status_code == 200
        deleted = client.request(
            "DELETE",
            "/api/auth/account",
            json={"password": password},
        )
        assert deleted.status_code == 200, deleted.text

    db = sqlite3.connect(str(Path(tmp_path) / "ledger.sqlite"))
    assert db.execute("SELECT COUNT(*) FROM assessment_results").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM assessment_supersessions").fetchone()[0] == 0
    db.close()


@pytest.mark.parametrize(
    "outcome",
    sorted(OFFICIAL_ASSESSMENT_OUTCOMES),
)
def test_all_six_official_outcomes_persist(tmp_path, outcome):
    path = Path(_ledger(tmp_path, f"outcome-{outcome}.sqlite"))
    Ledger(path)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("INSERT INTO users (id, created_at, email, password_hash) VALUES ('u1', 't', 'a@b.c', 'x')")
    conn.execute(
        "INSERT INTO investigations (id, owner_id, kind, input_text, created_at) VALUES ('i1', 'u1', 'claim', 'c', 't')"
    )
    snap = f"s-{outcome.lower()}"
    conn.execute(
        """
        INSERT INTO assessment_snapshots (
            id, investigation_id, owner_id, token_hash, snapshot_json, created_at, expires_at, consumed_at
        ) VALUES (?, 'i1', 'u1', ?, '{}', 't', '2099-01-01T00:00:00+00:00', 't')
        """,
        (snap, f"th-{outcome}"),
    )
    conn.execute(
        """
        INSERT INTO assessment_results (
            id, investigation_id, owner_id, snapshot_id, status,
            model_assessment, facing_assessment, failure_code, failure_message,
            why_json, uncertainty_json, original_material_json, created_at
        ) VALUES (?, 'i1', 'u1', ?, 'completed', ?, ?, NULL, NULL, '{}', '[]', '{}', 't')
        """,
        (f"r-{outcome}", snap, outcome, outcome),
    )
    conn.commit()
    row = conn.execute(
        "SELECT model_assessment, facing_assessment FROM assessment_results WHERE id = ?",
        (f"r-{outcome}",),
    ).fetchone()
    assert row == (outcome, outcome)
    conn.close()


def test_findings_rejected_for_failed_assessment(tmp_path):
    path = Path(_ledger(tmp_path, "findings-failed.sqlite"))
    Ledger(path)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("INSERT INTO users (id, created_at, email, password_hash) VALUES ('u1', 't', 'a@b.c', 'x')")
    conn.execute(
        "INSERT INTO investigations (id, owner_id, kind, input_text, created_at) VALUES ('i1', 'u1', 'claim', 'c', 't')"
    )
    conn.execute(
        """
        INSERT INTO assessment_snapshots (
            id, investigation_id, owner_id, token_hash, snapshot_json, created_at, expires_at, consumed_at
        ) VALUES ('s1', 'i1', 'u1', 'th1', '{}', 't', '2099-01-01T00:00:00+00:00', 't')
        """
    )
    conn.execute(
        """
        INSERT INTO assessment_results (
            id, investigation_id, owner_id, snapshot_id, status,
            model_assessment, facing_assessment, failure_code, failure_message,
            why_json, uncertainty_json, original_material_json, created_at
        ) VALUES ('r1', 'i1', 'u1', 's1', 'failed', NULL, NULL, 'no_model', 'safe', NULL, NULL, NULL, 't')
        """
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            """
            INSERT INTO findings (
                id, assessment_result_id, position, finding_type, evidence_status,
                alignment_reason, text, source_indexes_json
            ) VALUES ('f1', 'r1', 0, 'caution', 'not_established', NULL, 'x', '[]')
            """
        )
    conn.close()


def test_supersession_integrity_rejects_failed_or_cross_owner(tmp_path):
    path = Path(_ledger(tmp_path, "super-integrity.sqlite"))
    Ledger(path)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON")
    for uid, email in (("u1", "a@b.c"), ("u2", "c@d.e")):
        conn.execute(
            "INSERT INTO users (id, created_at, email, password_hash) VALUES (?, 't', ?, 'x')",
            (uid, email),
        )
        conn.execute(
            "INSERT INTO investigations (id, owner_id, kind, input_text, created_at) VALUES (?, ?, 'claim', 'c', 't')",
            (f"i-{uid}", uid),
        )
    for snap, inv, owner, rid, status, model, facing, fail in (
        ("s1", "i-u1", "u1", "r1", "completed", "UNRESOLVED", "UNRESOLVED", None),
        ("s2", "i-u1", "u1", "r2", "failed", None, None, "no_model"),
        ("s3", "i-u2", "u2", "r3", "completed", "CONTRADICTED", "CONTRADICTED", None),
    ):
        conn.execute(
            """
            INSERT INTO assessment_snapshots (
                id, investigation_id, owner_id, token_hash, snapshot_json, created_at, expires_at, consumed_at
            ) VALUES (?, ?, ?, ?, '{}', 't', '2099-01-01T00:00:00+00:00', 't')
            """,
            (snap, inv, owner, f"th-{snap}"),
        )
        if status == "completed":
            conn.execute(
                """
                INSERT INTO assessment_results (
                    id, investigation_id, owner_id, snapshot_id, status,
                    model_assessment, facing_assessment, failure_code, failure_message,
                    why_json, uncertainty_json, original_material_json, created_at
                ) VALUES (?, ?, ?, ?, 'completed', ?, ?, NULL, NULL, '{}', '[]', '{}', 't')
                """,
                (rid, inv, owner, snap, model, facing),
            )
        else:
            conn.execute(
                """
                INSERT INTO assessment_results (
                    id, investigation_id, owner_id, snapshot_id, status,
                    model_assessment, facing_assessment, failure_code, failure_message,
                    why_json, uncertainty_json, original_material_json, created_at
                ) VALUES (?, ?, ?, ?, 'failed', NULL, NULL, ?, 'safe', NULL, NULL, NULL, 't')
                """,
                (rid, inv, owner, snap, fail),
            )
    conn.commit()
    # Failed endpoint rejected
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            """
            INSERT INTO assessment_supersessions (
                id, owner_id, investigation_id, prior_result_id, successor_result_id, reason, created_at
            ) VALUES ('x1', 'u1', 'i-u1', 'r1', 'r2', 'reassessment', 't')
            """
        )
    # Cross-owner rejected
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            """
            INSERT INTO assessment_supersessions (
                id, owner_id, investigation_id, prior_result_id, successor_result_id, reason, created_at
            ) VALUES ('x2', 'u1', 'i-u1', 'r1', 'r3', 'correction', 't')
            """
        )
    conn.close()


def test_duplicate_completed_snapshot_returns_existing_without_rewrite(tmp_path):
    path = Path(_ledger(tmp_path, "dup.sqlite"))
    ledger = Ledger(path)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("INSERT INTO users (id, created_at, email, password_hash) VALUES ('u1', 't', 'a@b.c', 'x')")
    conn.execute(
        "INSERT INTO investigations (id, owner_id, kind, input_text, created_at) VALUES ('i1', 'u1', 'claim', 'c', 't')"
    )
    conn.execute(
        """
        INSERT INTO assessment_snapshots (
            id, investigation_id, owner_id, token_hash, snapshot_json, created_at, expires_at, consumed_at
        ) VALUES ('s1', 'i1', 'u1', 'th1', '{}', 't', '2099-01-01T00:00:00+00:00', 't')
        """
    )
    conn.commit()
    conn.close()
    first = ledger.save_completed_assessment(
        "u1",
        "i1",
        "s1",
        model_assessment="CONTRADICTED",
        facing_assessment="CONTRADICTED",
        why={"supporting": "a"},
        uncertainty=[],
        original_material={"established": False, "description": "", "source": None},
        findings=[],
    )
    second = ledger.save_completed_assessment(
        "u1",
        "i1",
        "s1",
        model_assessment="UNRESOLVED",
        facing_assessment="UNRESOLVED",
        why={},
        uncertainty=[],
        original_material={"established": False, "description": "", "source": None},
        findings=[{"type": "caution", "text": "should not write", "sources": []}],
    )
    assert first["assessmentResultId"] == second["assessmentResultId"]
    assert second["assessment"] == "CONTRADICTED"
    db = sqlite3.connect(path)
    assert db.execute("SELECT COUNT(*) FROM assessment_results").fetchone()[0] == 1
    assert db.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0
    db.close()


def test_migration_creates_phase_a_tables_on_existing_ledger(tmp_path):
    """Additive open of a pre-Phase-A schema creates new tables without wiping data."""
    path = Path(_ledger(tmp_path, "legacy.sqlite"))
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE users (
            id TEXT PRIMARY KEY, created_at TEXT NOT NULL, email TEXT, password_hash TEXT
        );
        CREATE TABLE investigations (
            id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, kind TEXT NOT NULL,
            input_text TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE assessment_snapshots (
            id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL, owner_id TEXT NOT NULL,
            token_hash TEXT NOT NULL, snapshot_json TEXT NOT NULL, created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL, consumed_at TEXT
        );
        INSERT INTO users (id, created_at, email, password_hash) VALUES ('u1', 't', 'a@b.c', 'x');
        INSERT INTO investigations (id, owner_id, kind, input_text, created_at)
            VALUES ('i1', 'u1', 'claim', 'legacy claim', 't');
        """
    )
    conn.commit()
    conn.close()
    ledger = Ledger(path)
    assert ledger.check_health() is True
    db = sqlite3.connect(path)
    names = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"assessment_results", "findings", "assessment_supersessions"} <= names
    assert db.execute("SELECT input_text FROM investigations WHERE id='i1'").fetchone()[0] == "legacy claim"
    db.close()
