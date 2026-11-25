"""E.9.5C Evidence Intelligence Graph — isolated ledgers and mocks only.

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
from app.evidence_graph import (
    GraphBuilder,
    validate_certainty,
    walk_replace_cycle,
)
from app.ledger import Ledger, LedgerError, refuse_test_ledger
from app.main import create_app

DUMMY_OPENAI = "test-openai-key"
DUMMY_PARALLEL = "test-parallel-key"
PASSWORD = "correct-horse-battery"


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


def _auth(client: TestClient, email: str | None = None, password: str = PASSWORD) -> dict:
    email = email or f"user-{token_hex(4)}@example.com"
    assert client.post("/api/auth/register", json={"email": email, "password": password}).status_code == 200
    logged = client.post("/api/auth/login", json={"email": email, "password": password})
    assert logged.status_code == 200
    client.headers["X-CSRF-Token"] = logged.json()["csrfToken"]
    return {"email": email, "password": password, **logged.json()}


def _openai_ok(assessment: str = "UNRESOLVED"):
    content = json.dumps({
        "assessment": assessment,
        "findings": [{"type": "support", "text": "Warm water is not a cure.", "sources": [0],
                      "evidenceStatus": "literally_aligned", "alignmentReason": "literal_sentence"}],
        "originalMaterial": {"established": False, "description": "", "source": None},
        "why": {},
        "uncertainty": [],
    })

    def handler(_request: httpx.Request) -> httpx.Response:
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


def test_schema_tables_and_certainty_policy(tmp_path):
    path = Path(_ledger(tmp_path))
    assert Ledger(path).check_health() is True
    conn = sqlite3.connect(path)
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"evidence_nodes", "evidence_edges", "evidence_edge_active", "evidence_graph_checkpoints"} <= names
    conn.close()
    with pytest.raises(ValueError):
        validate_certainty("SUPPORTS", "CONFIRMED", "model_assessment")
    with pytest.raises(ValueError):
        validate_certainty("PUBLISHED_AT", "CONFIRMED", "system_structural")
    validate_certainty("CONTAINS", "CONFIRMED", "system_structural")
    validate_certainty("SUPPORTS", "INFERRED", "model_finding_status")


def test_db_rejects_published_at_confirmed_and_non_allowlist(tmp_path):
    """M3: SQL trigger enforces certainty rules, not only application validation."""
    path = Path(_ledger(tmp_path, "certainty-db.sqlite"))
    Ledger(path)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("INSERT INTO users (id, created_at, email, password_hash) VALUES ('u1','t','a@b.c','x')")
    conn.execute(
        "INSERT INTO investigations (id, owner_id, kind, input_text, created_at) VALUES ('i1','u1','claim','c','t')"
    )
    conn.execute(
        """
        INSERT INTO evidence_nodes (
            id, owner_id, investigation_id, node_type, canonical_key, props_json, created_at, updated_at
        ) VALUES ('n1','u1','i1','investigation','inv:i1','{}','t','t'),
                 ('n2','u1','i1','publication_event','pub:x','{}','t','t'),
                 ('n3','u1','i1','finding','finding:1:0','{}','t','t')
        """
    )
    conn.commit()
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            """
            INSERT INTO evidence_edges (
                id, owner_id, investigation_id, src_node_id, dst_node_id, rel_type,
                certainty, method, evidence_json, scope_key, created_at
            ) VALUES ('e1','u1','i1','n1','n2','PUBLISHED_AT','CONFIRMED','system_structural','{}','|','t')
            """
        )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            """
            INSERT INTO evidence_edges (
                id, owner_id, investigation_id, src_node_id, dst_node_id, rel_type,
                certainty, method, evidence_json, scope_key, created_at
            ) VALUES ('e2','u1','i1','n3','n1','SUPPORTS','CONFIRMED','model_finding_status','{}','|','t')
            """
        )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            """
            INSERT INTO evidence_edges (
                id, owner_id, investigation_id, src_node_id, dst_node_id, rel_type,
                certainty, method, evidence_json, scope_key, created_at
            ) VALUES ('e3','u1','i1','n1','n2','CONTAINS','CONFIRMED','human_review','{}','|','t')
            """
        )
    # Allowed: PUBLISHED_AT as UNCERTAIN
    conn.execute(
        """
        INSERT INTO evidence_edges (
            id, owner_id, investigation_id, src_node_id, dst_node_id, rel_type,
            certainty, method, evidence_json, scope_key, created_at
        ) VALUES ('e4','u1','i1','n1','n2','PUBLISHED_AT','UNCERTAIN','system_structural','{}','|','t')
        """
    )
    conn.commit()
    conn.close()


def test_cross_owner_and_cross_investigation_edge_rejected(tmp_path):
    path = Path(_ledger(tmp_path, "fk.sqlite"))
    Ledger(path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("INSERT INTO users (id, created_at, email, password_hash) VALUES ('u1','t','a@b.c','x')")
    conn.execute("INSERT INTO users (id, created_at, email, password_hash) VALUES ('u2','t','c@d.e','x')")
    conn.execute("INSERT INTO investigations (id, owner_id, kind, input_text, created_at) VALUES ('i1','u1','claim','c','t')")
    conn.execute("INSERT INTO investigations (id, owner_id, kind, input_text, created_at) VALUES ('i2','u2','claim','c','t')")
    now = "t"
    for nid, inv, owner, key in (
        ("n1", "i1", "u1", "inv:i1"),
        ("n2", "i2", "u2", "inv:i2"),
    ):
        conn.execute(
            """
            INSERT INTO evidence_nodes (
                id, owner_id, investigation_id, node_type, canonical_key, props_json, created_at, updated_at
            ) VALUES (?, ?, ?, 'investigation', ?, '{}', ?, ?)
            """,
            (nid, owner, inv, key, now, now),
        )
    conn.commit()
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            """
            INSERT INTO evidence_edges (
                id, owner_id, investigation_id, src_node_id, dst_node_id, rel_type,
                certainty, method, evidence_json, scope_key, created_at
            ) VALUES ('e1','u1','i1','n1','n2','CONTAINS','CONFIRMED','system_structural','{}','|','t')
            """
        )
    conn.close()


def test_active_uniqueness_replace_cycle_and_history(tmp_path):
    path = Path(_ledger(tmp_path, "active.sqlite"))
    Ledger(path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("INSERT INTO users (id, created_at, email, password_hash) VALUES ('u1','t','a@b.c','x')")
    conn.execute("INSERT INTO investigations (id, owner_id, kind, input_text, created_at) VALUES ('i1','u1','claim','c','t')")
    builder = GraphBuilder(conn, "u1", "i1", now="t")
    a = builder.upsert_node("investigation", "inv:i1", {})
    b = builder.upsert_node("claim", "claim:primary", {"text": "x"})
    e1 = builder.ensure_active_edge(
        src_node_id=a, dst_node_id=b, rel_type="CONTAINS", certainty="CONFIRMED",
        method="system_structural", evidence={"v": 1},
    )
    e1b = builder.ensure_active_edge(
        src_node_id=a, dst_node_id=b, rel_type="CONTAINS", certainty="CONFIRMED",
        method="system_structural", evidence={"v": 1},
    )
    assert e1 == e1b
    e2 = builder.ensure_active_edge(
        src_node_id=a, dst_node_id=b, rel_type="CONTAINS", certainty="CONFIRMED",
        method="system_structural", evidence={"v": 2}, allow_replace=True,
    )
    assert e2 != e1
    active = conn.execute("SELECT edge_id FROM evidence_edge_active").fetchone()["edge_id"]
    assert active == e2
    assert conn.execute("SELECT COUNT(*) FROM evidence_edges").fetchone()[0] == 2
    # Multiple rel types between same pair
    builder.ensure_active_edge(
        src_node_id=a, dst_node_id=b, rel_type="REFERENCES", certainty="CONFIRMED",
        method="system_structural", evidence={"v": 1},
    )
    assert conn.execute("SELECT COUNT(*) FROM evidence_edge_active").fetchone()[0] == 2
    with pytest.raises(ValueError):
        walk_replace_cycle(conn, "x", "x")
    # Genuine multi-edge replacement cycle: c1 -> c2 -> c1 (FK briefly off to close the loop).
    conn.execute(
        """
        INSERT INTO evidence_edges (
            id, owner_id, investigation_id, src_node_id, dst_node_id, rel_type,
            certainty, method, evidence_json, scope_key, replaces_edge_id, created_at
        ) VALUES ('c1','u1','i1',?,?, 'REFERENCES','CONFIRMED','system_structural','{}','|',NULL,'t')
        """,
        (a, b),
    )
    conn.execute(
        """
        INSERT INTO evidence_edges (
            id, owner_id, investigation_id, src_node_id, dst_node_id, rel_type,
            certainty, method, evidence_json, scope_key, replaces_edge_id, created_at
        ) VALUES ('c2','u1','i1',?,?, 'REFERENCES','CONFIRMED','system_structural','{}','|','c1','t')
        """,
        (a, b),
    )
    # foreign_keys cannot be toggled mid-transaction — commit first.
    conn.commit()
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute("DELETE FROM evidence_edges WHERE id = 'c1'")
    conn.execute(
        """
        INSERT INTO evidence_edges (
            id, owner_id, investigation_id, src_node_id, dst_node_id, rel_type,
            certainty, method, evidence_json, scope_key, replaces_edge_id, created_at
        ) VALUES ('c1','u1','i1',?,?, 'REFERENCES','CONFIRMED','system_structural','{}','|','c2','t')
        """,
        (a, b),
    )
    conn.commit()
    conn.execute("PRAGMA foreign_keys=ON")
    with pytest.raises(ValueError, match="cycle"):
        walk_replace_cycle(conn, "new_edge", "c1")
    # Point the active REFERENCES pointer at c2 so GraphBuilder walks c2 -> c1 -> c2.
    conn.execute(
        """
        INSERT INTO evidence_edge_active (
            investigation_id, src_node_id, dst_node_id, rel_type, scope_key, edge_id
        ) VALUES ('i1',?,?, 'REFERENCES','|','c2')
        ON CONFLICT(investigation_id, src_node_id, dst_node_id, rel_type, scope_key)
        DO UPDATE SET edge_id = excluded.edge_id
        """,
        (a, b),
    )
    with pytest.raises(ValueError, match="cycle"):
        builder.ensure_active_edge(
            src_node_id=a,
            dst_node_id=b,
            rel_type="REFERENCES",
            certainty="CONFIRMED",
            method="system_structural",
            evidence={"v": 99},
            allow_replace=True,
        )
    # Historical CONTAINS replacements and cycle fixtures remain stored.
    hist = conn.execute("SELECT COUNT(*) FROM evidence_edges").fetchone()[0]
    assert hist >= 4
    assert conn.execute(
        "SELECT COUNT(*) FROM evidence_edges WHERE id IN (?, ?)", (e1, e2)
    ).fetchone()[0] == 2
    conn.close()


def test_materialize_idempotent_and_snapshot_stable(tmp_path):
    calls = {"n": 0}

    def openai_handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return _openai_ok("INSUFFICIENT_EVIDENCE")(_request)

    app = create_app(
        settings=_settings(ledger_path=_ledger(tmp_path)),
        openai_transport=httpx.MockTransport(openai_handler),
        parallel_transport=httpx.MockTransport(_search_one()),
    )
    with TestClient(app) as client:
        _auth(client)
        inv = client.post("/api/investigations", json={"input": "Warm water cures diabetes.", "kind": "claim"}).json()["investigationId"]
        assert client.post(f"/api/investigations/{inv}/search", json={"queries": ["a"]}).status_code == 200
        sealed = client.post(f"/api/investigations/{inv}/seal")
        assert sealed.status_code == 200
        token = sealed.json()["assessmentToken"]
        assessed = client.post(f"/api/investigations/{inv}/assess", json={"assessmentToken": token})
        assert assessed.status_code == 200
        assert "modelAssessment" not in assessed.json()
        assert calls["n"] == 1

        db = Path(tmp_path) / "ledger.sqlite"
        ledger = Ledger(db)
        before_nodes = sqlite3.connect(db).execute("SELECT COUNT(*) FROM evidence_nodes").fetchone()[0]
        before_edges = sqlite3.connect(db).execute("SELECT COUNT(*) FROM evidence_edge_active").fetchone()[0]
        # Rematerialize
        ledger.materialize_investigation_graph(
            sqlite3.connect(db).execute("SELECT owner_id FROM investigations").fetchone()[0],
            inv,
        )
        after_nodes = sqlite3.connect(db).execute("SELECT COUNT(*) FROM evidence_nodes").fetchone()[0]
        after_edges = sqlite3.connect(db).execute("SELECT COUNT(*) FROM evidence_edge_active").fetchone()[0]
        assert after_nodes == before_nodes
        assert after_edges == before_edges

        # Snapshot-scoped keys present
        keys = [r[0] for r in sqlite3.connect(db).execute(
            "SELECT canonical_key FROM evidence_nodes WHERE node_type='evidence_source'"
        )]
        assert any(k.startswith("snap:") for k in keys)
        snap_keys = [k for k in keys if k.startswith("snap:")]
        # Replace live sources
        assert client.post(f"/api/investigations/{inv}/search", json={"queries": ["b"]}).status_code == 200
        ledger.materialize_graph_scope(
            sqlite3.connect(db).execute("SELECT owner_id FROM investigations").fetchone()[0],
            inv,
            "investigation_skeleton",
            inv,
        )
        snap_keys_after = [r[0] for r in sqlite3.connect(db).execute(
            "SELECT canonical_key FROM evidence_nodes WHERE node_type='evidence_source' AND canonical_key LIKE 'snap:%'"
        )]
        assert set(snap_keys) <= set(snap_keys_after)


def test_graph_get_readonly_and_owner_isolation(tmp_path):
    app = create_app(
        settings=_settings(ledger_path=_ledger(tmp_path)),
        openai_transport=httpx.MockTransport(_openai_ok()),
        parallel_transport=httpx.MockTransport(_search_one()),
    )
    with TestClient(app) as client:
        _auth(client)
        inv = client.post("/api/investigations", json={"input": "claim", "kind": "claim"}).json()["investigationId"]
        client.post(f"/api/investigations/{inv}/search", json={"queries": ["a"]})
        token = client.post(f"/api/investigations/{inv}/seal").json()["assessmentToken"]
        assert client.post(f"/api/investigations/{inv}/assess", json={"assessmentToken": token}).status_code == 200

        db = str(Path(tmp_path) / "ledger.sqlite")
        before = {
            "nodes": sqlite3.connect(db).execute("SELECT COUNT(*) FROM evidence_nodes").fetchone()[0],
            "edges": sqlite3.connect(db).execute("SELECT COUNT(*) FROM evidence_edges").fetchone()[0],
            "active": sqlite3.connect(db).execute("SELECT COUNT(*) FROM evidence_edge_active").fetchone()[0],
            "cp": sqlite3.connect(db).execute(
                "SELECT status, updated_at FROM evidence_graph_checkpoints ORDER BY scope_type, scope_id"
            ).fetchall(),
        }
        graph = client.get(f"/api/investigations/{inv}/graph")
        assert graph.status_code == 200
        body = graph.json()
        assert "nodes" in body and "edges" in body and "graphStatus" in body
        assert "modelAssessment" not in json.dumps(body)
        assert body["note"]
        after = {
            "nodes": sqlite3.connect(db).execute("SELECT COUNT(*) FROM evidence_nodes").fetchone()[0],
            "edges": sqlite3.connect(db).execute("SELECT COUNT(*) FROM evidence_edges").fetchone()[0],
            "active": sqlite3.connect(db).execute("SELECT COUNT(*) FROM evidence_edge_active").fetchone()[0],
            "cp": sqlite3.connect(db).execute(
                "SELECT status, updated_at FROM evidence_graph_checkpoints ORDER BY scope_type, scope_id"
            ).fetchall(),
        }
        assert before == after

        client.cookies.clear()
        client.headers.pop("X-CSRF-Token", None)
        _auth(client, email=f"other-{token_hex(4)}@example.com")
        assert client.get(f"/api/investigations/{inv}/graph").status_code == 404


def test_assess_succeeds_when_graph_fails_no_second_provider(tmp_path):
    """M4: assess 200 + single provider call + failed assessment_result checkpoint."""
    calls = {"n": 0}

    def openai_handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return _openai_ok()(_request)

    def boom_assessment(self, *args, **kwargs):
        raise ValueError("boom")

    app = create_app(
        settings=_settings(ledger_path=_ledger(tmp_path, "graph-fail.sqlite")),
        openai_transport=httpx.MockTransport(openai_handler),
        parallel_transport=httpx.MockTransport(_search_one()),
    )
    with mock.patch.object(Ledger, "_materialize_assessment_result", boom_assessment):
        with TestClient(app) as client:
            _auth(client)
            inv = client.post("/api/investigations", json={"input": "claim", "kind": "claim"}).json()["investigationId"]
            client.post(f"/api/investigations/{inv}/search", json={"queries": ["a"]})
            token = client.post(f"/api/investigations/{inv}/seal").json()["assessmentToken"]
            assessed = client.post(f"/api/investigations/{inv}/assess", json={"assessmentToken": token})
            assert assessed.status_code == 200, assessed.text
            assert assessed.json()["assessmentResultId"]
            assert "modelAssessment" not in assessed.json()
            assert calls["n"] == 1
            latest = client.get(f"/api/investigations/{inv}/assessments/latest")
            assert latest.status_code == 200
            assert latest.json()["assessmentResultId"] == assessed.json()["assessmentResultId"]
            assert calls["n"] == 1
            graph = client.get(f"/api/investigations/{inv}/graph")
            assert graph.status_code == 200
            assert graph.json()["graphStatus"]["complete"] is False

    db = sqlite3.connect(str(Path(tmp_path) / "graph-fail.sqlite"))
    assert db.execute("SELECT COUNT(*) FROM assessment_results WHERE status='completed'").fetchone()[0] == 1
    assert db.execute("SELECT COUNT(*) FROM findings").fetchone()[0] >= 1
    result_id = assessed.json()["assessmentResultId"]
    row = db.execute(
        """
        SELECT status, last_error_code FROM evidence_graph_checkpoints
        WHERE scope_type = 'assessment_result' AND scope_id = ?
        """,
        (result_id,),
    ).fetchone()
    assert row is not None
    assert row[0] == "failed"
    assert row[1] == "graph_persist_failed"
    # Snapshot scope still completed via its own checkpointed operation.
    assert db.execute(
        "SELECT COUNT(*) FROM evidence_graph_checkpoints WHERE scope_type='snapshot' AND status='complete'"
    ).fetchone()[0] >= 1
    db.close()


def test_failed_checkpoint_retry(tmp_path):
    path = Path(_ledger(tmp_path, "retry.sqlite"))
    ledger = Ledger(path)
    conn = sqlite3.connect(path)
    conn.execute("INSERT INTO users (id, created_at, email, password_hash) VALUES ('u1','t','a@b.c','x')")
    conn.execute("INSERT INTO investigations (id, owner_id, kind, input_text, created_at) VALUES ('i1','u1','claim','c','t')")
    conn.commit()
    conn.close()
    # Force fail then succeed
    with mock.patch.object(Ledger, "_materialize_skeleton", side_effect=ValueError("boom")):
        with pytest.raises(LedgerError) as exc:
            ledger.materialize_graph_scope("u1", "i1", "investigation_skeleton", "i1")
        assert exc.value.failure_code == "graph_persist_failed"
    row = sqlite3.connect(path).execute(
        "SELECT status, last_error_code FROM evidence_graph_checkpoints"
    ).fetchone()
    assert row[0] == "failed"
    assert row[1] == "graph_persist_failed"
    ok = ledger.materialize_graph_scope("u1", "i1", "investigation_skeleton", "i1")
    assert ok["status"] == "complete"
    assert sqlite3.connect(path).execute(
        "SELECT status FROM evidence_graph_checkpoints"
    ).fetchone()[0] == "complete"


def test_investigation_and_account_erasure_clears_graph(tmp_path):
    app = create_app(
        settings=_settings(ledger_path=_ledger(tmp_path)),
        openai_transport=httpx.MockTransport(_openai_ok()),
        parallel_transport=httpx.MockTransport(_search_one()),
    )
    with TestClient(app) as client:
        _auth(client, password=PASSWORD)
        inv = client.post("/api/investigations", json={"input": "claim", "kind": "claim"}).json()["investigationId"]
        client.post(f"/api/investigations/{inv}/search", json={"queries": ["a"]})
        token = client.post(f"/api/investigations/{inv}/seal").json()["assessmentToken"]
        assert client.post(f"/api/investigations/{inv}/assess", json={"assessmentToken": token}).status_code == 200
        db = str(Path(tmp_path) / "ledger.sqlite")
        assert sqlite3.connect(db).execute("SELECT COUNT(*) FROM evidence_nodes").fetchone()[0] > 0
        assert client.delete(f"/api/investigations/{inv}").status_code == 200
        assert sqlite3.connect(db).execute("SELECT COUNT(*) FROM evidence_nodes").fetchone()[0] == 0
        assert sqlite3.connect(db).execute("SELECT COUNT(*) FROM evidence_edges").fetchone()[0] == 0
        assert sqlite3.connect(db).execute("SELECT COUNT(*) FROM evidence_edge_active").fetchone()[0] == 0
        assert sqlite3.connect(db).execute("SELECT COUNT(*) FROM evidence_graph_checkpoints").fetchone()[0] == 0

        # Account erasure path
        inv2 = client.post("/api/investigations", json={"input": "claim2", "kind": "claim"}).json()["investigationId"]
        client.post(f"/api/investigations/{inv2}/search", json={"queries": ["a"]})
        token2 = client.post(f"/api/investigations/{inv2}/seal").json()["assessmentToken"]
        assert client.post(f"/api/investigations/{inv2}/assess", json={"assessmentToken": token2}).status_code == 200
        deleted = client.request("DELETE", "/api/auth/account", json={"password": PASSWORD})
        assert deleted.status_code == 200, deleted.text
        assert sqlite3.connect(db).execute("SELECT COUNT(*) FROM evidence_nodes").fetchone()[0] == 0
        assert sqlite3.connect(db).execute("SELECT COUNT(*) FROM evidence_graph_checkpoints").fetchone()[0] == 0


def test_include_replaced_edges(tmp_path):
    path = Path(_ledger(tmp_path, "hist.sqlite"))
    Ledger(path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("INSERT INTO users (id, created_at, email, password_hash) VALUES ('u1','t','a@b.c','x')")
    conn.execute("INSERT INTO investigations (id, owner_id, kind, input_text, created_at) VALUES ('i1','u1','claim','c','t')")
    builder = GraphBuilder(conn, "u1", "i1", now="t")
    a = builder.upsert_node("investigation", "inv:i1", {})
    b = builder.upsert_node("claim", "claim:primary", {})
    builder.ensure_active_edge(
        src_node_id=a, dst_node_id=b, rel_type="CONTAINS", certainty="CONFIRMED",
        method="system_structural", evidence={"v": 1},
    )
    builder.ensure_active_edge(
        src_node_id=a, dst_node_id=b, rel_type="CONTAINS", certainty="CONFIRMED",
        method="system_structural", evidence={"v": 2}, allow_replace=True,
    )
    conn.commit()
    conn.close()
    ledger = Ledger(path)
    active_only = ledger.get_investigation_graph("u1", "i1", include_replaced=False)
    full = ledger.get_investigation_graph("u1", "i1", include_replaced=True)
    assert len(active_only["edges"]) == 1
    assert len(full["edges"]) == 2


def test_graph_completeness_expected_scopes(tmp_path):
    """H1: complete requires skeleton + every snapshot + every completed assessment."""
    app = create_app(
        settings=_settings(ledger_path=_ledger(tmp_path, "complete.sqlite")),
        openai_transport=httpx.MockTransport(_openai_ok()),
        parallel_transport=httpx.MockTransport(_search_one()),
    )
    with TestClient(app) as client:
        _auth(client)
        inv = client.post("/api/investigations", json={"input": "claim", "kind": "claim"}).json()["investigationId"]
        client.post(f"/api/investigations/{inv}/search", json={"queries": ["a"]})
        token = client.post(f"/api/investigations/{inv}/seal").json()["assessmentToken"]
        assessed = client.post(f"/api/investigations/{inv}/assess", json={"assessmentToken": token})
        assert assessed.status_code == 200
        result_id = assessed.json()["assessmentResultId"]
        db = Path(tmp_path) / "complete.sqlite"
        owner = sqlite3.connect(db).execute("SELECT owner_id FROM investigations").fetchone()[0]
        snap_id = sqlite3.connect(db).execute("SELECT id FROM assessment_snapshots").fetchone()[0]
        ledger = Ledger(db)

        full = client.get(f"/api/investigations/{inv}/graph").json()
        assert full["graphStatus"]["complete"] is True

        def _exec(sql, params=()):
            c = sqlite3.connect(db)
            try:
                c.execute(sql, params)
                c.commit()
            finally:
                c.close()

        # Missing assessment checkpoint
        _exec("DELETE FROM evidence_graph_checkpoints WHERE scope_type='assessment_result'")
        g = ledger.get_investigation_graph(owner, inv)
        assert g["graphStatus"]["complete"] is False
        statuses = {c["scopeType"]: c["status"] for c in g["graphStatus"]["checkpoints"]}
        assert statuses["assessment_result"] == "missing"

        # Restore assessment complete; missing snapshot checkpoint
        ledger._set_graph_checkpoint(owner, inv, "assessment_result", result_id, "complete", None)
        _exec("DELETE FROM evidence_graph_checkpoints WHERE scope_type='snapshot'")
        g = ledger.get_investigation_graph(owner, inv)
        assert g["graphStatus"]["complete"] is False
        assert any(
            c["scopeType"] == "snapshot" and c["status"] == "missing"
            for c in g["graphStatus"]["checkpoints"]
        )

        # Missing skeleton
        ledger._set_graph_checkpoint(owner, inv, "snapshot", snap_id, "complete", None)
        _exec("DELETE FROM evidence_graph_checkpoints WHERE scope_type='investigation_skeleton'")
        g = ledger.get_investigation_graph(owner, inv)
        assert g["graphStatus"]["complete"] is False
        assert any(
            c["scopeType"] == "investigation_skeleton" and c["status"] == "missing"
            for c in g["graphStatus"]["checkpoints"]
        )

        # Pending / failed checkpoints
        ledger._set_graph_checkpoint(owner, inv, "investigation_skeleton", inv, "pending", None)
        g = ledger.get_investigation_graph(owner, inv)
        assert g["graphStatus"]["complete"] is False
        ledger._set_graph_checkpoint(
            owner, inv, "investigation_skeleton", inv, "failed", "graph_persist_failed"
        )
        g = ledger.get_investigation_graph(owner, inv)
        assert g["graphStatus"]["complete"] is False

        # Fully rematerialized
        ledger.materialize_investigation_graph(owner, inv)
        g = ledger.get_investigation_graph(owner, inv)
        assert g["graphStatus"]["complete"] is True
        assert all(c["status"] == "complete" for c in g["graphStatus"]["checkpoints"])


def test_seal_materializes_skeleton_and_snapshot_checkpoints(tmp_path):
    """M1/M2: seal best-effort skeleton + snapshot each with own checkpoint."""
    app = create_app(
        settings=_settings(ledger_path=_ledger(tmp_path, "seal-scopes.sqlite")),
        openai_transport=httpx.MockTransport(_openai_ok()),
        parallel_transport=httpx.MockTransport(_search_one()),
    )
    with TestClient(app) as client:
        _auth(client)
        inv = client.post("/api/investigations", json={"input": "claim", "kind": "claim"}).json()["investigationId"]
        # Seal without prior search — skeleton must still be triggered by seal.
        token_resp = client.post(f"/api/investigations/{inv}/seal")
        assert token_resp.status_code == 200
        db = Path(tmp_path) / "seal-scopes.sqlite"
        rows = sqlite3.connect(db).execute(
            "SELECT scope_type, status FROM evidence_graph_checkpoints ORDER BY scope_type"
        ).fetchall()
        scopes = {r[0]: r[1] for r in rows}
        assert scopes.get("investigation_skeleton") == "complete"
        assert scopes.get("snapshot") == "complete"
        assert sqlite3.connect(db).execute(
            "SELECT COUNT(*) FROM evidence_nodes WHERE node_type='snapshot'"
        ).fetchone()[0] == 1


def test_assessment_does_not_nest_snapshot_without_checkpoint(tmp_path):
    """M2: assessment materialize ensures snapshot via scoped checkpoint, not silent nest."""
    app = create_app(
        settings=_settings(ledger_path=_ledger(tmp_path, "no-nest.sqlite")),
        openai_transport=httpx.MockTransport(_openai_ok()),
        parallel_transport=httpx.MockTransport(_search_one()),
    )
    with TestClient(app) as client:
        _auth(client)
        inv = client.post("/api/investigations", json={"input": "claim", "kind": "claim"}).json()["investigationId"]
        client.post(f"/api/investigations/{inv}/search", json={"queries": ["a"]})
        token = client.post(f"/api/investigations/{inv}/seal").json()["assessmentToken"]
        assert client.post(f"/api/investigations/{inv}/assess", json={"assessmentToken": token}).status_code == 200
        db = Path(tmp_path) / "no-nest.sqlite"
        def _q(sql, params=()):
            c = sqlite3.connect(db)
            try:
                return c.execute(sql, params).fetchone()
            finally:
                c.close()

        def _exec(sql, params=()):
            c = sqlite3.connect(db)
            try:
                c.execute(sql, params)
                c.commit()
            finally:
                c.close()

        snap_cp = _q("SELECT status FROM evidence_graph_checkpoints WHERE scope_type='snapshot'")
        assert snap_cp is not None and snap_cp[0] == "complete"
        owner = _q("SELECT owner_id FROM investigations")[0]
        result_id = _q("SELECT id FROM assessment_results WHERE status='completed'")[0]
        _exec("DELETE FROM evidence_graph_checkpoints WHERE scope_type='snapshot'")
        # Force assessment rematerialize (clear complete short-circuit)
        _exec(
            "UPDATE evidence_graph_checkpoints SET status='failed' WHERE scope_type='assessment_result'"
        )
        Ledger(db).materialize_graph_scope(owner, inv, "assessment_result", result_id)
        snap_cp = _q("SELECT status FROM evidence_graph_checkpoints WHERE scope_type='snapshot'")
        assert snap_cp is not None and snap_cp[0] == "complete"


def test_interrupted_pending_checkpoint_recoverable(tmp_path):
    """L2: durable pending survives; rematerialize completes without duplicates."""
    path = Path(_ledger(tmp_path, "pending.sqlite"))
    ledger = Ledger(path)
    conn = sqlite3.connect(path)
    conn.execute("INSERT INTO users (id, created_at, email, password_hash) VALUES ('u1','t','a@b.c','x')")
    conn.execute(
        "INSERT INTO investigations (id, owner_id, kind, input_text, created_at) VALUES ('i1','u1','claim','c','t')"
    )
    conn.commit()
    conn.close()
    ledger._set_graph_checkpoint("u1", "i1", "investigation_skeleton", "i1", "pending", None)
    assert sqlite3.connect(path).execute(
        "SELECT status FROM evidence_graph_checkpoints"
    ).fetchone()[0] == "pending"
    g = ledger.get_investigation_graph("u1", "i1")
    assert g["graphStatus"]["complete"] is False
    ok = ledger.materialize_graph_scope("u1", "i1", "investigation_skeleton", "i1")
    assert ok["status"] == "complete"
    nodes = sqlite3.connect(path).execute("SELECT COUNT(*) FROM evidence_nodes").fetchone()[0]
    ledger.materialize_graph_scope("u1", "i1", "investigation_skeleton", "i1")
    assert sqlite3.connect(path).execute("SELECT COUNT(*) FROM evidence_nodes").fetchone()[0] == nodes
    assert ledger.get_investigation_graph("u1", "i1")["graphStatus"]["complete"] is True


def test_best_effort_graph_logs_safe_error_code(tmp_path, caplog):
    """L1: graph failure logs catalog error_code only."""
    import logging

    calls = {"n": 0}

    def openai_handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return _openai_ok()(_request)

    def boom(self, *args, **kwargs):
        raise ValueError("boom secret-token-should-not-appear")

    app = create_app(
        settings=_settings(ledger_path=_ledger(tmp_path, "log.sqlite")),
        openai_transport=httpx.MockTransport(openai_handler),
        parallel_transport=httpx.MockTransport(_search_one()),
    )
    with caplog.at_level(logging.WARNING, logger="app.main"):
        with mock.patch.object(Ledger, "_materialize_skeleton", boom):
            with TestClient(app) as client:
                _auth(client)
                inv = client.post("/api/investigations", json={"input": "claim", "kind": "claim"}).json()[
                    "investigationId"
                ]
                # Search triggers skeleton best-effort
                assert client.post(f"/api/investigations/{inv}/search", json={"queries": ["a"]}).status_code == 200
    joined = " ".join(r.message for r in caplog.records)
    assert "graph_materialization_failed" in joined
    assert "error_code=graph_persist_failed" in joined or "graph_persist_failed" in joined
    assert "secret-token-should-not-appear" not in joined
    assert calls["n"] == 0
