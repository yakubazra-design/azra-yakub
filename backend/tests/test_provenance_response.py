"""Assessment responses project the sealed provenance record.

Temporary databases only. The live ledger is not opened.
"""

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from secrets import token_hex

import httpx
import pytest
from fastapi.testclient import TestClient

from app.auth import session_mac
from app.c2pa_statuses import ASSESSMENT_OUTCOMES
from app.image_evidence import build_image_evidence
from app.ledger import Ledger
from app.provenance import (
    EVENT_DEPICTION,
    HISTORICAL_STATUS,
    HISTORICAL_VERSION,
    build_provenance_record,
    public_provenance,
)
from test_api import DUMMY_OPENAI, _create, _ensure_auth, _ledger, _settings
from test_assets import _png, _upload
from test_seal_flow import ACTIVATION, Reader, _credential
from test_seal_http import _success_store

SECRET = "s" * 32
PRECISE_LATITUDE = "51.507351"
TRUST_PATH = "/tmp/trust-store-secret-path"
PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\nTUlJ\n-----END PRIVATE KEY-----"
OUTCOMES = {
    "VERIFIED",
    "PARTIALLY_VERIFIED",
    "CONTRADICTED",
    "INSUFFICIENT_EVIDENCE",
    "POTENTIAL_MANIPULATION",
    "UNRESOLVED",
}


def _model(_request):
    content = json.dumps({
        "assessment": "INSUFFICIENT_EVIDENCE",
        "findings": [],
        "why": {"choice": "The model must not decide from a credential."},
        "uncertainty": ["discarded"],
    })
    return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})


def _app(tmp_path, **kwargs):
    path = _ledger(tmp_path)
    prompts = []

    def capture(request: httpx.Request) -> httpx.Response:
        prompts.append(json.loads(request.content.decode())["messages"][0]["content"])
        return _model(request)

    settings = _settings(ledger_path=path, openai_api_key=DUMMY_OPENAI, auth_secret=SECRET)
    app = __import__("app.main", fromlist=["create_app"]).create_app(
        settings=settings,
        openai_transport=httpx.MockTransport(capture),
        **kwargs,
    )
    return path, app, prompts


def _owner(path: str, investigation: str) -> str:
    connection = sqlite3.connect(path)
    try:
        return connection.execute(
            "SELECT owner_id FROM investigations WHERE id = ?",
            (investigation,),
        ).fetchone()[0]
    finally:
        connection.close()


def _rows(path: str):
    connection = sqlite3.connect(path)
    try:
        return connection.execute("SELECT id, snapshot_json FROM assessment_snapshots").fetchall()
    finally:
        connection.close()


def _insert(path: str, owner: str, investigation: str, token: str, body: dict) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """
            INSERT INTO assessment_snapshots (
                id, investigation_id, owner_id, token_hash, snapshot_json,
                created_at, expires_at, consumed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
            """,
            (
                token_hex(16),
                investigation,
                owner,
                session_mac(SECRET, token),
                json.dumps(body),
                datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
                (datetime.now(timezone.utc) + timedelta(minutes=10)).replace(microsecond=0).isoformat(),
            ),
        )
        connection.commit()
    finally:
        connection.close()


def _sealed_asset(uploaded: dict, byte_length: int) -> dict:
    return {
        "sha256": uploaded["sha256"],
        "byteLength": byte_length,
        "mediaType": uploaded["mediaType"],
        "assetId": uploaded["assetId"],
    }


def _context(claim: str = "The event happened.") -> dict:
    return {
        "primaryClaim": claim,
        "verifiablePoints": [],
        "sources": [],
        "independence": {},
        "timeline": {},
    }


def test_projection_uses_the_public_record_and_ignores_the_outcome():
    image = {"sha256": "cd" * 32, "byteLength": 12, "mediaType": "image/png"}
    built = build_provenance_record(
        sha256=image["sha256"],
        byte_length=image["byteLength"],
        media_type=image["mediaType"],
        verified_at="2026-11-20T00:00:00Z",
        failure_code="reader_timeout",
    )
    assert built["ok"] is True
    evidence = build_image_evidence(
        image,
        "POTENTIAL_MANIPULATION",
        availability="retained",
        checked_at="2026-11-20T00:00:01+00:00",
        provenance=built["record"],
    )
    assert evidence["provenance"] == public_provenance(built["record"], image)
    assert evidence["provenance"]["result"]["kind"] == "technical"
    assert evidence["provenance"]["result"]["failureCode"] == "reader_timeout"
    assert evidence["provenance"]["result"]["status"] not in ASSESSMENT_OUTCOMES
    assert evidence["alteration"]["documentedEvidence"] == "source_linked"
    mismatched = dict(built["record"])
    mismatched["image"] = dict(built["record"]["image"])
    mismatched["image"]["sha256"] = "ab" * 32
    hidden = build_image_evidence(
        image,
        "UNRESOLVED",
        availability="retained",
        checked_at=None,
        provenance=mismatched,
    )
    assert hidden["provenance"] == public_provenance(mismatched, image)
    assert hidden["provenance"]["result"]["failureCode"] == "trust_configuration"
    assert "ab" * 32 not in json.dumps(hidden["provenance"])
    invalid = {"pem": PRIVATE_KEY, "latitude": PRECISE_LATITUDE, "path": TRUST_PATH, "actions": ["c2pa.edited"]}
    closed = build_image_evidence(
        image,
        "VERIFIED",
        availability="retained",
        checked_at=None,
        provenance=invalid,
    )
    rendered = json.dumps(closed["provenance"])
    assert closed["provenance"]["result"]["kind"] == "technical"
    assert "PRIVATE KEY" not in rendered
    assert PRECISE_LATITUDE not in rendered
    assert TRUST_PATH not in rendered
    assert "c2pa.edited" not in rendered
    absent = build_image_evidence(image, "UNRESOLVED", availability="retained", checked_at=None)
    assert absent["provenance"] == {
        "version": HISTORICAL_VERSION,
        "status": HISTORICAL_STATUS,
        "eventDepiction": EVENT_DEPICTION,
    }


def test_valid_sealed_provenance_is_projected_apart_from_the_assessment(tmp_path):
    path, app, prompts = _app(
        tmp_path,
        trust_store=_success_store(),
        c2pa_reader=Reader([_credential("credentials_trusted", label="urn:c2pa:response")]),
    )
    png = _png()
    with TestClient(app) as owner, TestClient(app) as stranger:
        _ensure_auth(owner, "owner@example.com")
        _ensure_auth(stranger, "stranger@example.com")
        investigation = _create(owner, "The event happened.")
        uploaded = _upload(owner, investigation, png)
        assert uploaded.status_code == 200, uploaded.text
        sealed = owner.post(f"/api/investigations/{investigation}/seal")
        assert sealed.status_code == 200, sealed.text
        token = sealed.json()["assessmentToken"]
        stored = json.loads(_rows(path)[0][1])
        connection = sqlite3.connect(path)
        try:
            with pytest.raises(sqlite3.IntegrityError, match="sealed snapshot"):
                connection.execute(
                    "UPDATE assessment_snapshots SET snapshot_json = ? WHERE investigation_id = ?",
                    (json.dumps({"provenance": {"result": {"status": "credentials_untrusted"}}}), investigation),
                )
            connection.rollback()
        finally:
            connection.close()
        assessed = owner.post(
            f"/api/investigations/{investigation}/assess",
            json={
                "assessmentToken": token,
                "primaryClaim": "FORGED",
                "provenance": {
                    "result": {"status": "POTENTIAL_MANIPULATION", "kind": "credential"},
                    "pem": PRIVATE_KEY,
                    "latitude": PRECISE_LATITUDE,
                },
                "imageEvidence": {
                    "provenance": {"result": {"status": "credentials_untrusted"}},
                    "gpsLat": PRECISE_LATITUDE,
                    "sha256": "ff" * 32,
                },
            },
        )
        replay = owner.post(
            f"/api/investigations/{investigation}/assess",
            json={"assessmentToken": token},
        )
        stolen = stranger.post(
            f"/api/investigations/{investigation}/assess",
            json={"assessmentToken": token, "provenance": {"result": {"status": "credentials_trusted"}}},
        )
    assert assessed.status_code == 200, assessed.text
    body = assessed.json()
    projected = body["imageEvidence"]["provenance"]
    sealed_image = {
        "sha256": uploaded.json()["sha256"],
        "byteLength": len(png),
        "mediaType": "image/png",
    }
    assert projected == public_provenance(stored["provenance"], sealed_image)
    assert projected["result"]["status"] == "credentials_trusted"
    assert projected["result"]["kind"] == "credential"
    assert projected["policy"]["activationDigest"] == ACTIVATION
    assert projected["eventDepiction"] == "not_established"
    assert set(projected) == {
        "version",
        "verifiedAt",
        "image",
        "reader",
        "policy",
        "result",
        "eventDepiction",
    }
    assert "actions" not in projected["result"]
    assert body["assessment"] == "INSUFFICIENT_EVIDENCE"
    assert body["assessment"] in OUTCOMES
    assert body["assessment"] != projected["result"]["status"]
    # Phase A adds durable identifiers; existing assessment fields keep their meanings.
    assert {"assessment", "findings", "originalMaterial", "why", "uncertainty", "imageEvidence"} <= set(body)
    assert {"assessmentResultId", "snapshotId", "assessedAt"} <= set(body)
    assert "modelAssessment" not in body
    assert "BEGIN CERTIFICATE" not in assessed.text
    assert "PRIVATE KEY" not in assessed.text
    assert PRECISE_LATITUDE not in assessed.text
    assert TRUST_PATH not in assessed.text
    assert "urn:c2pa:response" in json.dumps(projected["result"]["manifests"])
    assert "credentials_trusted" not in prompts[0]
    assert ACTIVATION not in prompts[0]
    assert "PRIVATE KEY" not in prompts[0]
    assert replay.status_code == 403
    assert replay.json()["code"] == "assessment_token_used"
    assert stolen.status_code == 404
    assert json.loads(_rows(path)[0][1])["provenance"] == stored["provenance"]


def test_missing_provenance_returns_not_examined(tmp_path):
    path, app, prompts = _app(tmp_path)
    png = _png()
    with TestClient(app) as client:
        _ensure_auth(client, "owner@example.com")
        investigation = _create(client, "The event happened.")
        uploaded = _upload(client, investigation, png)
        assert uploaded.status_code == 200, uploaded.text
        token = "historical-assessment-token"
        expires = (datetime.now(timezone.utc) + timedelta(minutes=10)).replace(microsecond=0).isoformat()
        assert Ledger(Path(path)).seal_assessment(
            _owner(path, investigation),
            investigation,
            session_mac(SECRET, token),
            _context(),
            expires,
        )
        assessed = client.post(
            f"/api/investigations/{investigation}/assess",
            json={"assessmentToken": token, "provenance": {"status": "credentials_trusted"}},
        )
    assert assessed.status_code == 200, assessed.text
    assert assessed.json()["imageEvidence"]["provenance"] == public_provenance(None)
    assert assessed.json()["assessment"] == "INSUFFICIENT_EVIDENCE"
    assert "provenance" not in json.loads(_rows(path)[0][1])
    assert "credentials_trusted" not in prompts[0]


def test_invalid_and_mismatched_stored_provenance_fail_closed(tmp_path):
    path, app, _prompts = _app(tmp_path)
    png = _png()
    with TestClient(app) as client:
        _ensure_auth(client, "owner@example.com")
        investigation = _create(client, "The event happened.")
        uploaded = _upload(client, investigation, png)
        assert uploaded.status_code == 200, uploaded.text
        asset = _sealed_asset(uploaded.json(), len(png))
        owner = _owner(path, investigation)
        valid = build_provenance_record(
            sha256="ab" * 32,
            byte_length=len(png),
            media_type="image/png",
            verified_at="2026-11-20T00:00:00Z",
            failure_code="witness_unavailable",
        )
        assert valid["ok"] is True
        _insert(path, owner, investigation, "mismatch-token", {
            **_context(),
            "sealedAsset": asset,
            "provenance": valid["record"],
        })
        _insert(path, owner, investigation, "invalid-token", {
            **_context(),
            "sealedAsset": asset,
            "provenance": {
                "version": "c2pa-provenance-1",
                "pem": PRIVATE_KEY,
                "manifestTrustPem": "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----",
                "path": TRUST_PATH,
                "latitude": PRECISE_LATITUDE,
                "actions": [{"action": "c2pa.edited"}],
                "result": {"status": "POTENTIAL_MANIPULATION"},
            },
        })
        mismatched = client.post(
            f"/api/investigations/{investigation}/assess",
            json={"assessmentToken": "mismatch-token"},
        )
        invalid = client.post(
            f"/api/investigations/{investigation}/assess",
            json={"assessmentToken": "invalid-token"},
        )
    assert mismatched.status_code == 200, mismatched.text
    assert invalid.status_code == 200, invalid.text
    safe = {
        "version": "c2pa-provenance-1",
        "result": {
            "kind": "technical",
            "status": "verification_failed",
            "failureCode": "trust_configuration",
            "checks": None,
            "manifests": [],
        },
        "eventDepiction": "not_established",
    }
    assert mismatched.json()["imageEvidence"]["provenance"] == safe
    assert invalid.json()["imageEvidence"]["provenance"] == safe
    assert mismatched.json()["imageEvidence"]["fileIdentity"]["sha256"] == asset["sha256"]
    assert mismatched.json()["assessment"] == "INSUFFICIENT_EVIDENCE"
    combined = mismatched.text + invalid.text
    assert "ab" * 32 not in combined
    assert "PRIVATE KEY" not in combined
    assert "BEGIN CERTIFICATE" not in combined
    assert TRUST_PATH not in combined
    assert PRECISE_LATITUDE not in combined
    assert "c2pa.edited" not in combined
    assert "POTENTIAL_MANIPULATION" not in combined


def test_technical_failure_stays_distinct_from_the_assessment(tmp_path):
    path, app, prompts = _app(tmp_path)
    with TestClient(app) as client:
        _ensure_auth(client, "owner@example.com")
        investigation = _create(client, "The event happened.")
        assert _upload(client, investigation, _png()).status_code == 200
        sealed = client.post(f"/api/investigations/{investigation}/seal")
        assessed = client.post(
            f"/api/investigations/{investigation}/assess",
            json={"assessmentToken": sealed.json()["assessmentToken"]},
        )
    assert sealed.status_code == 200
    assert assessed.status_code == 200, assessed.text
    provenance = assessed.json()["imageEvidence"]["provenance"]
    assert provenance["policy"] is None
    assert provenance["result"]["kind"] == "technical"
    assert provenance["result"]["status"] == "verification_failed"
    assert provenance["result"]["failureCode"] == "trust_configuration"
    assert assessed.json()["assessment"] == "INSUFFICIENT_EVIDENCE"
    assert provenance["result"]["status"] not in OUTCOMES
    assert provenance["result"]["failureCode"] not in OUTCOMES
    assert "trust_configuration" not in prompts[0]
    assert "verification_failed" not in prompts[0]
