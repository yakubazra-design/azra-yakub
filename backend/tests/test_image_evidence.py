"""Server image evidence is a presentation of the sealed file.

Temporary databases only. The live ledger is not opened.
"""

import json
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from app.image_evidence import RETENTION_STATEMENT, build_image_evidence
from app.images import IMAGE_CONSENT_VERSION
from app.main import create_app
from test_api import DUMMY_OPENAI, _create, _ensure_auth, _ledger, _seal, _settings
from test_assets import _jpeg, _png

FRONTEND = Path(__file__).resolve().parents[2] / "frontend"
FORGED = "ab" * 32


def _openai(_request: httpx.Request) -> httpx.Response:
    content = json.dumps({"assessment": "UNRESOLVED", "findings": [], "why": {}, "uncertainty": []})
    return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})


def _app(tmp_path):
    path = _ledger(tmp_path)
    app = create_app(
        settings=_settings(ledger_path=path, openai_api_key=DUMMY_OPENAI),
        openai_transport=httpx.MockTransport(_openai),
    )
    return path, app


def _upload(client: TestClient, investigation_id: str, data: bytes, client_hash: str | None = None):
    headers = {"Content-Type": "application/octet-stream", "X-Image-Consent": IMAGE_CONSENT_VERSION}
    if client_hash is not None:
        headers["X-Client-Sha256"] = client_hash
    return client.post(f"/api/investigations/{investigation_id}/asset", content=data, headers=headers)


def _snapshots(path: str) -> list[str]:
    import sqlite3

    conn = sqlite3.connect(path)
    try:
        rows = conn.execute("SELECT snapshot_json FROM assessment_snapshots").fetchall()
    finally:
        conn.close()
    return [row[0] for row in rows]


def test_builder_uses_the_sealed_record_and_the_fixed_retention_sentence():
    evidence = build_image_evidence(
        {
            "sha256": "cd" * 32,
            "mediaType": "image/png",
            "byteLength": 12,
            "assetId": "a" * 32,
            "receivedAt": "2026-11-17T14:00:00+00:00",
            "retention": "retained",
            "consentVersion": "image-upload-1",
            "clientHashStatus": "match",
            "imageEvidence": {"sha256": FORGED},
        },
        "UNRESOLVED",
        availability="retained",
        checked_at="2026-11-17T14:05:00+00:00",
    )
    assert evidence["fileIdentity"]["sha256"] == "cd" * 32
    assert evidence["retentionAtSeal"]["statement"] == RETENTION_STATEMENT
    assert "investigation or account is deleted" in RETENTION_STATEMENT
    assert evidence["currentFile"] == {
        "availability": "retained",
        "checkedAt": "2026-11-17T14:05:00+00:00",
    }
    assert evidence["embeddedMetadata"] == {"status": "not_extracted"}
    assert evidence["provenance"] == {
        "version": "absent",
        "status": "not_examined",
        "eventDepiction": "not_established",
    }
    assert evidence["alteration"]["technicalIndicators"] == "not_examined"
    assert evidence["alteration"]["originalComparison"] == "no_separate_original"
    assert evidence["alteration"]["documentedEvidence"] == "none_recorded"
    linked = build_image_evidence(
        {"sha256": "cd" * 32, "byteLength": 1, "clientHashStatus": "not_supplied"},
        "POTENTIAL_MANIPULATION",
        availability="not_checked",
        checked_at="2026-11-17T14:05:00+00:00",
    )
    assert linked["alteration"]["documentedEvidence"] == "source_linked"
    assert linked["currentFile"] == {"availability": "not_checked", "checkedAt": None}
    assert build_image_evidence({"sha256": "not-a-digest", "byteLength": 1}, "UNRESOLVED", availability="retained", checked_at=None) is None
    assert build_image_evidence({"sha256": "cd" * 32, "byteLength": True}, "UNRESOLVED", availability="retained", checked_at=None) is None


def test_assessment_returns_server_identity_without_storing_current_availability(tmp_path):
    png = _png()
    path = _ledger(tmp_path)
    prompts = []

    def capture(request: httpx.Request) -> httpx.Response:
        prompts.append(json.loads(request.content.decode())["messages"][0]["content"])
        return _openai(request)

    app = create_app(
        settings=_settings(ledger_path=path, openai_api_key=DUMMY_OPENAI),
        openai_transport=httpx.MockTransport(capture),
    )
    with TestClient(app) as client:
        _ensure_auth(client, "owner@example.com")
        investigation_id = _create(client, "A claim with an image.")
        uploaded = _upload(client, investigation_id, png, client_hash="11" * 32)
        assert uploaded.status_code == 200, uploaded.text
        server_hash = uploaded.json()["sha256"]
        token = _seal(client, investigation_id)
        assessed = client.post(
            f"/api/investigations/{investigation_id}/assess",
            json={
                "assessmentToken": token,
                "imageEvidence": {"sha256": FORGED, "gpsLat": 1.5, "fileIdentity": {"sha256": FORGED}},
                "sealedAsset": {"sha256": FORGED, "assetId": "client-picked"},
                "currentFile": {"availability": "subsequently_deleted"},
            },
        )
        text_only = _create(client, "A claim without an image.")
        text_assessed = client.post(
            f"/api/investigations/{text_only}/assess",
            json={"assessmentToken": _seal(client, text_only), "imageEvidence": {"sha256": FORGED}},
        )
    assert assessed.status_code == 200, assessed.text
    body = assessed.json()
    evidence = body["imageEvidence"]
    assert evidence["fileIdentity"]["sha256"] == server_hash
    assert evidence["fileIdentity"]["sha256"] != FORGED
    assert evidence["fileIdentity"]["assetId"] == uploaded.json()["assetId"]
    assert evidence["fileIdentity"]["mediaType"] == "image/png"
    assert evidence["fileIdentity"]["byteLength"] == len(png)
    assert evidence["receipt"]["receivedAt"] == uploaded.json()["receivedAt"]
    assert evidence["receipt"]["clientHashStatus"] == "mismatch"
    assert "does not establish manipulation" in evidence["receipt"]["comparison"]
    assert evidence["retentionAtSeal"]["statement"] == RETENTION_STATEMENT
    assert evidence["currentFile"]["availability"] == "retained"
    assert evidence["currentFile"]["checkedAt"]
    assert evidence["alteration"]["documentedEvidence"] == "none_recorded"
    assert body["assessment"] == "INSUFFICIENT_EVIDENCE"
    stored = _snapshots(path)
    assert len(stored) == 2
    joined = "\n".join(stored)
    assert "currentFile" not in joined
    assert "imageEvidence" not in joined
    assert "subsequently_deleted" not in joined
    assert server_hash in joined
    assert FORGED not in joined
    assert len(prompts) == 2
    image_prompt, text_prompt = prompts
    assert server_hash not in image_prompt
    assert "gps" not in image_prompt.lower()
    assert "An image file was sealed for this investigation." in image_prompt
    assert "No image file was sealed for this investigation." in text_prompt
    assert text_assessed.status_code == 200
    assert text_assessed.json()["imageEvidence"] is None
    assert text_assessed.json()["assessment"] == "INSUFFICIENT_EVIDENCE"


def test_deleted_snapshot_cannot_be_retrieved(tmp_path):
    path, app = _app(tmp_path)
    with TestClient(app) as client:
        _ensure_auth(client, "owner@example.com")
        investigation_id = _create(client, "Delete the sealed report.")
        uploaded = _upload(client, investigation_id, _jpeg())
        assert uploaded.status_code == 200
        digest = uploaded.json()["sha256"]
        assessed = client.post(
            f"/api/investigations/{investigation_id}/assess",
            json={"assessmentToken": _seal(client, investigation_id)},
        )
        assert assessed.status_code == 200
        assert assessed.json()["imageEvidence"]["fileIdentity"]["sha256"] == digest
        removed = client.delete(f"/api/investigations/{investigation_id}")
        missing = client.get(f"/api/investigations/{investigation_id}/evidence")
        report = client.get(f"/api/investigations/{investigation_id}/image-evidence")
    assert removed.status_code == 200
    assert removed.json() == {"deleted": True}
    assert missing.status_code == 404
    assert report.status_code == 404
    assert digest not in missing.text
    assert "imageEvidence" not in missing.text
    import sqlite3

    conn = sqlite3.connect(path)
    try:
        snapshots = conn.execute("SELECT COUNT(*) FROM assessment_snapshots").fetchone()[0]
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    finally:
        conn.close()
    assert snapshots == 0
    assert "image_evidence" not in tables
    assert "historical_reports" not in tables


def test_results_page_keeps_identity_and_local_metadata_apart():
    script = (FRONTEND / "engine.js").read_text()
    assert RETENTION_STATEMENT in script
    assert "Local image metadata on this device" in script
    assert "not server-verified evidence" in script
    assert "Separately: image evidence" not in script
    assert "no usable EXIF (capture date not established)" not in script
    assert "Kept until the account is deleted" not in script
    assert "function noteSealedFileDeleted" in script
    deletion = script.split("function noteSealedFileDeleted")[1].split("return {")[0]
    assert "fetch(" not in deletion
    assert "apiGet" not in deletion
    assert "apiPost" not in deletion
    assert "image-evidence-sha256" in deletion
    assess_request = script.split("function assess")[1].split("function validate")[0]
    assert "imageEvidence:" not in assess_request
    assert "serverProvenance" in script
    assert "renderProvenance" in script
    assert "Content Credentials" in script
    assert "c2pa: 'not_examined'" not in script
    assert "No provenance manifest was read." not in script
    assert "They do not prove that the event depicted in the image actually happened." in script
