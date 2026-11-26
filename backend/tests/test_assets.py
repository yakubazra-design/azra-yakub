"""Server image identity. Temporary databases and temporary asset directories only."""

import hashlib
import json
import os
import sqlite3
import struct
import threading
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from secrets import token_hex

import httpx
import pytest
from fastapi.testclient import TestClient

from app.assetstore import AssetStore, AssetStoreError
from app.backup import BackupError, backup_ledger, restore_ledger
from app.images import IMAGE_CONSENT_VERSION, detect_image
from app.ledger import Ledger, LedgerError
from app.limits import MAX_BODY_BYTES, MAX_IMAGE_BYTES
from app.main import create_app, session_mac
from app.validation import controlled_explanation
from tests.test_api import (
    DUMMY_OPENAI,
    _create,
    _ensure_auth,
    _json_response,
    _ledger,
    _seal,
    _settings,
)

PASSWORD = "correct-horse-battery"
FORGED_HASH = "ab" * 32
FRONTEND = Path(__file__).resolve().parents[2] / "frontend"


def _png() -> bytes:
    def chunk(tag: bytes, payload: bytes) -> bytes:
        crc = zlib.crc32(tag + payload) & 0xFFFFFFFF
        return struct.pack(">I", len(payload)) + tag + payload + struct.pack(">I", crc)

    header = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    pixels = zlib.compress(b"\x00\xff\x00\x00")
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", pixels) + chunk(b"IEND", b"")


def _jpeg() -> bytes:
    frame = b"\x08" + struct.pack(">HH", 1, 1) + b"\x01\x01\x11\x00"
    return b"\xff\xd8\xff\xc0" + struct.pack(">H", len(frame) + 2) + frame + b"\xff\xd9"


def _gif() -> bytes:
    return (
        b"GIF89a"
        + b"\x01\x00\x01\x00\x80\x00\x00\xff\x00\x00\x00\x00\x00"
        + b"!\xf9\x04\x00\x00\x00\x00\x00"
        + b",\x00\x00\x00\x00\x01\x00\x01\x00\x00"
        + b"\x02\x02D\x01\x00;"
    )


def _webp() -> bytes:
    payload = b"\x00"
    chunk = b"VP8 " + struct.pack("<I", len(payload)) + payload + b"\x00"
    body = b"WEBP" + chunk
    return b"RIFF" + struct.pack("<I", len(body)) + body


def _app(tmp_path, **overrides):
    path = _ledger(tmp_path)
    settings = _settings(ledger_path=path, openai_api_key=DUMMY_OPENAI, **overrides)
    return path, create_app(settings=settings)


def _upload(client: TestClient, investigation_id: str, data: bytes, headers: dict | None = None):
    sent = {"Content-Type": "application/octet-stream", "X-Image-Consent": IMAGE_CONSENT_VERSION}
    if headers:
        sent.update(headers)
    return client.post(
        f"/api/investigations/{investigation_id}/asset",
        content=data,
        headers=sent,
    )


def _files(path: str) -> list[Path]:
    root = Path(path).parent / "assets"
    return sorted(item for item in root.iterdir() if item.is_file() and item.suffix == ".bin")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _rows(path: str, query: str, params: tuple = ()):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(query, params).fetchall()
    finally:
        conn.close()


def test_detects_supported_rasters_and_rejects_malformed_bytes():
    png = _png()
    assert detect_image(png) == "image/png"
    assert detect_image(_jpeg()) == "image/jpeg"
    assert detect_image(_gif()) == "image/gif"
    assert detect_image(_webp()) == "image/webp"
    assert detect_image(b"") is None
    assert detect_image(b"\x89PNG\r\n\x1a\nnot-a-png") is None
    assert detect_image(b"GIF89a" + b"\x01\x00\x01\x00\x00\x00\x00;") is None
    assert detect_image(b"GIF89a") is None
    assert detect_image(_jpeg() + b"<script>alert(1)</script>") is None
    assert detect_image(b"RIFF" + b"\x08\x00\x00\x00WEBPVP8 ") is None
    assert detect_image(b"<svg xmlns='http://www.w3.org/2000/svg'></svg>") is None
    assert detect_image(b"<html><script>alert(1)</script></html>") is None
    assert detect_image(b"BM" + b"\x00" * 20) is None
    assert detect_image(png + b"trailing") is None


def test_valid_upload_records_server_identity_outside_the_database(tmp_path):
    png = _png()
    digest = _digest(png)
    path, app = _app(tmp_path)
    with TestClient(app) as client:
        investigation_id = _create(client, "A pictured claim.")
        response = _upload(client, investigation_id, png, {"X-Client-Sha256": digest.upper()})
        evidence = client.get(f"/api/investigations/{investigation_id}/evidence")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["sha256"] == digest
    assert body["byteLength"] == len(png)
    assert body["mediaType"] == "image/png"
    assert body["retention"] == "retained"
    assert body["clientHashStatus"] == "match"
    assert body["consentVersion"] == IMAGE_CONSENT_VERSION
    assert body["investigationId"] == investigation_id
    assert body["receivedAt"]
    assert "storageName" not in body
    assert ".bin" not in response.text
    assert str(tmp_path) not in response.text
    stored = _files(path)
    assert len(stored) == 1
    assert stored[0].read_bytes() == png
    assert (stored[0].stat().st_mode & 0o777) == 0o600
    assert (stored[0].parent.stat().st_mode & 0o777) == 0o700
    assert stored[0].name.endswith(".bin")
    assert png not in Path(path).read_bytes()
    row = _rows(path, "SELECT sha256, byte_length, media_type, retention, client_hash_status FROM image_assets")[0]
    assert row["sha256"] == digest
    assert row["byte_length"] == len(png)
    assert evidence.status_code == 200
    assert digest not in evidence.text
    assert "assets" not in evidence.text


def test_invalid_spoofed_and_oversized_uploads_are_rejected(tmp_path):
    path, app = _app(tmp_path)
    png = _png()
    with TestClient(app) as client:
        investigation_id = _create(client, "Reject the wrong bytes.")
        invalid = _upload(client, investigation_id, b"<html>not an image</html>", {"Content-Type": "image/png"})
        spoofed = _upload(client, investigation_id, png, {"Content-Type": "text/html"})
        declared = client.post(
            f"/api/investigations/{investigation_id}/asset",
            json={"sealedAsset": {"sha256": FORGED_HASH}, "filename": "../escape.png"},
        )
        too_wide = _upload(client, investigation_id, b"x" * (MAX_IMAGE_BYTES + 1))
        ordinary = client.post(
            "/api/investigations",
            content=b"x" * (MAX_BODY_BYTES + 1),
            headers={"Content-Type": "application/json"},
        )
        below_image_limit = _upload(client, investigation_id, b"x" * (MAX_BODY_BYTES + 1))
    assert invalid.status_code == 400
    assert invalid.json()["code"] == "invalid_image"
    assert spoofed.status_code == 200
    assert spoofed.json()["mediaType"] == "image/png"
    assert spoofed.json()["sha256"] == _digest(png)
    assert declared.status_code == 400
    assert FORGED_HASH not in Path(path).read_text(errors="ignore")
    assert too_wide.status_code == 413
    assert too_wide.json()["code"] == "request_too_large"
    assert ordinary.status_code == 413
    assert below_image_limit.status_code == 400
    names = [item.name for item in _files(path)]
    assert names == [names[0]]
    assert ".." not in names[0]
    assert not (Path(path).parent / "escape.png").exists()


def test_forged_client_hash_does_not_become_the_server_identity(tmp_path):
    png = _png()
    path, app = _app(tmp_path)
    with TestClient(app) as client:
        investigation_id = _create(client, "The browser hash is untrusted.")
        forged = _upload(client, investigation_id, png, {"X-Client-Sha256": FORGED_HASH})
        unusable = _upload(client, investigation_id, png, {"X-Client-Sha256": "definitely-not-sha256"})
        omitted = _upload(client, investigation_id, _jpeg())
    assert forged.status_code == 200
    assert forged.json()["sha256"] == _digest(png)
    assert forged.json()["sha256"] != FORGED_HASH
    assert forged.json()["clientHashStatus"] == "mismatch"
    assert FORGED_HASH not in forged.text
    assert unusable.json()["clientHashStatus"] == "unusable"
    assert unusable.json()["sha256"] == _digest(png)
    assert omitted.json()["clientHashStatus"] == "not_supplied"
    assert omitted.json()["mediaType"] == "image/jpeg"
    assert omitted.json()["sha256"] == _digest(_jpeg())
    stored = {row["sha256"] for row in _rows(path, "SELECT sha256 FROM image_assets")}
    assert stored == {_digest(_jpeg())}
    assert FORGED_HASH not in Path(path).read_text(errors="ignore")


def test_cross_account_and_unknown_investigation_are_not_found(tmp_path):
    png = _png()
    path, app = _app(tmp_path)
    with TestClient(app) as owner, TestClient(app) as stranger:
        investigation_id = _create(owner, "Owned claim")
        _ensure_auth(stranger)
        denied = _upload(stranger, investigation_id, png)
        missing = _upload(owner, "not-a-real-id", png)
        kept = _upload(owner, investigation_id, png)
    assert denied.status_code == 404
    assert denied.json()["code"] == "not_found"
    assert missing.status_code == 404
    assert kept.status_code == 200
    assert len(_files(path)) == 1
    assert _rows(path, "SELECT COUNT(*) AS n FROM image_assets")[0]["n"] == 1


def test_snapshot_seals_the_server_identity_before_assessment(tmp_path):
    png = _png()
    digest = _digest(png)
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["prompt"] = json.loads(request.content.decode())["messages"][0]["content"]
        content = json.dumps({
            "assessment": "POTENTIAL_MANIPULATION",
            "findings": [{"type": "caution", "text": "The image was manipulated.", "sources": []}],
            "why": {"choice": "The model says this was manipulated."},
            "uncertainty": ["The model says this was manipulated."],
        })
        return _json_response({"choices": [{"message": {"content": content}}]})

    path = _ledger(tmp_path)

    def search(_request: httpx.Request) -> httpx.Response:
        return _json_response({
            "results": [{
                "url": "https://www.cdc.gov/example",
                "title": "Example finding",
                "publish_date": "2024-05-01",
                "excerpts": ["The event was reported."],
            }],
        })

    app = create_app(
        settings=_settings(ledger_path=path, openai_api_key=DUMMY_OPENAI, parallel_api_key="test-parallel-key"),
        openai_transport=httpx.MockTransport(handler),
        parallel_transport=httpx.MockTransport(search),
    )
    with TestClient(app) as client:
        investigation_id = _create(client, "The event happened.")
        found = client.post(
            f"/api/investigations/{investigation_id}/search",
            json={"queries": ["event evidence"]},
        )
        assert found.status_code == 200, found.text
        uploaded = _upload(client, investigation_id, png, {"X-Client-Sha256": FORGED_HASH})
        before = _rows(path, "SELECT COUNT(*) AS n FROM assessment_snapshots")[0]["n"]
        token = _seal(client, investigation_id)
        late = _upload(client, investigation_id, _jpeg(), {"X-Client-Sha256": digest})
        assessed = client.post(
            f"/api/investigations/{investigation_id}/assess",
            json={
                "assessmentToken": token,
                "imageEvidence": {"sha256": FORGED_HASH, "gpsLat": 1.5, "gpsLon": 2, "fileName": "photo.jpg"},
                "sealedAsset": {"sha256": FORGED_HASH, "assetId": "client-picked"},
            },
        )
        replay = client.post(
            f"/api/investigations/{investigation_id}/assess",
            json={"assessmentToken": token},
        )
    assert before == 0
    assert uploaded.status_code == 200
    assert late.status_code == 409
    assert late.json()["code"] == "asset_after_seal"
    snapshot = json.loads(_rows(path, "SELECT snapshot_json FROM assessment_snapshots")[0]["snapshot_json"])
    sealed = snapshot["sealedAsset"]
    assert sealed["sha256"] == digest
    assert sealed["consentVersion"] == IMAGE_CONSENT_VERSION
    assert sealed["receivedAt"]
    assert sealed["assetId"] == uploaded.json()["assetId"]
    assert sealed["byteLength"] == len(png)
    assert sealed["mediaType"] == "image/png"
    assert "storageName" not in sealed
    assert FORGED_HASH not in snapshot["sealedAsset"]["sha256"]
    assert "photo.jpg" not in json.dumps(snapshot)
    assert assessed.status_code == 200
    assert assessed.json()["assessment"] == "UNRESOLVED"
    assert assessed.json()["why"] == controlled_explanation("UNRESOLVED")["why"]
    assert "manipulated" not in assessed.text
    assert digest not in seen["prompt"]
    assert FORGED_HASH not in seen["prompt"]
    assert "photo.jpg" not in seen["prompt"]
    assert "GPS=" not in seen["prompt"]
    assert "An image file was sealed for this investigation." in seen["prompt"]
    assert "do not use POTENTIAL_MANIPULATION on this basis alone." in seen["prompt"]
    assert replay.status_code == 403
    assert replay.json()["code"] == "assessment_token_used"
    assert [item.read_bytes() for item in _files(path)] == [png]


def test_provider_failure_still_consumes_the_token_and_keeps_the_file(tmp_path):
    png = _png()

    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out")

    path = _ledger(tmp_path)
    app = create_app(
        settings=_settings(ledger_path=path, openai_api_key=DUMMY_OPENAI),
        openai_transport=httpx.MockTransport(handler),
    )
    with TestClient(app) as client:
        investigation_id = _create(client, "The event happened.")
        uploaded = _upload(client, investigation_id, png)
        token = _seal(client, investigation_id)
        failed = client.post(
            f"/api/investigations/{investigation_id}/assess",
            json={"assessmentToken": token, "imageEvidence": {"sha256": FORGED_HASH}},
        )
        replay = client.post(
            f"/api/investigations/{investigation_id}/assess",
            json={"assessmentToken": token},
        )
    assert uploaded.status_code == 200
    assert failed.status_code == 502
    assert failed.json()["code"] == "server_unavailable"
    assert "assessment" not in failed.json()
    assert replay.status_code == 403
    assert replay.json()["code"] == "assessment_token_used"
    assert _files(path)[0].read_bytes() == png


def test_account_deletion_removes_records_and_bytes(tmp_path):
    png = _png()
    path, app = _app(tmp_path)
    with TestClient(app) as client:
        _ensure_auth(client, "owner@example.com", PASSWORD)
        investigation_id = _create(client, "Delete me.")
        uploaded = _upload(client, investigation_id, png)
        wrong = client.request("DELETE", "/api/auth/account", json={"password": "wrong-password-value"})
        still_there = _files(path)
        deleted = client.request("DELETE", "/api/auth/account", json={"password": PASSWORD})
        again = client.post("/api/auth/login", json={"email": "owner@example.com", "password": PASSWORD})
    assert uploaded.status_code == 200
    assert wrong.status_code == 403
    assert len(still_there) == 1
    assert deleted.status_code == 200
    assert deleted.json() == {"ok": True}
    assert _rows(path, "SELECT COUNT(*) AS n FROM image_assets")[0]["n"] == 0
    assert _rows(path, "SELECT COUNT(*) AS n FROM users")[0]["n"] == 0
    # Image bins must be gone. The video store may leave empty scaffolding dirs.
    assert list((Path(path).parent / "assets").glob("*.bin")) == []
    assert list((Path(path).parent / "assets").rglob("*.bin")) == []
    assert again.status_code == 401


def test_cleanup_failure_does_not_claim_the_account_or_file_was_deleted(tmp_path):
    png = _png()
    path, app = _app(tmp_path)
    assets = Path(path).parent / "assets"
    with TestClient(app) as client:
        _ensure_auth(client, "owner@example.com", PASSWORD)
        investigation_id = _create(client, "Keep the account if the file remains.")
        uploaded = _upload(client, investigation_id, png)
        stored = _files(path)[0]
        os.chmod(assets, 0o555)
        try:
            failed = client.request("DELETE", "/api/auth/account", json={"password": PASSWORD})
            present = stored.exists()
            session = client.get("/api/auth/session")
            remaining = _rows(path, "SELECT COUNT(*) AS n FROM image_assets")[0]["n"]
        finally:
            os.chmod(assets, 0o700)
        deleted = client.request("DELETE", "/api/auth/account", json={"password": PASSWORD})
    assert uploaded.status_code == 200
    assert failed.status_code == 500
    assert failed.json()["ok"] is False
    assert failed.json()["accountDeleted"] is False
    assert failed.json()["assetBytesDeleted"] is False
    assert failed.json()["code"] == "asset_cleanup_failed"
    assert present
    assert session.status_code == 200
    assert remaining == 1
    assert str(stored) not in failed.text
    assert deleted.status_code == 200
    assert deleted.json() == {"ok": True}
    assert not stored.exists()


def test_investigation_deletion_stops_when_the_file_cannot_be_removed(tmp_path):
    png = _png()
    path, app = _app(tmp_path)
    assets = Path(path).parent / "assets"
    with TestClient(app) as client:
        investigation_id = _create(client, "Keep the investigation if the file remains.")
        _upload(client, investigation_id, png)
        stored = _files(path)[0]
        os.chmod(assets, 0o555)
        try:
            failed = client.delete(f"/api/investigations/{investigation_id}")
            evidence = client.get(f"/api/investigations/{investigation_id}/evidence")
            remained = stored.exists()
        finally:
            os.chmod(assets, 0o700)
        deleted = client.delete(f"/api/investigations/{investigation_id}")
    assert failed.status_code == 500
    assert failed.json()["deleted"] is False
    assert failed.json()["code"] == "asset_cleanup_failed"
    assert remained
    assert evidence.status_code == 200
    assert deleted.status_code == 200
    assert deleted.json() == {"deleted": True}
    assert not stored.exists()
    assert _rows(path, "SELECT COUNT(*) AS n FROM image_assets")[0]["n"] == 0


def test_replacing_an_unsealed_image_reports_a_file_that_remains(tmp_path):
    png = _png()
    path, app = _app(tmp_path)
    with TestClient(app) as client:
        investigation_id = _create(client, "Replace the file.")
        first = _upload(client, investigation_id, png)
        previous = _files(path)[0]
        previous.unlink()
        previous.mkdir()
        try:
            second = _upload(client, investigation_id, _jpeg())
        finally:
            if previous.is_dir():
                previous.rmdir()
    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["previousFileRemoved"] is False
    assert second.json()["sha256"] == _digest(_jpeg())
    assert str(previous) not in second.text
    assert _rows(path, "SELECT COUNT(*) AS n FROM image_assets")[0]["n"] == 1


def test_database_failure_after_the_password_check_does_not_report_success(tmp_path, monkeypatch):
    png = _png()
    path, app = _app(tmp_path)
    with TestClient(app) as client:
        _ensure_auth(client, "owner@example.com", PASSWORD)
        investigation_id = _create(client, "Bytes can go before the row does.")
        _upload(client, investigation_id, png)

        def fail_erase(user_id, password):
            raise LedgerError("The evidence ledger is unavailable.")

        monkeypatch.setattr(app.state.ledger, "erase_account", fail_erase)
        failed = client.request("DELETE", "/api/auth/account", json={"password": PASSWORD})
    assert failed.status_code == 500
    assert failed.json().get("ok") is not True
    assert failed.json()["accountDeleted"] is False
    assert failed.json()["filesMayBeRemoved"] is True
    assert "still exists" in failed.json()["message"]
    assert "retried safely" in failed.json()["message"]
    assert _rows(path, "SELECT COUNT(*) AS n FROM users")[0]["n"] == 1
    assert list((Path(path).parent / "assets").glob("*.bin")) == []
    assert list((Path(path).parent / "assets").rglob("*.bin")) == []


def test_frontend_discloses_transmission_before_a_file_is_sent():
    html = (FRONTEND / "index.html").read_text()
    script = (FRONTEND / "engine.js").read_text()
    assert "nothing is uploaded anywhere" not in html
    assert "Nothing is sent until you confirm" in html
    assert "uploads the original file to the RealityCheck AI server" in html
    assert "original file bytes are retained until the account is deleted" in html
    assert "Embedded EXIF information, including GPS location and camera details, may be included" in html
    assert "not necessarily transmitted to the AI model" in html
    assert "does not establish authenticity or manipulation" in html
    assert "stay on this device" not in html
    assert "not sent to the server" not in script
    assert "X-Image-Consent" in script
    assert IMAGE_CONSENT_VERSION in script
    assert "Send image for file identity" in html
    assert "Keep the image on this device" in html
    assert "if (!sendConsent || !currentFile) return null;" in script
    assert "imageEvidence:" not in script.split("function assess")[1].split("function validate")[0]
    assert "GPS=" not in script.split("function assess")[1].split("function validate")[0]


def test_upload_requires_the_current_consent_version(tmp_path):
    _path, app = _app(tmp_path)
    with TestClient(app) as client:
        investigation_id = _create(client, "Consent is required.")
        refused = client.post(
            f"/api/investigations/{investigation_id}/asset",
            content=_png(),
            headers={"Content-Type": "application/octet-stream"},
        )
        wrong = client.post(
            f"/api/investigations/{investigation_id}/asset",
            content=_png(),
            headers={"Content-Type": "application/octet-stream", "X-Image-Consent": "image-upload-0"},
        )
    assert refused.status_code == 400
    assert refused.json()["code"] == "consent_required"
    assert wrong.status_code == 400
    assert _files(_path) == []


def test_concurrent_upload_and_seal_agree_on_one_file(tmp_path, monkeypatch):
    path = Path(_ledger(tmp_path))
    ledger = Ledger(path)
    owner = ledger.create_account("race@example.com", "not-a-password-hash")
    store = AssetStore.for_ledger(path)
    png = _png()
    digest = _digest(png)
    expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()

    def asset_rows(investigation):
        return _rows(
            path,
            """
            SELECT sha256, byte_length, storage_name
            FROM image_assets WHERE investigation_id = ?
            """,
            (investigation,),
        )

    def snapshot_rows(investigation):
        return _rows(
            path,
            "SELECT snapshot_json FROM assessment_snapshots WHERE investigation_id = ?",
            (investigation,),
        )

    def assert_stored_file(row):
        stored = path.parent / "assets" / row["storage_name"]
        data = stored.read_bytes()
        assert row["sha256"] == digest == _digest(data)
        assert int(row["byte_length"]) == len(data) == len(png)
        assert data == png
        assert row["sha256"] != FORGED_HASH

    def assert_sealed_identity(raw):
        body = json.loads(raw)
        sealed = body["sealedAsset"]
        assert sealed["sha256"] == digest
        assert sealed["byteLength"] == len(png)
        assert sealed["mediaType"] == "image/png"
        assert sealed["consentVersion"] == IMAGE_CONSENT_VERSION
        assert FORGED_HASH not in raw
        return sealed

    def seal_once(investigation):
        return ledger.seal_assessment(
            owner,
            investigation,
            token_hex(32),
            {"primaryClaim": "The event happened.", "sealedAsset": {"sha256": FORGED_HASH}},
            expires,
        )

    def assert_follow_up_seal(investigation):
        assert seal_once(investigation)
        saved = snapshot_rows(investigation)
        rows = asset_rows(investigation)
        assert len(saved) == 1
        assert len(rows) == 1
        assert_sealed_identity(saved[0]["snapshot_json"])
        assert_stored_file(rows[0])

    def assert_abort(investigation, outcome):
        """A seal that loses the pre-read race inserts nothing and keeps the file."""
        assert outcome.get("aborted") is True
        assert outcome.get("seal") is None
        assert outcome["upload"] == "saved"
        assert snapshot_rows(investigation) == []
        rows = asset_rows(investigation)
        assert len(rows) == 1
        assert_stored_file(rows[0])
        assert_follow_up_seal(investigation)

    # The pre-read finishes before the upload commits, then the locked read
    # sees the new row. That abort is one supported result of the race.
    investigation = ledger.create_investigation(owner, "claim", "The event happened.")
    prepared = threading.Event()
    release = threading.Event()
    original = Ledger._prepare_seal_metadata

    def prepare(self, owner_id, investigation_id):
        result = original(self, owner_id, investigation_id)
        prepared.set()
        assert release.wait(5)
        return result

    monkeypatch.setattr(Ledger, "_prepare_seal_metadata", prepare)
    held = {}
    held_failures = []

    def held_upload():
        try:
            asset_id = token_hex(16)
            storage = store.write(asset_id, png, owner_id=owner, investigation_id=investigation)
            status, _previous = ledger.save_image_asset(
                owner,
                investigation,
                asset_id,
                digest,
                len(png),
                "image/png",
                "not_supplied",
                storage,
                IMAGE_CONSENT_VERSION,
            )
            held["upload"] = status
        except Exception as exc:
            held_failures.append(exc)

    def held_seal():
        try:
            held["seal"] = seal_once(investigation)
        except LedgerError:
            held["aborted"] = True
        except Exception as exc:
            held_failures.append(exc)

    upload_thread = threading.Thread(target=held_upload)
    seal_thread = threading.Thread(target=held_seal)
    try:
        seal_thread.start()
        assert prepared.wait(5)
        upload_thread.start()
        upload_thread.join(5)
        assert upload_thread.is_alive() is False
    finally:
        release.set()
        seal_thread.join(5)
    assert seal_thread.is_alive() is False
    assert held_failures == []
    monkeypatch.undo()
    assert_abort(investigation, held)

    for _round in range(20):
        investigation = ledger.create_investigation(owner, "claim", "The event happened.")
        barrier = threading.Barrier(2)
        outcome = {}
        failures = []

        def upload():
            try:
                barrier.wait()
                asset_id = token_hex(16)
                try:
                    storage = store.write(asset_id, png, owner_id=owner, investigation_id=investigation)
                except AssetStoreError:
                    outcome["upload"] = "write"
                    return
                try:
                    status, _previous = ledger.save_image_asset(
                        owner,
                        investigation,
                        asset_id,
                        digest,
                        len(png),
                        "image/png",
                        "not_supplied",
                        storage,
                        IMAGE_CONSENT_VERSION,
                    )
                except LedgerError:
                    store.remove(storage)
                    outcome["upload"] = "error"
                    return
                if status != "saved":
                    store.remove(storage)
                outcome["upload"] = status
            except Exception as exc:
                failures.append(exc)

        def seal():
            try:
                barrier.wait()
                try:
                    outcome["seal"] = seal_once(investigation)
                except LedgerError:
                    outcome["aborted"] = True
            except Exception as exc:
                failures.append(exc)

        threads = [threading.Thread(target=upload), threading.Thread(target=seal)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
        assert [thread.is_alive() for thread in threads] == [False, False]
        assert failures == []
        snapshots = snapshot_rows(investigation)
        rows = asset_rows(investigation)
        if outcome.get("aborted"):
            assert_abort(investigation, outcome)
            continue
        assert len(snapshots) == 1
        body = json.loads(snapshots[0]["snapshot_json"])
        sealed = body.get("sealedAsset")
        if sealed:
            assert outcome["seal"]
            assert sealed["sha256"] == digest
            assert sealed["consentVersion"] == IMAGE_CONSENT_VERSION
            assert len(rows) == 1
            assert rows[0]["sha256"] == digest
            stored = path.parent / "assets" / rows[0]["storage_name"]
            assert stored.read_bytes() == png
            assert FORGED_HASH not in json.dumps(sealed)
        else:
            assert outcome["upload"] == "sealed"
            assert outcome["seal"]
            assert rows == []
            assert FORGED_HASH not in snapshots[0]["snapshot_json"]


def test_partial_writes_and_a_failed_rename_do_not_keep_a_bad_file(tmp_path, monkeypatch):
    path = Path(_ledger(tmp_path))
    Ledger(path)
    store = AssetStore.for_ledger(path)
    png = _png()
    real_write = os.write

    def fail_before_rename(fd, data):
        raise OSError("before rename")

    monkeypatch.setattr(os, "write", fail_before_rename)
    early = token_hex(16)
    with pytest.raises(AssetStoreError):
        store.write(early, png)
    assert not (store.root / f"{early}.bin").exists()
    assert list(store.root.glob("*.partial")) == []
    monkeypatch.undo()

    def short_write(fd, data):
        return real_write(fd, bytes(data[:1]))

    monkeypatch.setattr(os, "write", short_write)
    name = store.write(token_hex(16), png)
    assert (store.root / name).read_bytes() == png
    monkeypatch.undo()

    real_replace = os.replace

    def fail_after_replace(source, target):
        real_replace(source, target)
        raise OSError("after rename")

    monkeypatch.setattr(os, "replace", fail_after_replace)
    asset_id = token_hex(16)
    try:
        store.write(asset_id, png, owner_id="owner", investigation_id="investigation")
        raised = False
    except AssetStoreError:
        raised = True
    assert raised
    assert not (store.root / f"{asset_id}.bin").exists()
    assert list(store.root.glob("*.partial")) == []
    assert _rows(path, "SELECT COUNT(*) AS n FROM image_assets")[0]["n"] == 0


def test_a_file_left_after_rename_is_deleted_with_the_account(tmp_path, monkeypatch):
    path, app = _app(tmp_path)
    store = app.state.assets
    real_replace = os.replace

    def fail_after_replace(source, target):
        real_replace(source, target)
        raise OSError("after rename")

    monkeypatch.setattr(os, "replace", fail_after_replace)
    monkeypatch.setattr(AssetStore, "_unlink_quiet", lambda self, candidate: False)
    with TestClient(app) as client:
        _ensure_auth(client, "owner@example.com", PASSWORD)
        investigation_id = _create(client, "Keep the unfinished file.")
        failed = _upload(client, investigation_id, _png())
        assert failed.status_code == 503
        pending = store.pending_entries()
        assert len(pending) == 1
        assert (store.root / pending[0][0]).is_file()
        assert _rows(path, "SELECT COUNT(*) AS n FROM image_assets")[0]["n"] == 0
        monkeypatch.undo()
        deleted = client.request("DELETE", "/api/auth/account", json={"password": PASSWORD})
    assert deleted.status_code == 200
    assert deleted.json() == {"ok": True}
    assert _files(path) == []
    assert store.pending_entries() == []


def test_replacement_cleanup_is_removed_with_the_account(tmp_path):
    png = _png()
    path, app = _app(tmp_path)
    with TestClient(app) as client:
        _ensure_auth(client, "owner@example.com", PASSWORD)
        investigation_id = _create(client, "Replace and delete.")
        _upload(client, investigation_id, png)
        previous = _files(path)[0]
        previous.unlink()
        previous.mkdir()
        second = _upload(client, investigation_id, _jpeg())
        assert second.json()["previousFileRemoved"] is False
        blocked = client.request("DELETE", "/api/auth/account", json={"password": PASSWORD})
        assert blocked.status_code == 500
        assert blocked.json()["accountDeleted"] is False
        names = [row["storage_name"] for row in _rows(path, "SELECT storage_name FROM asset_cleanup")]
        assert previous.name in names
        previous.rmdir()
        deleted = client.request("DELETE", "/api/auth/account", json={"password": PASSWORD})
    assert deleted.status_code == 200
    assert deleted.json() == {"ok": True}
    assert _rows(path, "SELECT COUNT(*) AS n FROM asset_cleanup")[0]["n"] == 0
    assert _rows(path, "SELECT COUNT(*) AS n FROM image_assets")[0]["n"] == 0
    assert _files(path) == []


def test_investigation_deletion_retries_after_a_pending_file_is_removed(tmp_path):
    png = _png()
    path, app = _app(tmp_path)
    with TestClient(app) as client:
        investigation_id = _create(client, "Retry the investigation.")
        _upload(client, investigation_id, png)
        _upload(client, investigation_id, _jpeg())
        pending = _rows(path, "SELECT storage_name FROM asset_cleanup")
        assert pending == []
        stored = _files(path)[0]
        stored.unlink()
        stored.mkdir()
        ledger = app.state.ledger
        asset = ledger.image_asset(
            _rows(path, "SELECT owner_id FROM image_assets")[0]["owner_id"],
            investigation_id,
        )
        ledger.record_asset_cleanup(
            asset["ownerId"],
            investigation_id,
            stored.name,
            asset["sha256"],
            asset["byteLength"],
            "replaced",
        )
        failed = client.delete(f"/api/investigations/{investigation_id}")
        assert failed.status_code == 500
        assert failed.json()["deleted"] is False
        assert "still exists" in failed.json()["message"] or "could not be removed" in failed.json()["message"]
        evidence = client.get(f"/api/investigations/{investigation_id}/evidence")
        assert evidence.status_code == 200
        stored.rmdir()
        deleted = client.delete(f"/api/investigations/{investigation_id}")
    assert deleted.status_code == 200
    assert deleted.json() == {"deleted": True}
    assert _files(path) == []
    assert _rows(path, "SELECT COUNT(*) AS n FROM asset_cleanup")[0]["n"] == 0


def test_investigation_deletion_removes_a_pending_file(tmp_path):
    path, app = _app(tmp_path)
    with TestClient(app) as client:
        investigation_id = _create(client, "Remove the pending file.")
        owner = _rows(path, "SELECT owner_id FROM investigations")[0]["owner_id"]
        name = token_hex(16) + ".bin"
        target = Path(path).parent / "assets" / name
        target.write_bytes(b"left-behind")
        os.chmod(target, 0o600)
        app.state.assets.note_pending(name, owner, investigation_id)
        deleted = client.delete(f"/api/investigations/{investigation_id}")
    assert deleted.status_code == 200
    assert deleted.json() == {"deleted": True}
    assert not target.exists()
    assert app.state.assets.pending_entries() == []


def test_coordinated_backup_and_restore_round_trip(tmp_path):
    png = _png()
    path, app = _app(tmp_path)
    with TestClient(app) as client:
        investigation_id = _create(client, "Back this up.")
        uploaded = _upload(client, investigation_id, png)
    assert uploaded.status_code == 200
    written = backup_ledger(Path(path), tmp_path / "backups")
    manifest = json.loads(Path(str(written) + ".manifest.json").read_text())
    assert manifest["format"] == 1
    assert manifest["files"][0]["sha256"] == _digest(png)
    assert manifest["files"][0]["role"] == "asset"
    copied = Path(str(written) + ".assets") / manifest["files"][0]["name"]
    assert copied.read_bytes() == png
    assert (copied.stat().st_mode & 0o777) == 0o600
    restored = tmp_path / "restored" / "ledger.sqlite"
    restore_ledger(written, restored, application_stopped=True)
    restored_file = restored.parent / "assets" / manifest["files"][0]["name"]
    assert restored_file.read_bytes() == png
    assert Ledger(restored).check_health() is True


def test_restore_rejects_missing_corrupt_and_unreferenced_files(tmp_path):
    png = _png()
    path, app = _app(tmp_path)
    with TestClient(app) as client:
        investigation_id = _create(client, "Guard the restore.")
        _upload(client, investigation_id, png)
    written = backup_ledger(Path(path), tmp_path / "backups")
    assets = Path(str(written) + ".assets")
    stored = next(assets.iterdir())
    destination = tmp_path / "restored.sqlite"
    stored.unlink()
    with pytest.raises(BackupError):
        restore_ledger(written, destination, application_stopped=True)
    assert not destination.exists()

    written = backup_ledger(Path(path), tmp_path / "backups-2")
    assets = Path(str(written) + ".assets")
    stored = next(assets.iterdir())
    blob = bytearray(stored.read_bytes())
    blob[-1] ^= 0xFF
    stored.write_bytes(blob)
    with pytest.raises(BackupError):
        restore_ledger(written, destination, application_stopped=True)
    assert not destination.exists()

    extra = Path(path).parent / "assets" / (token_hex(16) + ".bin")
    extra.write_bytes(b"orphan")
    with pytest.raises(BackupError):
        backup_ledger(Path(path), tmp_path / "backups-3")
    assert list((tmp_path / "backups-3").glob("*")) == []


def _login(client: TestClient, email: str = "owner@example.com") -> None:
    logged = client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    assert logged.status_code == 200, logged.text
    client.headers["X-CSRF-Token"] = logged.json()["csrfToken"]


def _owner_and_investigation(path: Path) -> tuple[str, str]:
    rows = _rows(path, "SELECT owner_id, id FROM investigations")
    return rows[0]["owner_id"], rows[0]["id"]


def _assert_every_snapshot_image_exists(path: Path | str) -> None:
    """A snapshot that names an image must name bytes that are still on disk.

    A snapshot with no sealed image does not reference a file. One that does
    must match a real asset byte for byte.
    """
    root = Path(path).parent / "assets"
    for row in _rows(path, "SELECT snapshot_json FROM assessment_snapshots"):
        sealed = json.loads(row["snapshot_json"]).get("sealedAsset")
        if sealed is None:
            continue
        assert isinstance(sealed, dict)
        digest = sealed["sha256"]
        matches = [
            item
            for item in root.iterdir()
            if item.is_file() and not item.is_symlink() and item.name.endswith(".bin")
            and hashlib.sha256(item.read_bytes()).hexdigest() == digest
        ]
        assert matches, digest
        assert matches[0].stat().st_size == sealed["byteLength"]


def test_deletion_and_sealing_cannot_leave_a_missing_image(tmp_path):
    for _ in range(12):
        folder = tmp_path / token_hex(4)
        path, app = _app(folder)
        with TestClient(app) as client:
            _ensure_auth(client, "owner@example.com", PASSWORD)
            investigation_id = _create(client, "Race the seal.")
            uploaded = _upload(client, investigation_id, _png())
        digest = uploaded.json()["sha256"]
        owner_id, investigation_id = _owner_and_investigation(path)
        ledger = Ledger(Path(path))
        store = AssetStore.for_ledger(Path(path))
        barrier = threading.Barrier(2)

        def seal():
            barrier.wait()
            try:
                ledger.seal_assessment(
                    owner_id,
                    investigation_id,
                    token_hex(32),
                    {"claim": "A race.", "evidence": []},
                    "2099-01-01T00:00:00Z",
                )
            except LedgerError:
                return

        def remove():
            barrier.wait()
            if not ledger.prepare_investigation_deletion(owner_id, investigation_id):
                return
            for name, _, _ in store.pending_entries() + store.intent_entries():
                store.remove(name)
                store.finish_intent(name)
            for row in _rows(path, "SELECT storage_name FROM image_assets UNION SELECT storage_name FROM asset_cleanup"):
                store.remove(row["storage_name"])
            ledger.delete_investigation(owner_id, investigation_id)

        threads = [threading.Thread(target=seal), threading.Thread(target=remove)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        _assert_every_snapshot_image_exists(path)


def test_deletion_and_assessment_consumption_cannot_use_a_removed_image(tmp_path):
    path, app = _app(tmp_path)
    with TestClient(app) as client:
        _ensure_auth(client, "owner@example.com", PASSWORD)
        investigation_id = _create(client, "Race the assessment.")
        _upload(client, investigation_id, _png())
        token = _seal(client, investigation_id)
    owner_id, investigation_id = _owner_and_investigation(path)
    ledger = Ledger(Path(path))
    store = AssetStore.for_ledger(Path(path))
    barrier = threading.Barrier(2)
    outcome = {}
    file = Path(path).parent / "assets" / _rows(path, "SELECT storage_name FROM image_assets")[0]["storage_name"]
    digest = hashlib.sha256(file.read_bytes()).hexdigest()
    checked = threading.Barrier(2)

    def consume():
        barrier.wait()
        try:
            try:
                snapshot, status = ledger.consume_assessment(
                    owner_id,
                    investigation_id,
                    session_mac(app.state.auth_secret, token),
                )
            except LedgerError:
                outcome["status"] = "unavailable"
                return
            outcome["status"] = status
            asset = None if snapshot is None else snapshot.get("sealedAsset")
            outcome["asset"] = asset
            if isinstance(asset, dict):
                assert file.is_file()
                assert hashlib.sha256(file.read_bytes()).hexdigest() == asset["sha256"] == digest
        finally:
            checked.wait()

    def remove():
        barrier.wait()
        ledger.prepare_investigation_deletion(owner_id, investigation_id)
        checked.wait()
        for row in _rows(path, "SELECT storage_name FROM image_assets UNION SELECT storage_name FROM asset_cleanup"):
            store.remove(row["storage_name"])
        ledger.delete_investigation(owner_id, investigation_id)

    threads = [threading.Thread(target=consume), threading.Thread(target=remove)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if outcome.get("asset"):
        assert outcome["status"] == "ok"
    else:
        assert outcome["status"] in {"missing", "unavailable", "expired", "invalid", "used"}
    _assert_every_snapshot_image_exists(path)


def test_a_crash_after_rename_is_recovered_without_deleting_a_saved_asset(tmp_path):
    from app.assetstore import reconcile_assets

    path, app = _app(tmp_path)
    with TestClient(app) as client:
        _ensure_auth(client, "owner@example.com", PASSWORD)
        investigation_id = _create(client, "Keep the saved file.")
        uploaded = _upload(client, investigation_id, _png())
    saved = Path(path).parent / "assets" / _rows(path, "SELECT storage_name FROM image_assets")[0]["storage_name"]
    saved_bytes = saved.read_bytes()
    store = AssetStore.for_ledger(Path(path))
    owner_id, investigation_id = _owner_and_investigation(path)
    unpublished = store.write(token_hex(16), b"not-saved", owner_id=owner_id, investigation_id=investigation_id)
    assert (store.root / unpublished).is_file()
    assert store.intent_entries()
    reconcile_assets(store.root, {saved.name})
    assert not (store.root / unpublished).exists()
    assert store.intent_entries() == []
    assert saved.read_bytes() == saved_bytes
    stray = store.root / (token_hex(16) + ".bin")
    stray.write_bytes(b"untracked")
    partial = store.root / ".left.partial"
    partial.write_bytes(b"partial")
    Ledger(Path(path))
    assert saved.read_bytes() == saved_bytes
    assert not stray.exists()
    assert not partial.exists()
    assert (store.root / ".quarantine" / stray.name).is_file()
    with TestClient(app) as client:
        _ensure_auth(client, "owner@example.com", PASSWORD)
        health = client.get("/api/health")
    assert health.status_code == 503
    assert uploaded.json()["sha256"] == hashlib.sha256(saved_bytes).hexdigest()


def test_a_directory_sync_failure_does_not_leave_an_untracked_image(tmp_path, monkeypatch):
    def fail(self, directory):
        if directory.name == "assets":
            raise AssetStoreError("directory sync failed")

    monkeypatch.setattr(AssetStore, "_fsync_directory", fail)
    path, app = _app(tmp_path)
    with TestClient(app) as client:
        _ensure_auth(client, "owner@example.com", PASSWORD)
        investigation_id = _create(client, "Fail the directory sync.")
        failed = _upload(client, investigation_id, _png())
    assert failed.status_code == 503
    assert _files(path) == []
    assert _rows(path, "SELECT COUNT(*) AS n FROM image_assets")[0]["n"] == 0


def test_account_and_investigation_deletion_stay_retryable_after_a_database_failure(tmp_path, monkeypatch):
    path, app = _app(tmp_path)
    with TestClient(app) as client:
        _ensure_auth(client, "owner@example.com", PASSWORD)
        investigation_id = _create(client, "Retry after the files are gone.")
        _upload(client, investigation_id, _png())

        def fail_erase(self, user_id, password):
            raise LedgerError("The evidence ledger is unavailable.")

        monkeypatch.setattr(Ledger, "erase_account", fail_erase)
        first = client.request("DELETE", "/api/auth/account", json={"password": PASSWORD})
        second = client.request("DELETE", "/api/auth/account", json={"password": PASSWORD})
        monkeypatch.undo()
        for response in (first, second):
            assert response.status_code == 500
            body = response.json()
            assert body["accountDeleted"] is False
            assert body["filesMayBeRemoved"] is True
            assert "may already have been removed" in body["message"]
            assert "retried safely" in body["message"]
        finished = client.request("DELETE", "/api/auth/account", json={"password": PASSWORD})
    assert finished.status_code == 200
    assert finished.json() == {"ok": True}

    path, app = _app(tmp_path / "investigation")
    with TestClient(app) as client:
        _ensure_auth(client, "owner@example.com", PASSWORD)
        investigation_id = _create(client, "Retry the investigation.")
        _upload(client, investigation_id, _jpeg())

        def fail_delete(self, owner_id, investigation_id):
            raise LedgerError("The evidence ledger is unavailable.")

        monkeypatch.setattr(Ledger, "delete_investigation", fail_delete)
        first = client.delete(f"/api/investigations/{investigation_id}")
        second = client.delete(f"/api/investigations/{investigation_id}")
        monkeypatch.undo()
        for response in (first, second):
            assert response.status_code == 500
            body = response.json()
            assert body["deleted"] is False
            assert body["filesMayBeRemoved"] is True
            assert "may already have been removed" in body["message"]
        finished = client.delete(f"/api/investigations/{investigation_id}")
    assert finished.status_code == 200
    assert finished.json() == {"deleted": True}


def test_upload_and_seal_are_refused_after_investigation_deletion_begins(tmp_path):
    png = _png()
    path, app = _app(tmp_path)
    with TestClient(app) as client:
        _ensure_auth(client, "owner@example.com", PASSWORD)
        kept = _create(client, "This investigation stays.")
        investigation_id = _create(client, "Delete this investigation.")
        _upload(client, investigation_id, png)
        other = _upload(client, kept, _jpeg())
    owner_id, _ignored = _owner_and_investigation(path)
    original = _rows(path, "SELECT storage_name FROM image_assets WHERE investigation_id = ?", (investigation_id,))[0]
    stored = Path(path).parent / "assets" / original["storage_name"]
    original_bytes = stored.read_bytes()
    assert Ledger(Path(path)).prepare_investigation_deletion(owner_id, investigation_id)
    restarted = Ledger(Path(path))
    assert restarted.prepare_investigation_deletion(owner_id, investigation_id)
    with TestClient(app) as client:
        _login(client)
        rejected = _upload(client, investigation_id, _jpeg())
        sealed = client.post(f"/api/investigations/{investigation_id}/seal")
        still_open = _upload(client, kept, _webp())
    assert rejected.status_code == 409
    assert rejected.json()["code"] == "deletion_in_progress"
    assert sealed.status_code == 409
    assert sealed.json()["code"] == "deletion_in_progress"
    assert still_open.status_code == 200
    assert other.status_code == 200
    assert stored.read_bytes() == original_bytes
    current = _rows(
        path,
        "SELECT storage_name, retention FROM image_assets WHERE investigation_id = ?",
        (investigation_id,),
    )
    assert len(current) == 1
    assert current[0]["storage_name"] == original["storage_name"]
    assert current[0]["retention"] == "retiring"
    assert _rows(path, "SELECT COUNT(*) AS n FROM assessment_snapshots WHERE investigation_id = ?", (investigation_id,))[0]["n"] == 0
    assert _rows(path, "SELECT COUNT(*) AS n FROM pending_deletions WHERE investigation_id = ?", (investigation_id,))[0]["n"] == 1
    with TestClient(app) as client:
        _login(client)
        deleted = client.delete(f"/api/investigations/{investigation_id}")
    assert deleted.status_code == 200
    assert deleted.json() == {"deleted": True}
    assert not stored.exists()
    assert _rows(path, "SELECT COUNT(*) AS n FROM pending_deletions")[0]["n"] == 0
    _assert_every_snapshot_image_exists(path)


def test_upload_and_seal_are_refused_for_every_investigation_during_account_deletion(tmp_path):
    path, app = _app(tmp_path)
    with TestClient(app) as client:
        _ensure_auth(client, "owner@example.com", PASSWORD)
        first = _create(client, "First case.")
        second = _create(client, "Second case.")
        _upload(client, first, _png())
        _upload(client, second, _jpeg())
    owner_id = _rows(path, "SELECT id FROM users")[0]["id"]
    names = {
        row["investigation_id"]: row["storage_name"]
        for row in _rows(path, "SELECT investigation_id, storage_name FROM image_assets")
    }
    assert Ledger(Path(path)).prepare_account_deletion(owner_id, PASSWORD) == "ok"
    Ledger(Path(path))
    with TestClient(app) as client:
        _login(client)
        for investigation_id in (first, second):
            rejected = _upload(client, investigation_id, _webp())
            sealed = client.post(f"/api/investigations/{investigation_id}/seal")
            assert rejected.status_code == 409
            assert rejected.json()["code"] == "deletion_in_progress"
            assert sealed.status_code == 409
            assert sealed.json()["code"] == "deletion_in_progress"
            stored = Path(path).parent / "assets" / names[investigation_id]
            assert stored.is_file()
            assert _rows(
                path,
                "SELECT retention FROM image_assets WHERE investigation_id = ?",
                (investigation_id,),
            )[0]["retention"] == "retiring"
    pending = _rows(path, "SELECT investigation_id FROM pending_deletions")
    assert [row["investigation_id"] for row in pending] == [""]
    assert _rows(path, "SELECT COUNT(*) AS n FROM assessment_snapshots")[0]["n"] == 0
    with TestClient(app) as client:
        _login(client)
        deleted = client.request("DELETE", "/api/auth/account", json={"password": PASSWORD})
    assert deleted.status_code == 200
    assert deleted.json() == {"ok": True}
    assert _files(path) == []
    assert _rows(path, "SELECT COUNT(*) AS n FROM pending_deletions")[0]["n"] == 0
    assert _rows(path, "SELECT COUNT(*) AS n FROM users")[0]["n"] == 0


def test_interruption_before_and_after_unlink_keeps_deletion_closed(tmp_path):
    path, app = _app(tmp_path)
    with TestClient(app) as client:
        _ensure_auth(client, "owner@example.com", PASSWORD)
        investigation_id = _create(client, "Interrupt the deletion.")
        _upload(client, investigation_id, _png())
        token = _seal(client, investigation_id)
    owner_id, investigation_id = _owner_and_investigation(path)
    stored = _files(path)[0]
    digest = hashlib.sha256(stored.read_bytes()).hexdigest()
    _assert_every_snapshot_image_exists(path)
    assert Ledger(Path(path)).prepare_investigation_deletion(owner_id, investigation_id)
    assert stored.is_file()
    assert _rows(path, "SELECT COUNT(*) AS n FROM assessment_snapshots")[0]["n"] == 0
    Ledger(Path(path))
    with TestClient(app) as client:
        _login(client)
        rejected = _upload(client, investigation_id, _jpeg())
        sealed = client.post(f"/api/investigations/{investigation_id}/seal")
        replay = client.post(
            f"/api/investigations/{investigation_id}/assess",
            json={"assessmentToken": token},
        )
    assert rejected.status_code == 409
    assert sealed.status_code == 409
    assert replay.status_code == 403
    assert stored.is_file()
    assert hashlib.sha256(stored.read_bytes()).hexdigest() == digest
    AssetStore.for_ledger(Path(path)).remove(stored.name)
    assert not stored.exists()
    Ledger(Path(path))
    with TestClient(app) as client:
        _login(client)
        still_rejected = _upload(client, investigation_id, _webp())
        retried = client.delete(f"/api/investigations/{investigation_id}")
    assert still_rejected.status_code == 409
    assert retried.status_code == 200
    assert retried.json() == {"deleted": True}
    assert _rows(path, "SELECT COUNT(*) AS n FROM assessment_snapshots")[0]["n"] == 0
    assert _rows(path, "SELECT COUNT(*) AS n FROM pending_deletions")[0]["n"] == 0
    assert _rows(path, "SELECT COUNT(*) AS n FROM image_assets")[0]["n"] == 0


def _race_upload_seal_and_deletion(tmp_path: Path, *, with_image: bool, account: bool) -> None:
    """Upload, seal, and deletion start together from one of the two asset states."""
    folder = tmp_path / token_hex(4)
    path, app = _app(folder)
    with TestClient(app) as client:
        _ensure_auth(client, "owner@example.com", PASSWORD)
        investigation_id = _create(client, "Race the replacement.")
        if with_image:
            _upload(client, investigation_id, _png())
    owner_id, investigation_id = _owner_and_investigation(path)
    ledger = Ledger(Path(path))
    store = AssetStore.for_ledger(Path(path))
    barrier = threading.Barrier(3)
    errors: list[BaseException] = []
    outcome: dict = {}

    def upload():
        barrier.wait()
        asset_id = token_hex(16)
        data = _jpeg()
        try:
            name = store.write(asset_id, data, owner_id=owner_id, investigation_id=investigation_id)
        except AssetStoreError:
            # Deletion can unlink an intent file while it is being published.
            outcome["upload"] = "not_stored"
            return
        try:
            status, _previous = ledger.save_image_asset(
                owner_id,
                investigation_id,
                asset_id,
                hashlib.sha256(data).hexdigest(),
                len(data),
                "image/jpeg",
                "not_supplied",
                name,
                IMAGE_CONSENT_VERSION,
            )
        except LedgerError:
            status = "error"
        outcome["upload"] = status
        if status != "saved":
            store.remove(name)
            try:
                store.finish_intent(name)
            except AssetStoreError:
                pass

    def seal():
        barrier.wait()
        try:
            ledger.seal_assessment(
                owner_id,
                investigation_id,
                token_hex(32),
                {"claim": "A race.", "evidence": []},
                "2099-01-01T00:00:00Z",
            )
        except LedgerError:
            return

    def remove():
        barrier.wait()
        if account:
            if ledger.prepare_account_deletion(owner_id, PASSWORD) != "ok":
                return
        elif not ledger.prepare_investigation_deletion(owner_id, investigation_id):
            return
        names = [
            row["storage_name"]
            for row in _rows(
                path,
                "SELECT storage_name FROM image_assets UNION SELECT storage_name FROM asset_cleanup",
            )
        ]
        for item in store.intent_entries():
            names.append(item[0])
        for name in names:
            store.remove(name)
        if account:
            outcome["final"] = ledger.erase_account(owner_id, PASSWORD)
        else:
            outcome["final"] = ledger.delete_investigation(owner_id, investigation_id)

    def guarded(target):
        def run():
            try:
                target()
            except BaseException as exc:
                errors.append(exc)
        return run

    threads = [threading.Thread(target=guarded(upload)), threading.Thread(target=guarded(seal)), threading.Thread(target=guarded(remove))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert outcome.get("final") in {True, "ok"}
    _assert_every_snapshot_image_exists(path)
    assert _rows(path, "SELECT COUNT(*) AS n FROM assessment_snapshots")[0]["n"] == 0
    assert _rows(path, "SELECT COUNT(*) AS n FROM pending_deletions")[0]["n"] == 0
    assert _rows(path, "SELECT COUNT(*) AS n FROM image_assets")[0]["n"] == 0
    if outcome.get("upload") == "saved":
        assert not list((Path(path).parent / "assets").glob("*.bin"))


def test_upload_seal_and_deletion_cannot_leave_a_snapshot_for_a_missing_file(tmp_path):
    for with_image in (False, True):
        for account in (False, True):
            for _ in range(4):
                _race_upload_seal_and_deletion(tmp_path, with_image=with_image, account=account)


def _install_delete_trigger(path: Path | str, name: str, table: str) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            f"""
            CREATE TRIGGER {name}
            BEFORE DELETE ON {table}
            BEGIN
                SELECT RAISE(ABORT, 'simulated failure');
            END
            """
        )
        conn.commit()
    finally:
        conn.close()


def _drop_trigger(path: Path | str, name: str) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.execute(f"DROP TRIGGER {name}")
        conn.commit()
    finally:
        conn.close()


def test_zero_image_investigation_deletion_blocks_until_the_final_delete_commits(tmp_path):
    path, app = _app(tmp_path)
    with TestClient(app) as client:
        _ensure_auth(client, "owner@example.com", PASSWORD)
        kept = _create(client, "This investigation stays.")
        investigation_id = _create(client, "Delete the text-only investigation.")
        _seal(client, investigation_id)
    original = _rows(
        path,
        "SELECT id, snapshot_json FROM assessment_snapshots WHERE investigation_id = ?",
        (investigation_id,),
    )
    assert len(original) == 1
    assert json.loads(original[0]["snapshot_json"]).get("sealedAsset") is None
    _install_delete_trigger(path, "investigations_refuse_delete", "investigations")
    with TestClient(app) as client:
        _login(client)
        failed = client.delete(f"/api/investigations/{investigation_id}")
        rejected = _upload(client, investigation_id, _jpeg())
        sealed = client.post(f"/api/investigations/{investigation_id}/seal")
        kept_upload = _upload(client, kept, _png())
        created = _create(client, "A new investigation is not covered.")
        created_upload = _upload(client, created, _webp())
    assert failed.status_code == 500
    assert failed.json()["deleted"] is False
    assert "simulated" not in failed.text
    assert rejected.status_code == sealed.status_code == 409
    assert rejected.json()["code"] == sealed.json()["code"] == "deletion_in_progress"
    assert kept_upload.status_code == created_upload.status_code == 200
    current = _rows(
        path,
        "SELECT id, snapshot_json FROM assessment_snapshots WHERE investigation_id = ?",
        (investigation_id,),
    )
    assert [(row["id"], row["snapshot_json"]) for row in current] == [
        (original[0]["id"], original[0]["snapshot_json"])
    ]
    assert _rows(path, "SELECT investigation_id FROM pending_deletions")[0]["investigation_id"] == investigation_id
    _assert_every_snapshot_image_exists(path)
    Ledger(Path(path))
    with TestClient(app) as client:
        _login(client)
        failed_again = client.delete(f"/api/investigations/{investigation_id}")
        still_sealed = client.post(f"/api/investigations/{investigation_id}/seal")
    assert failed_again.status_code == 500
    assert still_sealed.status_code == 409
    assert _rows(
        path,
        "SELECT id FROM assessment_snapshots WHERE investigation_id = ?",
        (investigation_id,),
    )[0]["id"] == original[0]["id"]
    assert _rows(path, "SELECT COUNT(*) AS n FROM pending_deletions")[0]["n"] == 1
    _drop_trigger(path, "investigations_refuse_delete")
    with TestClient(app) as client:
        _login(client)
        finished = client.delete(f"/api/investigations/{investigation_id}")
        kept_still = client.post(f"/api/investigations/{kept}/seal")
    assert finished.status_code == 200
    assert finished.json() == {"deleted": True}
    assert kept_still.status_code == 200
    assert _rows(path, "SELECT COUNT(*) AS n FROM assessment_snapshots WHERE investigation_id = ?", (investigation_id,))[0]["n"] == 0
    assert _rows(path, "SELECT COUNT(*) AS n FROM pending_deletions")[0]["n"] == 0
    assert _rows(path, "SELECT COUNT(*) AS n FROM image_assets WHERE investigation_id = ?", (investigation_id,))[0]["n"] == 0
    _assert_every_snapshot_image_exists(path)


def test_zero_image_account_deletion_blocks_every_investigation_until_retry(tmp_path):
    path, app = _app(tmp_path)
    with TestClient(app) as client:
        _ensure_auth(client, "owner@example.com", PASSWORD)
        first = _create(client, "First text-only case.")
        second = _create(client, "Second text-only case.")
        _seal(client, first)
        _seal(client, second)
        wrong = client.request("DELETE", "/api/auth/account", json={"password": "not-the-right-password"})
    assert wrong.status_code == 403
    assert _rows(path, "SELECT COUNT(*) AS n FROM pending_deletions")[0]["n"] == 0
    assert _rows(path, "SELECT COUNT(*) AS n FROM assessment_snapshots")[0]["n"] == 2
    _install_delete_trigger(path, "users_refuse_delete", "users")
    with TestClient(app) as client:
        _login(client)
        failed = client.request("DELETE", "/api/auth/account", json={"password": PASSWORD})
        for investigation_id in (first, second):
            rejected = _upload(client, investigation_id, _jpeg())
            sealed = client.post(f"/api/investigations/{investigation_id}/seal")
            assert rejected.status_code == sealed.status_code == 409
            assert rejected.json()["code"] == sealed.json()["code"] == "deletion_in_progress"
        created = _create(client, "Created after account deletion began.")
        created_upload = _upload(client, created, _png())
        created_seal = client.post(f"/api/investigations/{created}/seal")
    assert failed.status_code == 503
    assert failed.json()["code"] == "ledger_unavailable"
    assert "simulated" not in failed.text
    assert created_upload.status_code == created_seal.status_code == 409
    assert created_upload.json()["code"] == created_seal.json()["code"] == "deletion_in_progress"
    assert _rows(path, "SELECT COUNT(*) AS n FROM assessment_snapshots")[0]["n"] == 2
    assert [row["investigation_id"] for row in _rows(path, "SELECT investigation_id FROM pending_deletions")] == [""]
    _assert_every_snapshot_image_exists(path)
    Ledger(Path(path))
    with TestClient(app) as client:
        _login(client)
        failed_again = client.request("DELETE", "/api/auth/account", json={"password": PASSWORD})
        still_rejected = _upload(client, created, _webp())
    assert failed_again.status_code == 503
    assert still_rejected.status_code == 409
    assert _rows(path, "SELECT COUNT(*) AS n FROM assessment_snapshots")[0]["n"] == 2
    assert _rows(path, "SELECT COUNT(*) AS n FROM pending_deletions")[0]["n"] == 1
    _drop_trigger(path, "users_refuse_delete")
    with TestClient(app) as client:
        _login(client)
        finished = client.request("DELETE", "/api/auth/account", json={"password": PASSWORD})
    assert finished.status_code == 200
    assert finished.json() == {"ok": True}
    assert _rows(path, "SELECT COUNT(*) AS n FROM users")[0]["n"] == 0
    assert _rows(path, "SELECT COUNT(*) AS n FROM assessment_snapshots")[0]["n"] == 0
    assert _rows(path, "SELECT COUNT(*) AS n FROM pending_deletions")[0]["n"] == 0
    assert _rows(path, "SELECT COUNT(*) AS n FROM investigations")[0]["n"] == 0
    assert _files(path) == []
    _assert_every_snapshot_image_exists(path)


def test_a_cleanup_row_still_retires_snapshots_before_any_unlink(tmp_path):
    path, app = _app(tmp_path)
    with TestClient(app) as client:
        _ensure_auth(client, "owner@example.com", PASSWORD)
        investigation_id = _create(client, "A cleanup row is enough to retire the snapshot.")
        _seal(client, investigation_id)
    owner_id, investigation_id = _owner_and_investigation(path)
    ledger = Ledger(Path(path))
    ledger.record_asset_cleanup(owner_id, investigation_id, "left.bin", "ab" * 32, 4, "replaced")
    assert ledger.prepare_investigation_deletion(owner_id, investigation_id)
    assert _rows(path, "SELECT COUNT(*) AS n FROM assessment_snapshots")[0]["n"] == 0
    assert _rows(path, "SELECT investigation_id FROM pending_deletions")[0]["investigation_id"] == investigation_id
    assert _rows(path, "SELECT COUNT(*) AS n FROM image_assets")[0]["n"] == 0
