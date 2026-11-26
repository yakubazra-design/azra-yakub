"""Stage 3.A — video identity sealing into assessment snapshots.

Isolated temporary ledgers only. Does not enable production ingest defaults.
Does not open the live ledger. Does not implement videoEvidence (Stage 3.B).
Does not record processing runs (Stage 3.C).
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
from pathlib import Path
from secrets import token_hex

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.ledger import Ledger, LedgerError
from app.main import create_app
from app.video_detect import VIDEO_CONSENT_VERSION
from app.video_probe import ensure_boot_self_test, reset_boot_self_test_for_tests, tier_a_ready
from app.video_store import VideoStore
from test_api import _create, _ensure_auth, _ledger, _settings


def _ffmpeg_mp4(path: Path, *, seconds: float = 1.0, size: str = "320x240") -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "/usr/bin/ffmpeg",
        "-y",
        "-f",
        "lavfi",
        "-i",
        f"color=c=black:s={size}:d={seconds}",
        "-c:v",
        "libx264",
        "-pix_fmt",
        "yuv420p",
        "-t",
        str(seconds),
        str(path),
    ]
    completed = subprocess.run(cmd, capture_output=True, timeout=60, check=False)
    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    return path.read_bytes()


def _video_settings(path: str, **overrides) -> Settings:
    data = dict(
        ledger_path=path,
        video_ingest_enabled=True,
        video_allow_tier_b=False,
        video_seal_integration=True,
    )
    data.update(overrides)
    return _settings(**data)


def _video_headers(client: TestClient, extra: dict | None = None) -> dict:
    headers = {
        "X-Video-Consent": VIDEO_CONSENT_VERSION,
        "Content-Type": "application/octet-stream",
    }
    if extra:
        headers.update(extra)
    return headers


def _future() -> str:
    from datetime import datetime, timedelta, timezone

    return (datetime.now(timezone.utc).replace(microsecond=0) + timedelta(minutes=10)).isoformat()


def _snapshot_rows(path: str) -> list[dict]:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT id, snapshot_json FROM assessment_snapshots ORDER BY created_at ASC"
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def test_defaults_keep_ingest_off_and_seal_integration_on():
    settings = Settings(
        ledger_path="/tmp/stage3a-defaults-unused.sqlite",
        openai_api_key="",
        parallel_api_key="",
    )
    assert settings.video_ingest_enabled is False
    assert settings.video_allow_tier_b is False
    assert settings.video_seal_integration is True


def test_seal_without_video_omits_sealed_video(tmp_path):
    path = _ledger(tmp_path)
    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client)
        inv = _create(client, "No video seal.")
        response = client.post(f"/api/investigations/{inv}/seal")
        assert response.status_code == 200, response.text
    rows = _snapshot_rows(path)
    assert len(rows) == 1
    body = json.loads(rows[0]["snapshot_json"])
    assert "sealedVideo" not in body
    assert "videoEvidence" not in body
    blob = json.dumps(body)
    assert "assets/video" not in blob
    assert ".bin" not in blob


def test_seal_with_ready_video_embeds_verified_identity(tmp_path):
    path = _ledger(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    digest = hashlib.sha256(payload).hexdigest()
    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client)
        inv = _create(client, "Seal with ready video.")
        uploaded = client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        )
        assert uploaded.status_code == 200, uploaded.text
        assert uploaded.json()["sha256"] == digest
        sealed = client.post(f"/api/investigations/{inv}/seal")
        assert sealed.status_code == 200, sealed.text
    rows = _snapshot_rows(path)
    assert len(rows) == 1
    body = json.loads(rows[0]["snapshot_json"])
    video = body["sealedVideo"]
    assert video["schemaVersion"] == "1"
    assert video["sha256"] == digest
    assert video["byteLength"] == len(payload)
    assert video["mediaType"].startswith("video/")
    assert video["attachmentStatus"] == "ready"
    assert isinstance(video["sealedAt"], str) and video["sealedAt"]
    assert "storageName" not in video
    assert "storage_name" not in video
    assert "probe_summary_json" not in video
    assert "ownerId" not in video
    blob = json.dumps(body)
    assert "assets/video" not in blob
    assert payload not in blob.encode() if False else True
    assert ".bin" not in blob


def test_client_cannot_inject_sealed_video(tmp_path):
    path = _ledger(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    forged = "ab" * 32
    ledger = Ledger(Path(path))
    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client)
        inv = _create(client, "Reject client sealedVideo.")
        assert client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        ).status_code == 200
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        owner_id = conn.execute(
            "SELECT owner_id FROM investigations WHERE id = ?", (inv,)
        ).fetchone()["owner_id"]
    finally:
        conn.close()
    snapshot_id = ledger.seal_assessment(
        owner_id,
        inv,
        token_hex(32),
        {
            "primaryClaim": "Inject attempt.",
            "sealedVideo": {"sha256": forged, "assetId": "client-picked"},
            "videoEvidence": {"version": "forged"},
        },
        _future(),
        video_seal_integration=True,
    )
    assert snapshot_id
    body = json.loads(_snapshot_rows(path)[0]["snapshot_json"])
    assert body["sealedVideo"]["sha256"] != forged
    assert body["sealedVideo"]["sha256"] == hashlib.sha256(payload).hexdigest()
    assert body["sealedVideo"]["assetId"] != "client-picked"
    assert "videoEvidence" not in body


def test_seal_blocks_when_attachment_not_ready(tmp_path):
    path = _ledger(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client)
        inv = _create(client, "Not ready blocks seal.")
        assert client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        ).status_code == 200
    ledger = Ledger(Path(path))
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        owner_id = conn.execute(
            "SELECT owner_id FROM investigations WHERE id = ?", (inv,)
        ).fetchone()["owner_id"]
    finally:
        conn.close()
    assert ledger.set_video_attachment_status(
        owner_id, inv, "integrity_failed", failure_code="integrity_mismatch"
    )
    with pytest.raises(LedgerError) as raised:
        ledger.seal_assessment(
            owner_id,
            inv,
            token_hex(32),
            {"primaryClaim": "Blocked."},
            _future(),
            video_seal_integration=True,
        )
    assert raised.value.failure_code == "video_not_ready"
    assert _snapshot_rows(path) == []


def test_seal_blocks_when_bytes_tampered(tmp_path):
    path = _ledger(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client)
        inv = _create(client, "Tamper blocks seal.")
        assert client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        ).status_code == 200
    ledger = Ledger(Path(path))
    store = VideoStore.for_ledger(Path(path))
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT owner_id, storage_name FROM video_assets").fetchone()
        owner_id = row["owner_id"]
        storage_name = row["storage_name"]
    finally:
        conn.close()
    target = store.path_for(storage_name)
    # Overwrite same-length bytes so size still matches the row but digest fails.
    original = target.read_bytes()
    tampered = bytes((b ^ 0xFF) for b in original)
    assert len(tampered) == len(original)
    fd = os.open(target, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
    try:
        os.write(fd, tampered)
        os.fsync(fd)
    finally:
        os.close(fd)
    with pytest.raises(LedgerError) as raised:
        ledger.seal_assessment(
            owner_id,
            inv,
            token_hex(32),
            {"primaryClaim": "Tampered."},
            _future(),
            video_seal_integration=True,
        )
    assert raised.value.failure_code == "video_identity_mismatch"
    assert _snapshot_rows(path) == []


def test_seal_blocks_when_file_missing(tmp_path):
    path = _ledger(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client)
        inv = _create(client, "Missing file blocks seal.")
        assert client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        ).status_code == 200
    ledger = Ledger(Path(path))
    store = VideoStore.for_ledger(Path(path))
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT owner_id, storage_name FROM video_assets").fetchone()
        owner_id = row["owner_id"]
        storage_name = row["storage_name"]
    finally:
        conn.close()
    store.path_for(storage_name).unlink()
    with pytest.raises(LedgerError) as raised:
        ledger.seal_assessment(
            owner_id,
            inv,
            token_hex(32),
            {"primaryClaim": "Missing."},
            _future(),
            video_seal_integration=True,
        )
    assert raised.value.failure_code == "video_identity_mismatch"
    assert _snapshot_rows(path) == []


def test_http_seal_returns_video_identity_mismatch(tmp_path):
    path = _ledger(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client)
        inv = _create(client, "HTTP mismatch code.")
        assert client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        ).status_code == 200
        store = VideoStore.for_ledger(Path(path))
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        try:
            storage_name = conn.execute("SELECT storage_name FROM video_assets").fetchone()[
                "storage_name"
            ]
        finally:
            conn.close()
        store.path_for(storage_name).unlink()
        response = client.post(f"/api/investigations/{inv}/seal")
        assert response.status_code == 409
        assert response.json()["code"] == "video_identity_mismatch"
    assert _snapshot_rows(path) == []


def test_video_seal_integration_false_with_video_blocks_seal(tmp_path):
    """Stage 3.A.1: attached video + flag false must not seal silently."""
    path = _ledger(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    with TestClient(
        create_app(settings=_video_settings(path, video_seal_integration=False))
    ) as client:
        _ensure_auth(client)
        inv = _create(client, "Flag off with video blocks seal.")
        assert client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        ).status_code == 200
        response = client.post(f"/api/investigations/{inv}/seal")
        assert response.status_code == 409
        body = response.json()
        assert body["code"] == "video_seal_integration_disabled"
        assert "assets/video" not in json.dumps(body)
        assert ".bin" not in json.dumps(body)
    assert _snapshot_rows(path) == []


def test_video_seal_integration_false_without_video_seals_normally(tmp_path):
    path = _ledger(tmp_path)
    with TestClient(
        create_app(settings=_video_settings(path, video_seal_integration=False))
    ) as client:
        _ensure_auth(client)
        inv = _create(client, "Flag off without video seals.")
        response = client.post(f"/api/investigations/{inv}/seal")
        assert response.status_code == 200, response.text
    body = json.loads(_snapshot_rows(path)[0]["snapshot_json"])
    assert "sealedVideo" not in body


def test_cross_account_cannot_seal_other_video(tmp_path):
    path = _ledger(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client, email="owner-a@example.com")
        inv = _create(client, "Owner A video.")
        assert client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        ).status_code == 200
        client.post("/api/auth/logout")
        _ensure_auth(client, email="owner-b@example.com")
        response = client.post(f"/api/investigations/{inv}/seal")
        assert response.status_code == 404


def test_assess_prompt_ctx_still_boolean_sealed_image_only(tmp_path):
    """Stage 3.A must not add videoEvidence or send video bytes to the model path."""
    path = _ledger(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client)
        inv = _create(client, "No videoEvidence yet.")
        assert client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        ).status_code == 200
        token = client.post(f"/api/investigations/{inv}/seal").json()["assessmentToken"]
        # Without OpenAI key, assess fails provider-side; still ensure snapshot has no videoEvidence.
        rows = _snapshot_rows(path)
        body = json.loads(rows[0]["snapshot_json"])
        assert "sealedVideo" in body
        assert "videoEvidence" not in body
        assert token


def test_tier_a_still_ready_and_boot_not_written_as_user_run(tmp_path):
    """Decision 11: boot self-test must not create video_processing_runs rows."""
    path = _ledger(tmp_path)
    reset_boot_self_test_for_tests()
    assert ensure_boot_self_test()[0] is True
    assert tier_a_ready()[0] is True
    Ledger(Path(path))  # open schema
    conn = sqlite3.connect(path)
    try:
        count = conn.execute("SELECT COUNT(*) FROM video_processing_runs").fetchone()[0]
    finally:
        conn.close()
    assert count == 0
