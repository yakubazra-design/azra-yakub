"""Stage 2 V1.2.A — Tier A FFprobe sandbox + video upload APIs.

Isolated temporary ledgers only. Does not enable VIDEO_INGEST_ENABLED by
default. Does not open the live ledger. Does not send media to providers.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import threading
import time
from pathlib import Path
from secrets import token_hex

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.ledger import Ledger
from app.limits import MAX_IMAGE_BYTES, MAX_VIDEO_BYTES
from app.main import create_app
from app.video_detect import VIDEO_CONSENT_VERSION, VIDEO_REMOVE_CONFIRM
from app.video_probe import (
    ensure_boot_self_test,
    probe_video_file,
    reset_boot_self_test_for_tests,
    tier_a_ready,
)
from app.video_store import VideoStore, purge_video_quarantine, reconcile_video_assets
from test_api import _create, _ensure_auth, _ledger, _seal, _settings


def _ffmpeg_mp4(path: Path, *, seconds: float = 1.0, size: str = "320x240", codec: str = "libx264") -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "/usr/bin/ffmpeg",
        "-y",
        "-f",
        "lavfi",
        "-i",
        f"color=c=black:s={size}:d={seconds}",
        "-c:v",
        codec,
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


def test_image_limit_unchanged_and_video_cap_exact():
    assert MAX_IMAGE_BYTES == 8_388_608
    assert MAX_VIDEO_BYTES == 104_857_600


def test_tier_a_boot_self_test_passes_on_this_host():
    reset_boot_self_test_for_tests()
    ok, code = ensure_boot_self_test()
    assert ok is True
    assert code == "ok"
    ready, ready_code = tier_a_ready()
    assert ready is True
    assert ready_code == "tier_a"


def test_tier_a_refuses_url_like_paths(tmp_path):
    reset_boot_self_test_for_tests()
    ensure_boot_self_test()
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    with pytest.raises(Exception) as raised:
        probe_video_file(
            Path("https://example.com/video.mp4"),
            scratch_parent=scratch,
            skip_boot_check=True,
        )
    assert raised.value.code == "video_probe_failed"


def test_tier_a_canary_and_network_denied_via_self_test():
    """Self-test already asserts canary unreadability and net unshare."""
    reset_boot_self_test_for_tests()
    ok, code = ensure_boot_self_test()
    assert ok and code == "ok"


def test_flag_off_reports_unavailable_even_when_bwrap_works(tmp_path):
    path = _ledger(tmp_path)
    reset_boot_self_test_for_tests()
    assert tier_a_ready()[0] is True
    with TestClient(create_app(settings=_settings(ledger_path=path))) as client:
        body = client.get("/api/health").json()
        assert body["videoIngestEnabled"] is False
        assert body["videoIngestAvailable"] is False
        _ensure_auth(client)
        inv = _create(client, "Flag-off video routes.")
        response = client.post(
            f"/api/investigations/{inv}/video",
            content=b"not-a-video",
            headers=_video_headers(client),
        )
        assert response.status_code == 503
        assert response.json()["code"] == "video_ingest_disabled"
        assert client.get(f"/api/investigations/{inv}/video").status_code == 503
        assert client.delete(
            f"/api/investigations/{inv}/video",
            headers={"X-Video-Remove-Confirm": VIDEO_REMOVE_CONFIRM},
        ).status_code == 503


def test_upload_get_delete_happy_path(tmp_path):
    path = _ledger(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    digest = hashlib.sha256(payload).hexdigest()
    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client)
        inv = _create(client, "Happy-path video upload.")
        posted = client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client, {"X-Client-Sha256": digest}),
        )
        assert posted.status_code == 200, posted.text
        body = posted.json()
        assert body["sha256"] == digest
        assert body["byteLength"] == len(payload)
        assert body["mediaType"] == "video/mp4"
        assert body["videoCodec"] == "h264"
        assert body["attachmentStatus"] == "ready"
        assert "storageName" not in body
        assert "probe_summary" not in body
        assert "/" not in str(body.get("formatName", ""))
        text = posted.text.lower()
        assert "bwrap" not in text
        assert "scratch" not in text
        assert str(tmp_path).lower() not in text

        got = client.get(f"/api/investigations/{inv}/video")
        assert got.status_code == 200
        assert got.json()["videoAssetId"] == body["videoAssetId"]
        assert "storageName" not in got.json()

        removed = client.delete(
            f"/api/investigations/{inv}/video",
            headers={"X-Video-Remove-Confirm": VIDEO_REMOVE_CONFIRM},
        )
        assert removed.status_code == 200, removed.text
        assert removed.json()["removed"] is True
        assert client.get(f"/api/investigations/{inv}/video").status_code == 404


def test_consent_csrf_and_auth_gates(tmp_path):
    path = _ledger(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    with TestClient(create_app(settings=_video_settings(path))) as client:
        # Unauthenticated
        response = client.post(
            "/api/investigations/deadbeefdeadbeefdeadbeefdeadbeef/video",
            content=payload,
            headers=_video_headers(client),
        )
        assert response.status_code in {401, 404}

        _ensure_auth(client)
        inv = _create(client, "Consent and CSRF gates.")
        missing_consent = client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers={"Content-Type": "application/octet-stream"},
        )
        assert missing_consent.status_code == 400
        assert missing_consent.json()["code"] == "consent_required"

        bad_meta = client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client, {"X-Video-Metadata-Consent": "nope"}),
        )
        assert bad_meta.status_code == 400
        assert bad_meta.json()["code"] == "metadata_consent_invalid"

        # CSRF: clear token
        client.headers.pop("X-CSRF-Token", None)
        csrf = client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        )
        assert csrf.status_code == 403
        assert csrf.json()["code"] == "csrf_failed"


def test_rejects_non_video_bytes(tmp_path):
    path = _ledger(tmp_path)
    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client)
        inv = _create(client, "Reject garbage.")
        response = client.post(
            f"/api/investigations/{inv}/video",
            content=b"\x89PNG\r\n\x1a\n" + b"\x00" * 200,
            headers=_video_headers(client),
        )
        assert response.status_code == 400
        assert response.json()["code"] == "invalid_video"


def test_delete_requires_confirmation_and_blocks_after_seal(tmp_path):
    path = _ledger(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client)
        inv = _create(client, "Delete confirmation and seal.")
        assert client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        ).status_code == 200
        missing = client.delete(f"/api/investigations/{inv}/video")
        assert missing.status_code == 400
        assert missing.json()["code"] == "removal_confirmation_required"

        _seal(client, inv)
        sealed = client.delete(
            f"/api/investigations/{inv}/video",
            headers={"X-Video-Remove-Confirm": VIDEO_REMOVE_CONFIRM},
        )
        assert sealed.status_code == 409
        assert sealed.json()["code"] == "video_after_seal"
        # Upload after seal also blocked
        after = client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        )
        assert after.status_code == 409
        assert after.json()["code"] == "video_after_seal"


def test_get_does_not_expose_paths_or_raw_probe(tmp_path):
    path = _ledger(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client)
        inv = _create(client, "Safe GET metadata.")
        client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        )
        body = client.get(f"/api/investigations/{inv}/video").json()
    forbidden = {
        "storageName",
        "probe_summary",
        "probeSummary",
        "probe_summary_json",
        "path",
        "filesystemPath",
        "downloadUrl",
        "url",
    }
    assert forbidden.isdisjoint(body.keys())
    blob = json.dumps(body).lower()
    assert "assets/video" not in blob
    assert ".bin" not in blob
    assert "bwrap" not in blob


def test_reconcile_partial_intent_orphan_and_cleanup_retry(tmp_path):
    path = _ledger(tmp_path)
    ledger = Ledger(Path(path))
    store = VideoStore.for_ledger(Path(path))

    # Stale partial
    partial = store.open_partial(token_hex(8))
    store.append_partial(partial, b"partial-bytes")
    assert partial.is_file()

    # Incomplete intent without DB row: promote then leave intent
    upload = store.open_partial(token_hex(8))
    payload = b"\x00" * 64 + b"intent-orphan"
    store.append_partial(upload, payload)
    digest = hashlib.sha256(payload).hexdigest()
    asset_id = token_hex(16)
    storage_name = store.promote_partial(
        upload,
        asset_id,
        owner_id="owner",
        investigation_id="inv",
        digest=digest,
        byte_length=len(payload),
    )
    assert (store.root / ".intent" / storage_name).is_file()

    summary = reconcile_video_assets(store.root, referenced=set())
    assert summary["partials_removed"] >= 1
    assert not partial.exists()
    assert summary["intents_orphans_removed"] >= 1
    assert not store.exists(storage_name)

    # Orphan published file → quarantine
    orphan_id = token_hex(16)
    orphan_name = orphan_id + ".bin"
    orphan_path = store.root / orphan_name
    orphan_path.write_bytes(b"orphan")
    os.chmod(orphan_path, 0o600)
    summary2 = reconcile_video_assets(store.root, referenced=set())
    assert summary2["quarantined"] == 1
    assert (store.root / ".quarantine" / orphan_name).is_file()

    # Failed cleanup retry: cleanup row + file → remove and clear row
    with TestClient(create_app(settings=_settings(ledger_path=path))) as client:
        _ensure_auth(client)
        inv = _create(client, "Cleanup retry.")
    import sqlite3

    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    owner_id = conn.execute("SELECT id FROM users LIMIT 1").fetchone()["id"]
    cleanup_name = token_hex(16) + ".bin"
    (store.root / cleanup_name).write_bytes(b"cleanup-me")
    conn.execute(
        """
        INSERT INTO video_asset_cleanup (
            storage_name, owner_id, investigation_id, sha256, byte_length, reason, created_at
        ) VALUES (?, ?, ?, ?, ?, 'user_removed', ?)
        """,
        (cleanup_name, owner_id, inv, hashlib.sha256(b"cleanup-me").hexdigest(), 10, "2020-01-01T00:00:00+00:00"),
    )
    conn.commit()
    conn.close()
    ledger._reconcile_video_assets()
    assert not (store.root / cleanup_name).exists()
    conn = sqlite3.connect(path)
    left = conn.execute(
        "SELECT 1 FROM video_asset_cleanup WHERE storage_name = ?",
        (cleanup_name,),
    ).fetchone()
    conn.close()
    assert left is None


def test_missing_file_never_silently_absent(tmp_path):
    path = _ledger(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    import sqlite3

    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client)
        inv = _create(client, "Missing file stays visible.")
        posted = client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        )
        assert posted.status_code == 200
        storage = Path(path).parent / "assets" / "video"
        bins = list(storage.glob("*.bin"))
        assert len(bins) == 1
        bins[0].unlink()

    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    owner = conn.execute(
        "SELECT owner_id FROM investigations WHERE id = ?",
        (inv,),
    ).fetchone()["owner_id"]
    conn.close()
    ledger = Ledger(Path(path))
    ledger._reconcile_video_assets()
    row = ledger.video_asset(owner, inv)
    assert row is not None
    assert row["attachmentStatus"] == "missing"
    assert row["failureCode"] == "video_bytes_missing"


def test_hash_mismatch_marked_integrity_failed(tmp_path):
    path = _ledger(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    import sqlite3

    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client)
        inv = _create(client, "Integrity mismatch.")
        assert client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        ).status_code == 200
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    owner = conn.execute(
        "SELECT owner_id FROM investigations WHERE id = ?",
        (inv,),
    ).fetchone()["owner_id"]
    conn.close()
    store = VideoStore.for_ledger(Path(path))
    bins = list(store.root.glob("*.bin"))
    assert len(bins) == 1
    bins[0].write_bytes(payload + b"tampered")
    ledger = Ledger(Path(path))
    ledger._reconcile_video_assets()
    row = ledger.video_asset(owner, inv)
    assert row is not None
    assert row["attachmentStatus"] == "integrity_failed"
    assert row["failureCode"] == "integrity_mismatch"


def test_concurrent_upload_returns_conflict(tmp_path):
    path = _ledger(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    app = create_app(settings=_video_settings(path))
    with TestClient(app) as client:
        _ensure_auth(client)
        inv = _create(client, "Concurrent upload.")
        import sqlite3

        conn = sqlite3.connect(path)
        owner_id = conn.execute("SELECT id FROM users LIMIT 1").fetchone()[0]
        conn.close()
        held = app.state.videos.try_acquire_upload_lock(owner_id)
        assert held is not None
        try:
            response = client.post(
                f"/api/investigations/{inv}/video",
                content=payload,
                headers=_video_headers(client),
            )
            assert response.status_code == 409
            assert response.json()["code"] == "video_upload_in_progress"
        finally:
            app.state.videos.release_upload_lock(held)


def test_quarantine_purge_expires_old_files(tmp_path):
    root = tmp_path / "assets" / "video"
    store = VideoStore(root)
    q = root / ".quarantine"
    old = q / (token_hex(16) + ".bin")
    old.write_bytes(b"old")
    os.utime(old, (time.time() - 40 * 24 * 3600, time.time() - 40 * 24 * 3600))
    summary = purge_video_quarantine(root)
    assert summary["expired"] == 1
    assert not old.exists()


def test_request_size_middleware_keeps_image_limit(tmp_path):
    """Video path does not raise the JSON/image body caps."""
    path = _ledger(tmp_path)
    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client)
        inv = _create(client, "Image limit still 8 MiB.")
        # Oversized image still rejected at image limit (not video limit).
        huge = b"\x89PNG\r\n\x1a\n" + b"\x00" * (MAX_IMAGE_BYTES + 100)
        response = client.post(
            f"/api/investigations/{inv}/asset",
            content=huge,
            headers={
                "X-Image-Consent": "image-upload-1",
                "Content-Type": "application/octet-stream",
            },
        )
        assert response.status_code == 413
