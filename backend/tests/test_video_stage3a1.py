"""Stage 3.A.1 — seal-gate fail-closed + upload/seal/delete flock coordination.

Isolated temporary ledgers only. Does not enable production ingest defaults.
Does not open the live ledger. Does not start Stage 3.B+.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import threading
from pathlib import Path
from secrets import token_hex

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.ledger import Ledger, LedgerError
from app.main import create_app
from app.video_detect import VIDEO_CONSENT_VERSION, VIDEO_REMOVE_CONFIRM
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


def _owner_id(path: str, investigation_id: str) -> str:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT owner_id FROM investigations WHERE id = ?",
            (investigation_id,),
        ).fetchone()["owner_id"]
    finally:
        conn.close()


def test_flag_false_no_video_seals_normally(tmp_path):
    path = _ledger(tmp_path)
    with TestClient(
        create_app(settings=_video_settings(path, video_seal_integration=False))
    ) as client:
        _ensure_auth(client)
        inv = _create(client, "3.A.1 false no video.")
        assert client.post(f"/api/investigations/{inv}/seal").status_code == 200
    assert "sealedVideo" not in json.loads(_snapshot_rows(path)[0]["snapshot_json"])


def test_flag_false_attached_video_returns_409_disabled(tmp_path):
    path = _ledger(tmp_path)
    payload = _ffmpeg_mp4(tmp_path / "ok.mp4")
    with TestClient(
        create_app(settings=_video_settings(path, video_seal_integration=False))
    ) as client:
        _ensure_auth(client)
        inv = _create(client, "3.A.1 false with video.")
        assert client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        ).status_code == 200
        response = client.post(f"/api/investigations/{inv}/seal")
    assert response.status_code == 409
    assert response.json()["code"] == "video_seal_integration_disabled"
    assert _snapshot_rows(path) == []


def test_flag_true_ready_video_embeds_sealed_video(tmp_path):
    path = _ledger(tmp_path)
    payload = _ffmpeg_mp4(tmp_path / "ok.mp4")
    digest = hashlib.sha256(payload).hexdigest()
    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client)
        inv = _create(client, "3.A.1 true ready.")
        assert client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        ).status_code == 200
        assert client.post(f"/api/investigations/{inv}/seal").status_code == 200
    video = json.loads(_snapshot_rows(path)[0]["snapshot_json"])["sealedVideo"]
    assert video["sha256"] == digest
    assert video["schemaVersion"] == "1"


def test_flag_true_non_ready_blocks(tmp_path):
    path = _ledger(tmp_path)
    payload = _ffmpeg_mp4(tmp_path / "ok.mp4")
    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client)
        inv = _create(client, "3.A.1 non-ready.")
        assert client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        ).status_code == 200
    ledger = Ledger(Path(path))
    owner = _owner_id(path, inv)
    assert ledger.set_video_attachment_status(owner, inv, "missing", failure_code="video_bytes_missing")
    with pytest.raises(LedgerError) as raised:
        ledger.seal_assessment(
            owner, inv, token_hex(32), {"primaryClaim": "x"}, _future(), video_seal_integration=True
        )
    assert raised.value.failure_code == "video_not_ready"
    assert _snapshot_rows(path) == []


def test_flag_true_missing_and_mismatched_block(tmp_path):
    path = _ledger(tmp_path)
    payload = _ffmpeg_mp4(tmp_path / "ok.mp4")
    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client)
        inv = _create(client, "3.A.1 missing/mismatch.")
        assert client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        ).status_code == 200
    ledger = Ledger(Path(path))
    store = VideoStore.for_ledger(Path(path))
    owner = _owner_id(path, inv)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        storage_name = conn.execute("SELECT storage_name FROM video_assets").fetchone()["storage_name"]
    finally:
        conn.close()
    target = store.path_for(storage_name)
    original = target.read_bytes()
    tampered = bytes(b ^ 0xFF for b in original)
    fd = os.open(target, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
    try:
        os.write(fd, tampered)
        os.fsync(fd)
    finally:
        os.close(fd)
    with pytest.raises(LedgerError) as raised:
        ledger.seal_assessment(
            owner, inv, token_hex(32), {"primaryClaim": "tamper"}, _future(), video_seal_integration=True
        )
    assert raised.value.failure_code == "video_identity_mismatch"
    target.unlink()
    with pytest.raises(LedgerError) as raised_missing:
        ledger.seal_assessment(
            owner, inv, token_hex(32), {"primaryClaim": "missing"}, _future(), video_seal_integration=True
        )
    assert raised_missing.value.failure_code == "video_identity_mismatch"
    assert _snapshot_rows(path) == []


def test_successful_seal_never_omits_attached_video(tmp_path):
    path = _ledger(tmp_path)
    payload = _ffmpeg_mp4(tmp_path / "ok.mp4")
    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client)
        inv = _create(client, "Never omit attached.")
        assert client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        ).status_code == 200
        assert client.post(f"/api/investigations/{inv}/seal").status_code == 200
    body = json.loads(_snapshot_rows(path)[0]["snapshot_json"])
    assert isinstance(body.get("sealedVideo"), dict)
    assert body["sealedVideo"]["attachmentStatus"] == "ready"


def test_seal_holds_owner_lock_during_hash_verify(tmp_path, monkeypatch):
    """While seal hashes, a second owner-lock acquire must fail (shared with delete)."""
    path = _ledger(tmp_path)
    payload = _ffmpeg_mp4(tmp_path / "ok.mp4")
    observed: list[bool] = []
    real_verify = VideoStore.verify_path

    def gated_verify(self, path_obj, digest, byte_length):
        probe = VideoStore.for_ledger(Path(path))
        # Same owner lock used by delete/upload — must be busy during hash.
        contender = probe.try_acquire_upload_lock(_owner_id(path, inv))
        observed.append(contender is None)
        if contender is not None:
            probe.release_upload_lock(contender)
        return real_verify(self, path_obj, digest, byte_length)

    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client)
        inv = _create(client, "Lock held during hash.")
        assert client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        ).status_code == 200
        owner = _owner_id(path, inv)
        # Open ledger before patching so startup reconcile is not counted.
        ledger = Ledger(Path(path))
        monkeypatch.setattr(VideoStore, "verify_path", gated_verify)
        snapshot_id = ledger.seal_assessment(
            owner,
            inv,
            token_hex(32),
            {"primaryClaim": "hash under lock"},
            _future(),
            video_seal_integration=True,
        )
        assert snapshot_id
    assert observed == [True]


def test_delete_conflicts_when_owner_lock_already_held(tmp_path):
    """HTTP delete uses the same owner flock as seal/upload (non-blocking 409)."""
    path = _ledger(tmp_path)
    payload = _ffmpeg_mp4(tmp_path / "ok.mp4")
    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client)
        inv = _create(client, "Delete vs held lock.")
        assert client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        ).status_code == 200
        owner = _owner_id(path, inv)
        store = client.app.state.videos
        held = store.try_acquire_upload_lock(owner)
        assert held is not None
        try:
            deleted = client.delete(
                f"/api/investigations/{inv}/video",
                headers={"X-Video-Remove-Confirm": VIDEO_REMOVE_CONFIRM},
            )
            assert deleted.status_code == 409
            assert deleted.json()["code"] == "video_operation_in_progress"
            # Bytes must remain while the contending operation holds the lock.
            assert list(store.root.glob("*.bin"))
        finally:
            store.release_upload_lock(held)


def test_seal_blocked_while_delete_holds_lock(tmp_path, monkeypatch):
    path = _ledger(tmp_path)
    payload = _ffmpeg_mp4(tmp_path / "ok.mp4")
    entered = threading.Event()
    release = threading.Event()
    real_remove = VideoStore.remove_report

    def gated_remove(self, storage_name):
        entered.set()
        assert release.wait(timeout=5)
        return real_remove(self, storage_name)

    monkeypatch.setattr(VideoStore, "remove_report", gated_remove)
    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client)
        inv = _create(client, "Seal vs delete lock.")
        assert client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        ).status_code == 200
        delete_result = {}

        def run_delete():
            delete_result["response"] = client.delete(
                f"/api/investigations/{inv}/video",
                headers={"X-Video-Remove-Confirm": VIDEO_REMOVE_CONFIRM},
            )

        thread = threading.Thread(target=run_delete)
        thread.start()
        assert entered.wait(timeout=5)
        sealed = client.post(f"/api/investigations/{inv}/seal")
        assert sealed.status_code == 409
        assert sealed.json()["code"] == "video_seal_busy"
        release.set()
        thread.join(timeout=10)
        assert delete_result["response"].status_code == 200
    assert _snapshot_rows(path) == []


def test_seal_blocked_while_upload_lock_held(tmp_path):
    path = _ledger(tmp_path)
    payload = _ffmpeg_mp4(tmp_path / "ok.mp4")
    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client)
        inv = _create(client, "Seal vs upload lock.")
        assert client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        ).status_code == 200
        owner = _owner_id(path, inv)
        store = client.app.state.videos
        held = store.try_acquire_upload_lock(owner)
        assert held is not None
        try:
            response = client.post(f"/api/investigations/{inv}/seal")
            assert response.status_code == 409
            assert response.json()["code"] == "video_seal_busy"
        finally:
            store.release_upload_lock(held)
    assert _snapshot_rows(path) == []


def test_delete_lock_released_after_exception(tmp_path, monkeypatch):
    path = _ledger(tmp_path)
    payload = _ffmpeg_mp4(tmp_path / "ok.mp4")
    real_remove = VideoStore.remove_report

    def boom(self, storage_name):
        raise RuntimeError("forced-delete-failure")

    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client)
        inv = _create(client, "Delete exception releases lock.")
        assert client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        ).status_code == 200
        owner = _owner_id(path, inv)
        monkeypatch.setattr(VideoStore, "remove_report", boom)
        with pytest.raises(RuntimeError):
            client.delete(
                f"/api/investigations/{inv}/video",
                headers={"X-Video-Remove-Confirm": VIDEO_REMOVE_CONFIRM},
            )
        monkeypatch.setattr(VideoStore, "remove_report", real_remove)
        # Lock must be free for a subsequent owner operation.
        store = client.app.state.videos
        recovered = store.try_acquire_upload_lock(owner)
        assert recovered is not None
        store.release_upload_lock(recovered)


def test_process_termination_releases_owner_lock(tmp_path):
    """fcntl flock is released when the holding process exits without unlock."""
    root = tmp_path / "assets" / "video"
    store = VideoStore(root)
    owner = "owner-terminate"
    marker = tmp_path / "held.marker"

    def child():
        local = VideoStore(root)
        handle = local.try_acquire_upload_lock(owner)
        if handle is None:
            os._exit(2)
        marker.write_text("held", encoding="utf-8")
        os._exit(0)

    import multiprocessing

    proc = multiprocessing.Process(target=child)
    proc.start()
    proc.join(timeout=10)
    assert proc.exitcode == 0
    assert marker.exists()
    recovered = store.try_acquire_upload_lock(owner)
    assert recovered is not None
    store.release_upload_lock(recovered)


def test_erasure_unlink_failure_still_fail_closed(tmp_path, monkeypatch):
    path = _ledger(tmp_path)
    payload = _ffmpeg_mp4(tmp_path / "ok.mp4")
    password = "correct-horse-battery"
    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client, "erase-3a1@example.com", password)
        inv = _create(client, "Erasure fail-closed.")
        assert client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        ).status_code == 200
        store = VideoStore.for_ledger(Path(path))
        assert list(store.root.glob("*.bin"))

        def fail_remove(self, storage_name):
            return "failed"

        real_remove = VideoStore.remove_report
        monkeypatch.setattr(VideoStore, "remove_report", fail_remove)
        erased = client.request("DELETE", "/api/auth/account", json={"password": password})
        assert erased.status_code == 500
        assert erased.json()["code"] == "asset_cleanup_failed"
        assert erased.json().get("accountDeleted") is False
        assert list(store.root.glob("*.bin"))
        monkeypatch.setattr(VideoStore, "remove_report", real_remove)


def test_upload_blocked_while_delete_holds_lock(tmp_path, monkeypatch):
    path = _ledger(tmp_path)
    payload = _ffmpeg_mp4(tmp_path / "ok.mp4")
    entered = threading.Event()
    release = threading.Event()
    real_remove = VideoStore.remove_report

    def gated_remove(self, storage_name):
        entered.set()
        assert release.wait(timeout=5)
        return real_remove(self, storage_name)

    monkeypatch.setattr(VideoStore, "remove_report", gated_remove)
    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client)
        inv = _create(client, "Upload vs delete lock.")
        assert client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        ).status_code == 200
        delete_result = {}

        def run_delete():
            delete_result["response"] = client.delete(
                f"/api/investigations/{inv}/video",
                headers={"X-Video-Remove-Confirm": VIDEO_REMOVE_CONFIRM},
            )

        thread = threading.Thread(target=run_delete)
        thread.start()
        assert entered.wait(timeout=5)
        # Concurrent upload for same owner must conflict on the shared lock.
        other = _create(client, "Second investigation upload.")
        conflict = client.post(
            f"/api/investigations/{other}/video",
            content=payload,
            headers=_video_headers(client),
        )
        assert conflict.status_code == 409
        assert conflict.json()["code"] == "video_upload_in_progress"
        release.set()
        thread.join(timeout=10)
        assert delete_result["response"].status_code == 200
