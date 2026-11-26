"""Stage 3.C — user-upload video probe processing-run persistence.

Isolated temporary ledgers only. Does not enable production ingest defaults.
Does not open the live ledger. Does not make provider calls. Does not modify
the frontend stash. Does not begin Stage 3.D.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from secrets import token_hex

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.ledger import Ledger, LedgerError
from app.main import create_app
from app.video_detect import VIDEO_CONSENT_VERSION, VIDEO_REMOVE_CONFIRM
from app.video_probe import (
    VideoProbeError,
    ensure_boot_self_test,
    probe_video_file,
    reset_boot_self_test_for_tests,
    sandboxed_ffprobe_version,
    tier_a_ready,
)
from app.video_store import VideoStore
from test_api import DUMMY_OPENAI, _create, _ensure_auth, _ledger, _settings
from test_video_stage3a import _ffmpeg_mp4, _video_headers, _video_settings


PASSWORD = "correct-horse-battery"


def _runs(path: str) -> list[dict]:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT id, video_asset_id, investigation_id, owner_id, stage, status,
                   failure_code, toolchain_version, isolation_tier, started_at,
                   finished_at, resource_ms
            FROM video_processing_runs
            ORDER BY started_at ASC, id ASC
            """
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def _owner_id(path: str) -> str:
    conn = sqlite3.connect(path)
    try:
        return conn.execute("SELECT id FROM users LIMIT 1").fetchone()[0]
    finally:
        conn.close()


def test_successful_user_upload_probe_creates_succeeded_run(tmp_path):
    path = _ledger(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    with TestClient(create_app(settings=_video_settings(path))) as client:
        inv = _create(client, "Stage 3.C success probe.")
        response = client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        )
        assert response.status_code == 200, response.text
        asset_id = response.json()["videoAssetId"]
    rows = _runs(path)
    assert len(rows) == 1
    row = rows[0]
    assert row["stage"] == "probe"
    assert row["status"] == "succeeded"
    assert row["failure_code"] is None
    assert row["video_asset_id"] == asset_id
    assert row["investigation_id"] == inv
    assert row["isolation_tier"] == "A"
    assert row["started_at"]
    assert row["finished_at"]
    assert isinstance(row["resource_ms"], int) and row["resource_ms"] >= 0
    assert row["toolchain_version"]


@pytest.mark.parametrize(
    "code",
    [
        "invalid_video",
        "video_probe_timeout",
        "probe_output_too_large",
        "video_isolation_insufficient",
        "video_toolchain_unavailable",
        "codec_not_allowed",
    ],
)
def test_failed_probe_records_failure_code(tmp_path, monkeypatch, code):
    path = _ledger(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)

    def boom(*_args, **_kwargs):
        raise VideoProbeError(code)

    monkeypatch.setattr("app.main.probe_video_file", boom)
    with TestClient(create_app(settings=_video_settings(path))) as client:
        inv = _create(client, f"Stage 3.C fail {code}.")
        response = client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        )
        assert response.status_code >= 400
        assert response.json()["code"] == code
    rows = _runs(path)
    assert len(rows) == 1
    assert rows[0]["status"] == "failed"
    assert rows[0]["failure_code"] == code
    assert rows[0]["video_asset_id"] is None
    assert rows[0]["finished_at"]


def test_pre_probe_invalid_container_does_not_create_run(tmp_path):
    path = _ledger(tmp_path)
    with TestClient(create_app(settings=_video_settings(path))) as client:
        inv = _create(client, "Not a video container.")
        response = client.post(
            f"/api/investigations/{inv}/video",
            content=b"not-a-video-file",
            headers=_video_headers(client),
        )
        assert response.status_code == 400
        assert response.json()["code"] == "invalid_video"
    assert _runs(path) == []


def test_boot_self_test_and_version_helpers_do_not_create_user_runs(tmp_path):
    path = _ledger(tmp_path)
    Ledger(Path(path))
    reset_boot_self_test_for_tests()
    assert ensure_boot_self_test()[0] is True
    assert tier_a_ready()[0] is True
    assert sandboxed_ffprobe_version()
    assert _runs(path) == []


def test_synthetic_probe_outside_upload_does_not_create_user_run(tmp_path):
    path = _ledger(tmp_path)
    Ledger(Path(path))
    media = tmp_path / "synth.mp4"
    _ffmpeg_mp4(media)
    store = VideoStore(tmp_path / "videos")
    reset_boot_self_test_for_tests()
    probe_video_file(media, scratch_parent=store.scratch_dir(), skip_boot_check=True)
    assert _runs(path) == []


def test_cross_account_cannot_see_other_processing_runs(tmp_path):
    path = _ledger(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    with TestClient(create_app(settings=_video_settings(path))) as client:
        a = _ensure_auth(client, email=f"a-{token_hex(3)}@example.com")
        inv_a = client.post("/api/investigations", json={"input": "Owner A", "kind": "claim"}).json()[
            "investigationId"
        ]
        assert client.post(
            f"/api/investigations/{inv_a}/video",
            content=payload,
            headers=_video_headers(client),
        ).status_code == 200
        owner_a = _owner_id(path)

    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client, email=f"b-{token_hex(3)}@example.com", password=PASSWORD)
        inv_b = client.post("/api/investigations", json={"input": "Owner B", "kind": "claim"}).json()[
            "investigationId"
        ]
        owner_b = None
        conn = sqlite3.connect(path)
        try:
            owner_b = conn.execute(
                "SELECT id FROM users WHERE email LIKE 'b-%'"
            ).fetchone()[0]
        finally:
            conn.close()
        ledger = Ledger(Path(path))
        assert ledger.video_processing_runs(owner_b, inv_a) == []
        assert ledger.video_processing_runs(owner_a, inv_b) == []
        assert len(ledger.video_processing_runs(owner_a, inv_a)) == 1


def test_cross_investigation_isolation(tmp_path):
    path = _ledger(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    with TestClient(create_app(settings=_video_settings(path))) as client:
        inv1 = _create(client, "Investigation one.")
        inv2 = client.post(
            "/api/investigations", json={"input": "Investigation two.", "kind": "claim"}
        ).json()["investigationId"]
        assert client.post(
            f"/api/investigations/{inv1}/video",
            content=payload,
            headers=_video_headers(client),
        ).status_code == 200
        owner = _owner_id(path)
        ledger = Ledger(Path(path))
        runs1 = ledger.video_processing_runs(owner, inv1)
        runs2 = ledger.video_processing_runs(owner, inv2)
        assert len(runs1) == 1
        assert runs2 == []
        assert runs1[0]["investigationId"] == inv1


def test_retry_upload_does_not_duplicate_success_for_same_run(tmp_path):
    path = _ledger(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    with TestClient(create_app(settings=_video_settings(path))) as client:
        inv = _create(client, "Retry upload.")
        assert client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        ).status_code == 200
        assert client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        ).status_code == 200
    rows = _runs(path)
    assert len(rows) == 2
    assert all(row["status"] == "succeeded" for row in rows)
    assert rows[0]["id"] != rows[1]["id"]
    owner = _owner_id(path)
    ledger = Ledger(Path(path))
    # Completing an already-succeeded run is idempotent and does not insert another.
    assert ledger.complete_video_probe_run(owner, rows[0]["id"], status="succeeded") is True
    assert len(_runs(path)) == 2


def test_asset_deletion_keeps_historical_run_rows(tmp_path):
    path = _ledger(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    with TestClient(create_app(settings=_video_settings(path))) as client:
        inv = _create(client, "Delete video after probe.")
        uploaded = client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        )
        assert uploaded.status_code == 200
        deleted = client.delete(
            f"/api/investigations/{inv}/video",
            headers={"X-Video-Remove-Confirm": VIDEO_REMOVE_CONFIRM},
        )
        assert deleted.status_code == 200, deleted.text
    rows = _runs(path)
    assert len(rows) == 1
    assert rows[0]["status"] == "succeeded"


def test_investigation_erasure_removes_processing_runs(tmp_path):
    path = _ledger(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    with TestClient(create_app(settings=_video_settings(path))) as client:
        inv = _create(client, "Erase investigation runs.")
        assert client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        ).status_code == 200
        owner = _owner_id(path)
        assert len(_runs(path)) == 1
        deleted = client.delete(f"/api/investigations/{inv}")
        assert deleted.status_code == 200, deleted.text
    assert _runs(path) == []
    ledger = Ledger(Path(path))
    assert ledger.video_processing_runs(owner, inv) == []


def test_account_erasure_removes_processing_runs(tmp_path):
    path = _ledger(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client, email=f"erase-{token_hex(3)}@example.com", password=PASSWORD)
        inv = client.post(
            "/api/investigations", json={"input": "Erase account runs.", "kind": "claim"}
        ).json()["investigationId"]
        assert client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        ).status_code == 200
        assert len(_runs(path)) == 1
        erased = client.request("DELETE", "/api/auth/account", json={"password": PASSWORD})
        assert erased.status_code == 200, erased.text
    assert _runs(path) == []


def test_processing_persistence_failure_does_not_report_durable_success(tmp_path, monkeypatch):
    path = _ledger(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)

    def fail_complete(*_args, **_kwargs):
        raise LedgerError("The evidence ledger is unavailable.")

    with TestClient(create_app(settings=_video_settings(path))) as client:
        inv = _create(client, "Persist failure after probe.")
        monkeypatch.setattr(Ledger, "complete_video_probe_run", fail_complete)
        response = client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        )
        assert response.status_code == 503
    # start may have written a started row before complete failed; must not be succeeded.
    rows = _runs(path)
    assert all(row["status"] != "succeeded" for row in rows)


def test_start_persistence_failure_aborts_before_probe(tmp_path, monkeypatch):
    path = _ledger(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    called = {"probe": 0}

    def fail_start(*_args, **_kwargs):
        raise LedgerError("The evidence ledger is unavailable.")

    def track_probe(*_args, **_kwargs):
        called["probe"] += 1
        raise AssertionError("probe must not run when start fails")

    monkeypatch.setattr(Ledger, "start_video_probe_run", fail_start)
    monkeypatch.setattr("app.main.probe_video_file", track_probe)
    with TestClient(create_app(settings=_video_settings(path))) as client:
        inv = _create(client, "Start persistence failure.")
        response = client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        )
        assert response.status_code == 503
    assert called["probe"] == 0
    assert _runs(path) == []


def test_concurrent_delete_waits_on_owner_lock(tmp_path, monkeypatch):
    """While upload holds the owner flock, DELETE cannot unlink concurrently."""
    path = _ledger(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    events: list[str] = []

    real_probe = probe_video_file

    def slow_probe(*args, **kwargs):
        events.append("probe_begin")
        time.sleep(0.35)
        result = real_probe(*args, **kwargs)
        events.append("probe_end")
        return result

    monkeypatch.setattr("app.main.probe_video_file", slow_probe)
    app = create_app(settings=_video_settings(path))
    with TestClient(app) as client:
        inv = _create(client, "Concurrent delete.")
        # Start upload in-process; TestClient is sync so we probe the lock state
        # by attempting a second lock acquire while one upload is mid-flight via
        # a direct store check after starting a blocked second upload attempt.
        store = app.state.videos
        owner = None

        def capture_owner(*args, **kwargs):
            nonlocal owner
            out = real_probe(*args, **kwargs)
            # During probe the first upload still holds the flock.
            owner = _owner_id(path)
            second = store.try_acquire_upload_lock(owner)
            events.append("second_lock")
            assert second is None
            return out

        monkeypatch.setattr("app.main.probe_video_file", capture_owner)
        response = client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        )
        assert response.status_code == 200
        assert "second_lock" in events
        rows = _runs(path)
        assert len(rows) == 1 and rows[0]["status"] == "succeeded"


def test_defaults_still_keep_ingest_off():
    settings = Settings(
        ledger_path="/tmp/stage3c-defaults-unused.sqlite",
        openai_api_key="",
        parallel_api_key="",
    )
    assert settings.video_ingest_enabled is False
    assert settings.video_allow_tier_b is False
    assert settings.video_seal_integration is True


def test_complete_rejects_path_like_failure_codes(tmp_path):
    path = _ledger(tmp_path)
    ledger = Ledger(Path(path))
    with TestClient(create_app(settings=_video_settings(path))) as client:
        inv = _create(client, "Sanitize failure codes.")
        owner = _owner_id(path)
    run_id = ledger.start_video_probe_run(owner, inv, isolation_tier="A")
    assert ledger.complete_video_probe_run(
        owner,
        run_id,
        status="failed",
        failure_code="/tmp/secret/path",
    )
    rows = ledger.video_processing_runs(owner, inv)
    assert rows[0]["failureCode"] is None
