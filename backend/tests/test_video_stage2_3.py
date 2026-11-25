"""Stage 2.3 security gap closure — isolated tmp ledgers / synthetic media only."""

from __future__ import annotations

import os
import subprocess
import time
from multiprocessing import Process, Queue
from pathlib import Path
from secrets import token_hex

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.video_detect import VIDEO_REMOVE_CONFIRM
import app.video_probe as video_probe
from app.video_probe import (
    CONFIGURED_CONTROLS,
    RUNTIME_VERIFIED_CONTROLS,
    _ffprobe_version_line,
    ensure_boot_self_test,
    probe_video_file,
    reset_boot_self_test_for_tests,
    tier_a_ready,
)
from app.video_store import VideoStore
from test_api import _create, _ensure_auth, _ledger
from test_video_stage2 import _ffmpeg_mp4, _video_headers, _video_settings


def test_runtime_controls_are_distinct_from_configured_only():
    """Configured argv controls must not be smuggled into the runtime set."""
    assert "unshare_pid" in CONFIGURED_CONTROLS
    assert "unshare_ipc" in CONFIGURED_CONTROLS
    assert "unshare_uts" in CONFIGURED_CONTROLS
    assert "pid_namespace_distinct" in RUNTIME_VERIFIED_CONTROLS
    assert "ipc_namespace_distinct" in RUNTIME_VERIFIED_CONTROLS
    assert "uts_namespace_distinct" in RUNTIME_VERIFIED_CONTROLS
    assert "clearenv_runtime" in RUNTIME_VERIFIED_CONTROLS
    assert "broad_usr_ro_bind" in CONFIGURED_CONTROLS
    assert "broad_usr_ro_bind" not in RUNTIME_VERIFIED_CONTROLS


def test_boot_self_test_runtime_verifies_namespaces_and_env():
    reset_boot_self_test_for_tests()
    ok, code = ensure_boot_self_test()
    assert ok is True
    assert code == "ok"
    ready, ready_code = tier_a_ready()
    assert ready is True
    assert ready_code == "tier_a"
    assert video_probe._ffprobe_version_cache.startswith("ffprobe")


def test_ffprobe_version_helper_does_not_invoke_host_binary(monkeypatch):
    """M-4C: version path must not shell out to host ffprobe."""
    reset_boot_self_test_for_tests()
    assert ensure_boot_self_test()[0] is True

    def boom(*_a, **_k):
        raise AssertionError("host ffprobe -version must not be called")

    monkeypatch.setattr(subprocess, "run", boom)
    line = _ffprobe_version_line("/usr/bin/ffprobe")
    assert line.startswith("ffprobe")
    assert "Copyright" in line or line == "ffprobe"


def test_upload_lock_releases_after_normal_completion(tmp_path):
    root = tmp_path / "assets" / "video"
    store = VideoStore(root)
    owner = token_hex(16)
    first = store.try_acquire_upload_lock(owner)
    assert first is not None
    store.release_upload_lock(first)
    second = store.try_acquire_upload_lock(owner)
    assert second is not None
    store.release_upload_lock(second)


def test_upload_lock_releases_after_holder_process_terminates(tmp_path):
    """M-5: kernel drops flock when the holding process dies without unlock."""
    root = tmp_path / "assets" / "video"
    owner = token_hex(16)
    marker = tmp_path / "holder-acquired"

    def holder():
        try:
            store = VideoStore(root)
            handle = store.try_acquire_upload_lock(owner)
            if handle is None:
                marker.write_text("none", encoding="utf-8")
                os._exit(2)
            marker.write_text("held", encoding="utf-8")
            # Exit hard without release_upload_lock — FD close should drop flock.
            os._exit(0)
        except Exception:
            marker.write_text("error", encoding="utf-8")
            os._exit(3)

    proc = Process(target=holder)
    proc.start()
    proc.join(timeout=10)
    assert proc.exitcode == 0
    assert marker.read_text(encoding="utf-8") == "held"

    deadline = time.time() + 2
    acquired = None
    store = VideoStore(root)
    while time.time() < deadline:
        acquired = store.try_acquire_upload_lock(owner)
        if acquired is not None:
            break
        time.sleep(0.05)
    assert acquired is not None
    store.release_upload_lock(acquired)


def test_upload_lock_contention_across_processes(tmp_path):
    root = tmp_path / "assets" / "video"
    store = VideoStore(root)
    owner = token_hex(16)
    held = store.try_acquire_upload_lock(owner)
    assert held is not None
    q: Queue = Queue()

    def other():
        other_store = VideoStore(root)
        q.put(other_store.try_acquire_upload_lock(owner) is None)

    proc = Process(target=other)
    proc.start()
    proc.join(timeout=10)
    assert proc.exitcode == 0
    assert q.get(timeout=1) is True
    store.release_upload_lock(held)


def test_investigation_erasure_stops_when_video_unlink_fails(tmp_path, monkeypatch):
    """M-7: investigation delete must not succeed while video bytes remain."""
    path = _ledger(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client, "erase-unlink-inv@example.com")
        inv = _create(client, "Erase stops on video unlink failure.")
        assert (
            client.post(
                f"/api/investigations/{inv}/video",
                content=payload,
                headers=_video_headers(client),
            ).status_code
            == 200
        )
        store = VideoStore.for_ledger(Path(path))
        assert list(store.root.glob("*.bin"))

        def fail_remove(self, storage_name):
            return "failed"

        real_remove = VideoStore.remove_report
        monkeypatch.setattr(VideoStore, "remove_report", fail_remove)
        failed = client.delete(f"/api/investigations/{inv}")
        assert failed.status_code == 500
        assert failed.json()["code"] == "asset_cleanup_failed"
        assert failed.json().get("deleted") is False
        assert list(store.root.glob("*.bin"))

        monkeypatch.setattr(VideoStore, "remove_report", real_remove)
        ok = client.delete(f"/api/investigations/{inv}")
        assert ok.status_code == 200
        assert list(store.root.glob("*.bin")) == []


def test_account_erasure_stops_when_video_unlink_fails(tmp_path, monkeypatch):
    """M-7: account delete must not succeed while video bytes remain."""
    path = _ledger(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    password = "correct-horse-battery"
    with TestClient(create_app(settings=_video_settings(path))) as client:
        _ensure_auth(client, "erase-unlink-acct@example.com", password)
        inv = _create(client, "Account erase stops on video unlink failure.")
        assert (
            client.post(
                f"/api/investigations/{inv}/video",
                content=payload,
                headers=_video_headers(client),
            ).status_code
            == 200
        )
        store = VideoStore.for_ledger(Path(path))
        assert list(store.root.glob("*.bin"))

        def fail_remove(self, storage_name):
            return "failed"

        real_remove = VideoStore.remove_report
        monkeypatch.setattr(VideoStore, "remove_report", fail_remove)
        failed = client.request("DELETE", "/api/auth/account", json={"password": password})
        assert failed.status_code == 500
        assert failed.json()["code"] == "asset_cleanup_failed"
        assert failed.json().get("accountDeleted") is False
        assert list(store.root.glob("*.bin"))

        monkeypatch.setattr(VideoStore, "remove_report", real_remove)
        ok = client.request("DELETE", "/api/auth/account", json={"password": password})
        assert ok.status_code == 200
        assert list(store.root.glob("*.bin")) == []


@pytest.mark.skipif(
    not os.path.isfile("/usr/bin/ffmpeg") or not os.path.isfile("/usr/bin/ffprobe"),
    reason="ffmpeg/ffprobe unavailable",
)
def test_sandboxed_probe_enforces_duration_limit(tmp_path, monkeypatch):
    """True duration rejection via lowered cap (avoids multi-minute fixtures)."""
    import app.video_probe as vp

    out = tmp_path / "two-sec.mp4"
    payload = _ffmpeg_mp4(out, seconds=2.0, size="64x64")
    assert payload
    monkeypatch.setattr(vp, "MAX_VIDEO_DURATION_MS", 500)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    reset_boot_self_test_for_tests()
    ensure_boot_self_test()
    with pytest.raises(Exception) as raised:
        probe_video_file(out, scratch_parent=scratch, skip_boot_check=True)
    assert raised.value.code in {"duration_out_of_range", "video_probe_failed"}


@pytest.mark.skipif(
    not os.path.isfile("/usr/bin/ffmpeg") or not os.path.isfile("/usr/bin/ffprobe"),
    reason="ffmpeg/ffprobe unavailable",
)
def test_sandboxed_probe_enforces_frame_rate_limit(tmp_path, monkeypatch):
    import app.video_probe as vp

    out = tmp_path / "fps.mp4"
    payload = _ffmpeg_mp4(out, seconds=1.0, size="64x64")
    assert payload
    monkeypatch.setattr(vp, "MAX_VIDEO_FRAME_RATE", 0.5)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    reset_boot_self_test_for_tests()
    ensure_boot_self_test()
    with pytest.raises(Exception) as raised:
        probe_video_file(out, scratch_parent=scratch, skip_boot_check=True)
    assert raised.value.code in {"frame_rate_out_of_range", "video_probe_failed"}


@pytest.mark.skipif(
    not os.path.isfile("/usr/bin/ffmpeg") or not os.path.isfile("/usr/bin/ffprobe"),
    reason="ffmpeg/ffprobe unavailable",
)
def test_sandboxed_probe_enforces_bitrate_limit(tmp_path, monkeypatch):
    import app.video_probe as vp

    out = tmp_path / "br.mp4"
    payload = _ffmpeg_mp4(out, seconds=1.0, size="320x240")
    assert payload
    monkeypatch.setattr(vp, "MAX_VIDEO_BITRATE_BPS", 1)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    reset_boot_self_test_for_tests()
    ensure_boot_self_test()
    with pytest.raises(Exception) as raised:
        probe_video_file(out, scratch_parent=scratch, skip_boot_check=True)
    assert raised.value.code in {"bitrate_out_of_range", "video_probe_failed", "duration_out_of_range"}


@pytest.mark.skipif(
    not os.path.isfile("/usr/bin/ffmpeg") or not os.path.isfile("/usr/bin/ffprobe"),
    reason="ffmpeg/ffprobe unavailable",
)
def test_sandboxed_probe_rejects_av1_when_encoder_available(tmp_path):
    out = tmp_path / "av1.mp4"
    cmd = [
        "/usr/bin/ffmpeg",
        "-y",
        "-f",
        "lavfi",
        "-i",
        "color=c=black:s=320x240:d=1",
        "-c:v",
        "libaom-av1",
        "-pix_fmt",
        "yuv420p",
        "-t",
        "1",
        str(out),
    ]
    completed = subprocess.run(cmd, capture_output=True, timeout=120)
    if completed.returncode != 0 or not out.is_file():
        pytest.skip("libaom-av1 encoder unavailable — AV1 fixture not generated")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    reset_boot_self_test_for_tests()
    ensure_boot_self_test()
    with pytest.raises(Exception) as raised:
        probe_video_file(out, scratch_parent=scratch, skip_boot_check=True)
    assert raised.value.code in {"av1_not_allowed", "codec_not_allowed", "video_probe_failed"}


def test_settings_flags_remain_disabled():
    settings = Settings(ledger_path="/tmp/unused-stage23.sqlite")
    assert settings.video_ingest_enabled is False
    assert settings.video_allow_tier_b is False


def test_proxy_prerequisite_still_documented():
    text = Path("/workspace/deploy/nginx.conf").read_text(encoding="utf-8")
    assert "client_max_body_size 8m;" in text
    assert "105000000" in text
