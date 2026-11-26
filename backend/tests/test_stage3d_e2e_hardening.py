"""Stage 3.D — end-to-end hardening and integration verification.

Isolated temporary ledgers only. Does not enable production ingest defaults.
Does not open the live ledger. Does not make provider/API calls.
Does not begin Stage 3.E. Does not change feature-flag defaults.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import sqlite3
from pathlib import Path
from secrets import token_hex

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.images import IMAGE_CONSENT_VERSION
from app.ledger import Ledger, LedgerError
from app.limits import (
    MAX_IMAGE_BYTES,
    MAX_VIDEO_AUDIO_STREAMS,
    MAX_VIDEO_BITRATE_BPS,
    MAX_VIDEO_BYTES,
    MAX_VIDEO_DURATION_MS,
    MAX_VIDEO_FRAME_RATE,
    MAX_VIDEO_HEIGHT,
    MAX_VIDEO_WIDTH,
)
from app.main import create_app
from app.video_detect import VIDEO_REMOVE_CONFIRM
from app.video_evidence import DISCLAIMER
from app.video_probe import (
    PROBE_STDOUT_MAX,
    PROBE_WALL_SECONDS,
    VideoProbeError,
    probe_video_file,
    reset_boot_self_test_for_tests,
)
from app.video_store import VideoStore
from test_api import DUMMY_OPENAI, _create, _ensure_auth, _ledger, _seal, _settings
from test_assets import _png
from test_video_stage3a import _ffmpeg_mp4, _video_headers, _video_settings
from test_video_stage3b import _upload_video


PASSWORD = "correct-horse-battery"


def _image_headers() -> dict:
    return {"Content-Type": "application/octet-stream", "X-Image-Consent": IMAGE_CONSENT_VERSION}


def _openai(_request: httpx.Request) -> httpx.Response:
    content = json.dumps(
        {
            "assessment": "UNRESOLVED",
            "findings": [],
            "why": {},
            "uncertainty": ["Fixture uncertainty."],
            "originalMaterial": {"established": False, "description": "", "source": None},
        }
    )
    return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})


def _combined_app(tmp_path, **overrides):
    path = _ledger(tmp_path)
    prompts: list[str] = []

    def capture(request: httpx.Request) -> httpx.Response:
        prompts.append(json.loads(request.content.decode())["messages"][0]["content"])
        return _openai(request)

    settings = _video_settings(path, openai_api_key=DUMMY_OPENAI, **overrides)
    app = create_app(settings=settings, openai_transport=httpx.MockTransport(capture))
    return path, app, prompts


def _runs(path: str) -> list[dict]:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM video_processing_runs ORDER BY started_at").fetchall()]
    finally:
        conn.close()


def _snapshots(path: str) -> list[dict]:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT id, snapshot_json FROM assessment_snapshots ORDER BY created_at ASC"
        ).fetchall()
        return [{"id": r["id"], "body": json.loads(r["snapshot_json"])} for r in rows]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 3.D.1 — End-to-end workflows
# ---------------------------------------------------------------------------


def test_e2e_image_only_investigation_workflow(tmp_path):
    path, app, prompts = _combined_app(tmp_path)
    png = _png()
    with TestClient(app) as client:
        inv = _create(client, "Image-only claim.")
        uploaded = client.post(
            f"/api/investigations/{inv}/asset",
            content=png,
            headers=_image_headers(),
        )
        assert uploaded.status_code == 200, uploaded.text
        assessed = client.post(
            f"/api/investigations/{inv}/assess",
            json={"assessmentToken": _seal(client, inv)},
        )
        assert assessed.status_code == 200, assessed.text
        body = assessed.json()
        assert body.get("imageEvidence") is not None
        assert body.get("videoEvidence") is None
        latest = client.get(f"/api/investigations/{inv}/assessments/latest")
        assert latest.status_code == 200
        assert latest.json().get("imageEvidence") is not None
        assert latest.json().get("videoEvidence") is None
        deleted = client.delete(f"/api/investigations/{inv}")
        assert deleted.status_code == 200
    assert prompts
    assert "videoEvidence" not in prompts[0]
    assert _snapshots(path) == []


def test_e2e_video_only_investigation_workflow(tmp_path):
    path, app, prompts = _combined_app(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    digest = hashlib.sha256(payload).hexdigest()
    with TestClient(app) as client:
        inv = _create(client, "Video-only claim.")
        uploaded = _upload_video(client, inv, payload, metadata_accepted=True)
        assert uploaded.status_code == 200, uploaded.text
        video_asset_id = uploaded.json()["videoAssetId"]
        assessed = client.post(
            f"/api/investigations/{inv}/assess",
            json={
                "assessmentToken": _seal(client, inv),
                "videoEvidence": {"version": "forged", "fileIdentity": {"sha256": "ab" * 32}},
                "sealedVideo": {"sha256": "ab" * 32},
            },
        )
        assert assessed.status_code == 200, assessed.text
        body = assessed.json()
        ve = body["videoEvidence"]
        assert ve["version"] == "video-evidence-1"
        assert ve["fileIdentity"]["sha256"] == digest
        assert ve["fileIdentity"]["assetId"] == video_asset_id
        assert ve["currentFile"]["availability"] == "retained"
        assert body.get("imageEvidence") is None
        latest = client.get(f"/api/investigations/{inv}/assessments/latest")
        assert latest.status_code == 200
        hist = latest.json()["videoEvidence"]
        assert hist["fileIdentity"]["sha256"] == digest
        assert hist["version"] == "video-evidence-1"
    runs = _runs(path)
    assert len(runs) == 1
    assert runs[0]["status"] == "succeeded"
    assert runs[0]["video_asset_id"] == video_asset_id
    snaps = _snapshots(path)
    assert len(snaps) == 1
    sealed = snaps[0]["body"]["sealedVideo"]
    assert sealed["sha256"] == digest
    assert "storageName" not in sealed
    assert "storage_name" not in sealed
    assert "videoEvidence" not in snaps[0]["body"]
    assert digest not in prompts[0]
    assert "videoEvidence" not in prompts[0]
    assert payload not in prompts[0].encode()


def test_e2e_image_and_video_remain_separate_contracts(tmp_path):
    path, app, prompts = _combined_app(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    png = _png()
    with TestClient(app) as client:
        inv = _create(client, "Both image and video.")
        assert (
            client.post(
                f"/api/investigations/{inv}/asset",
                content=png,
                headers=_image_headers(),
            ).status_code
            == 200
        )
        assert _upload_video(client, inv, payload, metadata_accepted=True).status_code == 200
        assessed = client.post(
            f"/api/investigations/{inv}/assess",
            json={"assessmentToken": _seal(client, inv)},
        )
        assert assessed.status_code == 200, assessed.text
        body = assessed.json()
        assert body["imageEvidence"] is not None
        assert body["videoEvidence"] is not None
        assert body["imageEvidence"]["fileIdentity"]["sha256"] != body["videoEvidence"]["fileIdentity"]["sha256"]
        assert body["imageEvidence"]["version"] == "image-evidence-1"
        assert body["videoEvidence"]["version"] == "video-evidence-1"
        assert "formatName" not in body["videoEvidence"]["technicalMetadata"]
        blob = json.dumps(body)
        assert "assets/video" not in blob
        assert "storageName" not in blob
    assert "videoEvidence" not in prompts[0]
    snaps = _snapshots(path)
    assert "sealedVideo" in snaps[0]["body"]
    assert "videoEvidence" not in snaps[0]["body"]
    assert "imageEvidence" not in snaps[0]["body"]


# ---------------------------------------------------------------------------
# 3.D.2 — Failure handling
# ---------------------------------------------------------------------------


def test_invalid_image_and_invalid_video_fail_closed(tmp_path):
    path, app, _ = _combined_app(tmp_path)
    with TestClient(app) as client:
        inv = _create(client, "Invalid uploads.")
        bad_image = client.post(
            f"/api/investigations/{inv}/asset",
            content=b"not-an-image",
            headers=_image_headers(),
        )
        assert bad_image.status_code >= 400
        bad_video = client.post(
            f"/api/investigations/{inv}/video",
            content=b"not-a-video",
            headers=_video_headers(client),
        )
        assert bad_video.status_code == 400
        assert bad_video.json()["code"] == "invalid_video"
    assert _runs(path) == []


@pytest.mark.parametrize(
    "code",
    [
        "video_probe_timeout",
        "probe_output_too_large",
        "video_isolation_insufficient",
        "codec_not_allowed",
        "invalid_video",
    ],
)
def test_probe_failures_do_not_report_success(tmp_path, monkeypatch, code):
    path, app, _ = _combined_app(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)

    def boom(*_a, **_k):
        raise VideoProbeError(code)

    monkeypatch.setattr("app.main.probe_video_file", boom)
    with TestClient(app) as client:
        inv = _create(client, f"Probe fail {code}.")
        response = _upload_video(client, inv, payload)
        assert response.status_code >= 400
        assert response.json()["code"] == code
    rows = _runs(path)
    assert len(rows) == 1
    assert rows[0]["status"] == "failed"
    assert rows[0]["failure_code"] == code


def test_success_complete_failure_fails_closed(tmp_path, monkeypatch):
    path, app, _ = _combined_app(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)

    def fail_complete(*_a, **_k):
        raise LedgerError("The evidence ledger is unavailable.")

    with TestClient(app) as client:
        inv = _create(client, "Complete failure.")
        monkeypatch.setattr(Ledger, "complete_video_probe_run", fail_complete)
        response = _upload_video(client, inv, payload)
        assert response.status_code == 503
    assert all(r["status"] != "succeeded" for r in _runs(path))


def test_hash_mismatch_client_header_still_seals_server_identity(tmp_path):
    path, app, _ = _combined_app(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    digest = hashlib.sha256(payload).hexdigest()
    with TestClient(app) as client:
        inv = _create(client, "Client hash mismatch.")
        headers = _video_headers(client, {"X-Client-Sha256": "ab" * 32})
        uploaded = client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=headers,
        )
        assert uploaded.status_code == 200, uploaded.text
        assert uploaded.json()["clientHashStatus"] == "mismatch"
        assert uploaded.json()["sha256"] == digest
        assessed = client.post(
            f"/api/investigations/{inv}/assess",
            json={"assessmentToken": _seal(client, inv)},
        )
        assert assessed.status_code == 200
        assert assessed.json()["videoEvidence"]["fileIdentity"]["sha256"] == digest
        assert assessed.json()["videoEvidence"]["receipt"]["clientHashStatus"] == "mismatch"


def test_concurrent_upload_lock_rejects_second_holder(tmp_path):
    path, app, _ = _combined_app(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    with TestClient(app) as client:
        inv = _create(client, "Concurrent upload lock.")
        store = app.state.videos
        assert store is not None
        # Hold the owner upload lock while attempting a second upload.
        conn = sqlite3.connect(path)
        try:
            owner_id = conn.execute("SELECT id FROM users LIMIT 1").fetchone()[0]
        finally:
            conn.close()
        handle = store.try_acquire_upload_lock(owner_id)
        assert handle is not None
        try:
            response = _upload_video(client, inv, payload)
            assert response.status_code == 409
            assert response.json()["code"] == "video_upload_in_progress"
        finally:
            store.release_upload_lock(handle)
    assert _runs(path) == []


# ---------------------------------------------------------------------------
# 3.D.3 — Security, ownership, erasure
# ---------------------------------------------------------------------------


def test_cross_account_rejects_investigation_and_video_access(tmp_path):
    path, app, _ = _combined_app(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    with TestClient(app) as client:
        _ensure_auth(client, "owner-a@example.com")
        inv = _create(client, "Owner A private.")
        assert _upload_video(client, inv, payload).status_code == 200
        client.cookies.clear()
        client.headers.pop("X-CSRF-Token", None)
        _ensure_auth(client, "owner-b@example.com")
        get_inv = client.get(f"/api/investigations/{inv}")
        get_video = client.get(f"/api/investigations/{inv}/video")
        assess = client.post(
            f"/api/investigations/{inv}/assess",
            json={"assessmentToken": "not-a-token"},
        )
        latest = client.get(f"/api/investigations/{inv}/assessments/latest")
    assert get_inv.status_code in {403, 404}
    assert get_video.status_code in {403, 404}
    assert assess.status_code >= 400
    assert latest.status_code == 404
    assert "videoEvidence" not in latest.text


def test_no_video_download_or_stream_routes():
    from app import main as main_mod

    src = inspect.getsource(main_mod)
    assert "/video/download" not in src
    assert "/video/stream" not in src
    assert '@app.post("/api/investigations/{investigation_id}/video")' in src
    assert '@app.get("/api/investigations/{investigation_id}/video")' in src
    assert '@app.delete("/api/investigations/{investigation_id}/video")' in src
    # GET returns metadata only — no FileResponse / StreamingResponse for video bytes.
    get_block = src.split('@app.get("/api/investigations/{investigation_id}/video")', 1)[1]
    get_block = get_block.split("@app.", 1)[0]
    assert "FileResponse" not in get_block
    assert "StreamingResponse" not in get_block
    assert "read_bytes" not in get_block


def test_account_erasure_removes_runs_and_assets(tmp_path):
    path, app, _ = _combined_app(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    with TestClient(app) as client:
        _ensure_auth(client, f"erase-{token_hex(3)}@example.com", password=PASSWORD)
        inv = client.post(
            "/api/investigations", json={"input": "Erase me.", "kind": "claim"}
        ).json()["investigationId"]
        assert _upload_video(client, inv, payload).status_code == 200
        assert len(_runs(path)) == 1
        erased = client.request("DELETE", "/api/auth/account", json={"password": PASSWORD})
        assert erased.status_code == 200, erased.text
    assert _runs(path) == []
    conn = sqlite3.connect(path)
    try:
        assert conn.execute("SELECT COUNT(*) FROM video_assets").fetchone()[0] == 0
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 3.D.4 — Snapshot / historical consistency
# ---------------------------------------------------------------------------


def test_post_seal_user_delete_is_rejected(tmp_path):
    """Sealed video identity must not be silently dropped by a user DELETE."""
    path, app, _ = _combined_app(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    with TestClient(app) as client:
        inv = _create(client, "Post-seal delete blocked.")
        assert _upload_video(client, inv, payload, metadata_accepted=True).status_code == 200
        assessed = client.post(
            f"/api/investigations/{inv}/assess",
            json={"assessmentToken": _seal(client, inv)},
        )
        assert assessed.status_code == 200
        digest = assessed.json()["videoEvidence"]["fileIdentity"]["sha256"]
        blocked = client.delete(
            f"/api/investigations/{inv}/video",
            headers={"X-Video-Remove-Confirm": VIDEO_REMOVE_CONFIRM},
        )
        assert blocked.status_code == 409
        assert blocked.json()["code"] == "video_after_seal"
        latest = client.get(f"/api/investigations/{inv}/assessments/latest")
        assert latest.status_code == 200
        assert latest.json()["videoEvidence"]["fileIdentity"]["sha256"] == digest
        assert latest.json()["videoEvidence"]["currentFile"]["availability"] == "retained"
    snaps = _snapshots(path)
    assert snaps[0]["body"]["sealedVideo"]["sha256"] == digest


def test_historical_video_evidence_survives_bytes_loss(tmp_path):
    """Availability may change when sealed bytes vanish; identity must not rewrite."""
    path, app, _ = _combined_app(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    digest = hashlib.sha256(payload).hexdigest()
    with TestClient(app) as client:
        inv = _create(client, "Bytes lost after seal.")
        assert _upload_video(client, inv, payload, metadata_accepted=True).status_code == 200
        assessed = client.post(
            f"/api/investigations/{inv}/assess",
            json={"assessmentToken": _seal(client, inv)},
        )
        assert assessed.status_code == 200
        snapshot_id = assessed.json()["snapshotId"]
        sealed_sha = assessed.json()["videoEvidence"]["fileIdentity"]["sha256"]
        assert sealed_sha == digest
        store = VideoStore.for_ledger(Path(path))
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute("SELECT storage_name FROM video_assets").fetchone()
        finally:
            conn.close()
        assert row is not None
        assert store.remove(row["storage_name"]) is True
        historical = client.get(f"/api/investigations/{inv}/assessments/{snapshot_id}")
        latest = client.get(f"/api/investigations/{inv}/assessments/latest")
        assert historical.status_code == 200
        hist_ve = historical.json()["videoEvidence"]
        assert hist_ve["fileIdentity"]["sha256"] == digest
        assert hist_ve["version"] == "video-evidence-1"
        assert hist_ve["fileIdentity"]["sha256"] == sealed_sha
        assert hist_ve["currentFile"]["availability"] == "subsequently_deleted"
        assert latest.json()["videoEvidence"]["currentFile"]["availability"] == "subsequently_deleted"
        snaps = _snapshots(path)
        assert "videoEvidence" not in snaps[0]["body"]
        assert "storageName" not in json.dumps(snaps[0]["body"])
        assert snaps[0]["body"]["sealedVideo"]["sha256"] == digest


def test_unavailable_video_is_not_authentic_or_verified_language(tmp_path):
    path, app, _ = _combined_app(tmp_path)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    with TestClient(app) as client:
        inv = _create(client, "No authenticity language.")
        assert _upload_video(client, inv, payload).status_code == 200
        assessed = client.post(
            f"/api/investigations/{inv}/assess",
            json={"assessmentToken": _seal(client, inv)},
        )
        assert assessed.status_code == 200
        store = VideoStore.for_ledger(Path(path))
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute("SELECT storage_name FROM video_assets").fetchone()
        finally:
            conn.close()
        assert store.remove(row["storage_name"]) is True
        latest = client.get(f"/api/investigations/{inv}/assessments/latest")
        text = latest.text
    for banned in (
        "Genuine video",
        "Authentic video",
        "Verified original",
        "Proven real",
        "Manipulated video",
    ):
        assert banned not in text
    ve = latest.json()["videoEvidence"]
    assert ve["currentFile"]["availability"] == "subsequently_deleted"
    assert "does not establish authenticity" in ve["disclaimer"]
    assert DISCLAIMER.split(".")[0] in ve["disclaimer"]


# ---------------------------------------------------------------------------
# 3.D.5 — Resource limits (constants + probe cleanup)
# ---------------------------------------------------------------------------


def test_resource_limit_constants_unchanged():
    assert MAX_IMAGE_BYTES == 8 * 1024 * 1024
    assert MAX_VIDEO_BYTES == 100 * 1024 * 1024
    assert MAX_VIDEO_DURATION_MS == 180_000
    assert MAX_VIDEO_WIDTH == 1920
    assert MAX_VIDEO_HEIGHT == 1080
    assert MAX_VIDEO_FRAME_RATE == 60.0
    assert MAX_VIDEO_BITRATE_BPS == 20_000_000
    assert MAX_VIDEO_AUDIO_STREAMS == 1
    assert PROBE_WALL_SECONDS == 25
    assert PROBE_STDOUT_MAX == 1 * 1024 * 1024


def test_defaults_keep_ingest_disabled():
    settings = Settings(
        ledger_path="/tmp/stage3d-defaults-unused.sqlite",
        openai_api_key="",
        parallel_api_key="",
    )
    assert settings.video_ingest_enabled is False
    assert settings.video_allow_tier_b is False
    assert settings.video_seal_integration is True


def test_probe_scratch_cleaned_after_success(tmp_path):
    store = VideoStore(tmp_path / "videos")
    media = tmp_path / "ok.mp4"
    _ffmpeg_mp4(media)
    reset_boot_self_test_for_tests()
    before = set(store.scratch_dir().glob("probe-*")) if store.scratch_dir().exists() else set()
    probe_video_file(media, scratch_parent=store.scratch_dir(), skip_boot_check=True)
    after = set(store.scratch_dir().glob("probe-*")) if store.scratch_dir().exists() else set()
    assert after == before


def test_oversized_video_request_rejected(tmp_path, monkeypatch):
    """Reject when streamed bytes would exceed MAX_VIDEO_BYTES (fixture-controlled)."""
    path, app, _ = _combined_app(tmp_path)
    monkeypatch.setattr("app.main.MAX_VIDEO_BYTES", 1024)
    media = tmp_path / "ok.mp4"
    payload = _ffmpeg_mp4(media)
    assert len(payload) > 1024
    with TestClient(app) as client:
        inv = _create(client, "Oversized.")
        response = client.post(
            f"/api/investigations/{inv}/video",
            content=payload,
            headers=_video_headers(client),
        )
        assert response.status_code == 413
        assert response.json()["code"] == "request_too_large"
    assert _runs(path) == []


# ---------------------------------------------------------------------------
# Frontend contract still present (Stage 3.B)
# ---------------------------------------------------------------------------


def test_frontend_video_evidence_helpers_still_present():
    engine = Path(__file__).resolve().parents[2] / "frontend" / "engine.js"
    assert engine.is_file()
    script = engine.read_text(encoding="utf-8")
    assert "function serverVideoEvidence" in script
    assert "function renderVideoEvidence" in script
    assert "videoEvidence: serverVideoEvidence(r.videoEvidence)" in script
    assess = script.split("function assess")[1].split("function validate")[0]
    assert "videoEvidence:" not in assess
    assert "sealedVideo:" not in assess
