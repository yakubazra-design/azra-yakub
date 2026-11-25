"""Stage 1 V1.2.A foundations — isolated tmp ledgers only.

Does not open the live ledger. Does not enable VIDEO_INGEST_ENABLED.
Does not invoke FFprobe against user media.
"""

from __future__ import annotations

import struct
from pathlib import Path
from secrets import token_hex

from app.config import Settings
from app.ledger import Ledger
from app.limits import MAX_IMAGE_BYTES, MAX_VIDEO_BYTES
from app.main import create_app
from app.video_detect import (
    ATTACHMENT_MISSING,
    ATTACHMENT_READY,
    codec_allowed,
    detect_video_container,
)
from app.video_store import VideoStore, reconcile_video_assets
from fastapi.testclient import TestClient
from test_api import _create, _ensure_auth, _ledger, _settings


def _ftyp(major: bytes, compat: bytes = b"") -> bytes:
    payload = major + struct.pack(">I", 0) + compat
    return struct.pack(">I", 8 + len(payload)) + b"ftyp" + payload


def _minimal_mp4_prefix() -> bytes:
    return _ftyp(b"isom", b"isom" + b"mp41") + (b"\x00" * 64)


def _minimal_qt_prefix() -> bytes:
    return _ftyp(b"qt  ", b"qt  ") + (b"\x00" * 64)


def _minimal_webm_prefix() -> bytes:
    # EBML + DocType webm in early bytes
    return b"\x1a\x45\xdf\xa3" + b"\x00" * 20 + b"webm" + b"\x00" * 40


def test_limits_keep_image_cap_and_define_video_cap():
    assert MAX_IMAGE_BYTES == 8 * 1024 * 1024
    assert MAX_VIDEO_BYTES == 100 * 1024 * 1024
    assert MAX_VIDEO_BYTES != 100 * 1000 * 1000


def test_settings_default_video_ingest_disabled():
    settings = Settings(ledger_path="/tmp/unused-not-opened.sqlite")
    assert settings.video_ingest_enabled is False
    assert settings.video_allow_tier_b is False


def test_detect_video_container_allow_and_reject():
    assert detect_video_container(_minimal_mp4_prefix()) == "video/mp4"
    assert detect_video_container(_minimal_qt_prefix()) == "video/quicktime"
    assert detect_video_container(_minimal_webm_prefix()) == "video/webm"
    # Classic MOV-like without ftyp
    assert detect_video_container(b"\x00\x00\x00\x14moov" + b"\x00" * 32) is None
    assert detect_video_container(b"") is None
    assert detect_video_container(b"\x89PNG\r\n\x1a\n") is None


def test_codec_policy_rejects_hevc_and_av1():
    assert codec_allowed("h264", "aac") is None
    assert codec_allowed("hevc", "aac") == "hevc_not_allowed"
    assert codec_allowed("h265", None) == "hevc_not_allowed"
    assert codec_allowed("av1", "opus") == "av1_not_allowed"
    assert codec_allowed("vp9", "vorbis") is None
    assert codec_allowed(None, None) == "no_video_stream"


def test_video_store_promote_intent_and_reconcile_orphan(tmp_path):
    refuse = _ledger(tmp_path)
    store = VideoStore.for_ledger(Path(refuse))
    upload_id = token_hex(8)
    partial = store.open_partial(upload_id)
    payload = _minimal_mp4_prefix() + b"\x11" * 1000
    store.append_partial(partial, payload)
    digest = __import__("hashlib").sha256(payload).hexdigest()
    asset_id = token_hex(16)
    storage_name = store.promote_partial(
        partial,
        asset_id,
        owner_id="owner",
        investigation_id="inv",
        digest=digest,
        byte_length=len(payload),
    )
    assert storage_name == asset_id + ".bin"
    assert store.exists(storage_name)
    assert store.verify_file(storage_name, digest, len(payload))
    # Intent still present until finished
    assert (store.root / ".intent" / storage_name).is_file()
    store.finish_intent(storage_name)
    assert not (store.root / ".intent" / storage_name).exists()

    # Orphan .bin with no referenced row → quarantine
    summary = reconcile_video_assets(store.root, referenced=set())
    assert summary["quarantined"] == 1
    assert not store.exists(storage_name)
    assert (store.root / ".quarantine" / storage_name).is_file()


def test_reconcile_marks_missing_without_deleting_row(tmp_path):
    path = _ledger(tmp_path)
    ledger = Ledger(Path(path))
    with TestClient(create_app(settings=_settings(ledger_path=path))) as client:
        _ensure_auth(client)
        inv = _create(client, "Video missing-file seal block foundation.")
    import sqlite3
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    owner_id = conn.execute("SELECT id FROM users LIMIT 1").fetchone()["id"]
    conn.close()

    store = VideoStore.for_ledger(Path(path))
    upload_id = token_hex(8)
    partial = store.open_partial(upload_id)
    payload = _minimal_mp4_prefix() + b"\x22" * 500
    store.append_partial(partial, payload)
    digest = __import__("hashlib").sha256(payload).hexdigest()
    asset_id = token_hex(16)
    storage_name = store.promote_partial(
        partial,
        asset_id,
        owner_id=owner_id,
        investigation_id=inv,
        digest=digest,
        byte_length=len(payload),
    )
    outcome, _prev = ledger.save_video_asset(
        owner_id,
        inv,
        asset_id,
        digest,
        len(payload),
        "video/mp4",
        "not_supplied",
        storage_name,
        "video-upload-1",
        "declined",
        "declined",
        attachment_status=ATTACHMENT_READY,
        duration_ms=1000,
        width=640,
        height=360,
        video_codec="h264",
        audio_codec="aac",
        format_name="mp4",
    )
    assert outcome == "saved"
    store.finish_intent(storage_name)
    assert store.remove(storage_name) is True

    ledger._reconcile_video_assets()
    row = ledger.video_asset(owner_id, inv)
    assert row is not None, "V1.2.2E: missing file must not drop the attachment row"
    assert row["attachmentStatus"] == ATTACHMENT_MISSING
    assert row["failureCode"] == "video_bytes_missing"
    # Row still present after second reconcile
    ledger._reconcile_video_assets()
    row2 = ledger.video_asset(owner_id, inv)
    assert row2 is not None
    assert row2["attachmentStatus"] == ATTACHMENT_MISSING


def test_health_reports_video_ingest_disabled(tmp_path):
    path = _ledger(tmp_path)
    with TestClient(create_app(settings=_settings(ledger_path=path))) as client:
        body = client.get("/api/health").json()
    assert body["videoIngestEnabled"] is False


def test_image_asset_path_untouched_by_video_subdir(tmp_path):
    """Video store lives under assets/video; image reconcile root stays assets/."""
    path = _ledger(tmp_path)
    image_root = Path(path).parent / "assets"
    video_root = image_root / "video"
    VideoStore(video_root)
    assert video_root.is_dir()
    assert image_root.is_dir()
    # Creating video store must not require image bins
    assert list(image_root.glob("*.bin")) == []
