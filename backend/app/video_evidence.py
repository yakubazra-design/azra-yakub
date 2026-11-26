"""Presentation of a sealed video. This is not an authenticity judgment.

The object is projected from the immutable ``sealedVideo`` record already
stored on the assessment snapshot. It is attached to assessment responses.
It is not written back into that snapshot, and it does not add a report store
or send video bytes to a model.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from app.video_store import VideoStore, VideoStoreError

DISCLAIMER = (
    "This object describes file identity and technical metadata only. "
    "It does not establish authenticity, original capture time, publication history, "
    "or the truth of any claim."
)

RETENTION_STATEMENT = (
    "Retention and metadata information reflects the recorded state at sealing."
)

COMPARISON = {
    "match": (
        "A SHA-256 match identifies the same file bytes only. "
        "It does not establish authenticity or prove when or where the video was recorded."
    ),
    "mismatch": (
        "The hash supplied by this device did not match the server hash. "
        "This comparison identifies file bytes only and does not establish authenticity "
        "or prove that the video was manipulated."
    ),
    "unusable": (
        "The hash supplied by this device was not a usable SHA-256 value. "
        "The server hash is the file identity. It does not establish authenticity."
    ),
    "not_supplied": (
        "No hash was supplied by this device. The server hash is the file identity. "
        "It does not establish authenticity or prove when or where the video was recorded."
    ),
}

_AVAILABILITY = {"retained", "subsequently_deleted", "not_checked", "unavailable"}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CLIENT_HASH = set(COMPARISON)
_SNAPSHOT_ID = re.compile(r"^[0-9a-f]{32}$")


def build_video_evidence(
    sealed_video,
    *,
    availability: str,
    checked_at: str | None,
    snapshot_id: str | None = None,
):
    """Return the owner-facing presentation object, or None when invalid.

    ``availability`` describes one check. ``retained`` is allowed only when
    that check verified bytes matching the sealed hash and length under the
    owner lock. This function does not read the filesystem and does not look
    at a client-supplied evidence object.
    """
    if not isinstance(sealed_video, dict):
        return None
    digest = sealed_video.get("sha256")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest.strip().lower()) is None:
        return None
    digest = digest.strip().lower()
    byte_length = sealed_video.get("byteLength")
    if not isinstance(byte_length, int) or isinstance(byte_length, bool) or byte_length < 0:
        return None
    media_type = sealed_video.get("mediaType")
    if not isinstance(media_type, str) or not media_type.strip():
        return None
    if availability not in _AVAILABILITY:
        availability = "not_checked"
    if availability == "not_checked":
        checked_at = None
    comparison = sealed_video.get("clientHashStatus")
    if comparison not in _CLIENT_HASH:
        comparison = "not_supplied"
    asset_id = sealed_video.get("assetId")
    received_at = sealed_video.get("receivedAt")
    sealed_at = sealed_video.get("sealedAt")
    retention = sealed_video.get("retention")
    consent = sealed_video.get("consentVersion")
    metadata_decision = sealed_video.get("metadataConsentDecision")
    if not isinstance(metadata_decision, str) or not metadata_decision.strip():
        metadata_decision = "omitted"
    attachment_status = sealed_video.get("attachmentStatus")
    record_id = ""
    if isinstance(snapshot_id, str) and _SNAPSHOT_ID.fullmatch(snapshot_id.strip().lower()):
        record_id = snapshot_id.strip().lower()

    technical = _technical_metadata(sealed_video, metadata_decision)
    processing = {
        "attachmentStatusAtSeal": attachment_status if isinstance(attachment_status, str) else "",
        "probeStatus": "recorded_at_seal",
        "note": (
            "Technical probe values were recorded at seal time. "
            "They do not establish when the video was originally recorded."
        ),
    }

    return {
        "version": "video-evidence-1",
        "snapshotId": record_id,
        "disclaimer": DISCLAIMER,
        "fileIdentity": {
            "sha256": digest,
            "mediaType": media_type.strip(),
            "byteLength": byte_length,
            "assetId": asset_id if isinstance(asset_id, str) else "",
        },
        "receipt": {
            "receivedAt": received_at if isinstance(received_at, str) else "",
            "sealedAt": sealed_at if isinstance(sealed_at, str) else "",
            "clientHashStatus": comparison,
            "comparison": COMPARISON[comparison],
        },
        "retentionAtSeal": {
            "retention": retention if isinstance(retention, str) else "",
            "consentVersion": consent if isinstance(consent, str) else "",
            "metadataConsentDecision": metadata_decision,
            "statement": RETENTION_STATEMENT,
        },
        "technicalMetadata": technical,
        "processing": processing,
        "currentFile": {
            "availability": availability,
            "checkedAt": checked_at,
        },
        "provenance": {
            "version": "absent",
            "status": "not_examined",
            "note": "C2PA video verification is outside the scope of this stage.",
        },
        "alteration": {
            "documentedEvidence": "none_recorded",
            "technicalIndicators": "not_examined",
            "originalComparison": "no_separate_original",
        },
    }


def _technical_metadata(sealed_video: dict, metadata_decision: str) -> dict:
    """Project selective probe fields only when metadata consent was accepted."""
    if metadata_decision != "accepted":
        return {
            "status": "not_disclosed",
            "note": (
                "Technical probe metadata is not presented because metadata consent "
                "was not accepted for this attachment."
            ),
        }
    return {
        "durationMs": _optional_int(sealed_video.get("durationMs")),
        "width": _optional_int(sealed_video.get("width")),
        "height": _optional_int(sealed_video.get("height")),
        "videoCodec": _optional_str(sealed_video.get("videoCodec")),
        "audioCodec": _optional_str(sealed_video.get("audioCodec")),
    }


def _optional_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text if text else None


def check_sealed_video_availability(
    *,
    store: VideoStore | None,
    asset_record: dict | None,
    sealed_video: dict,
    lock_acquired: bool,
) -> tuple[str, str | None]:
    """Determine current-file availability for a sealed video identity.

    Callers must acquire the owner-scoped video lock before invoking this when
    a filesystem check is attempted. When the lock was not acquired, returns
    ``unavailable`` without claiming retention.

    ``asset_record`` is the owner-scoped ``video_assets`` public record (may
    include ``storageName`` for verification only). That name is never returned.
    """
    checked_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    if not isinstance(sealed_video, dict):
        return "unavailable", checked_at
    digest = sealed_video.get("sha256")
    byte_length = sealed_video.get("byteLength")
    asset_id = sealed_video.get("assetId")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest.strip().lower()) is None:
        return "unavailable", checked_at
    digest = digest.strip().lower()
    if not isinstance(byte_length, int) or isinstance(byte_length, bool) or byte_length < 0:
        return "unavailable", checked_at
    if store is None:
        return "unavailable", checked_at
    if not lock_acquired:
        return "unavailable", checked_at
    if asset_record is None:
        return "subsequently_deleted", checked_at
    if not isinstance(asset_record, dict):
        return "unavailable", checked_at
    if asset_record.get("retention") == "retiring":
        return "subsequently_deleted", checked_at
    record_digest = asset_record.get("sha256")
    record_length = asset_record.get("byteLength")
    record_id = asset_record.get("videoAssetId") or asset_record.get("assetId")
    if isinstance(asset_id, str) and asset_id and record_id != asset_id:
        return "unavailable", checked_at
    if record_digest != digest or record_length != byte_length:
        return "unavailable", checked_at
    storage_name = asset_record.get("storageName")
    if not isinstance(storage_name, str) or not storage_name:
        return "unavailable", checked_at
    try:
        if not store.exists(storage_name):
            return "subsequently_deleted", checked_at
        if not store.verify_file(storage_name, digest, byte_length):
            return "unavailable", checked_at
    except VideoStoreError:
        return "unavailable", checked_at
    return "retained", checked_at
