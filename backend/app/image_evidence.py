"""Presentation of a sealed image. This is not an authenticity judgment.

The object is built from the server record already stored on the sealed
snapshot. It is attached to an assessment response. It is not written back
into that snapshot, and it does not add a report store.
"""

import re

from app.metadata_extract import public_embedded_metadata
from app.provenance import public_provenance

RETENTION_STATEMENT = (
    "When this assessment was sealed, the server was retaining this file. "
    "It may subsequently be removed when the investigation or account is deleted."
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_AVAILABILITY = {"retained", "subsequently_deleted", "not_checked", "unavailable"}
_COMPARISON = {
    "match": (
        "The hash supplied by this device matched the server hash. "
        "This comparison does not establish authenticity."
    ),
    "mismatch": (
        "The hash supplied by this device did not match the server hash. "
        "This comparison does not establish manipulation."
    ),
    "unusable": (
        "The hash supplied by this device was not a SHA-256 value. "
        "The server hash is the file identity."
    ),
    "not_supplied": (
        "No hash was supplied by this device. The server hash is the file identity."
    ),
}


def build_image_evidence(
    sealed_asset,
    outcome: str,
    *,
    availability: str,
    checked_at: str | None,
    embedded=None,
    snapshot_id: str | None = None,
    provenance=None,
):
    """Return the presentation object, or None when no sealed image exists.

    ``availability`` describes one check. ``retained`` is allowed only when
    that check found bytes matching the sealed hash and length. This function
    does not read the filesystem and does not look at a client-supplied
    evidence object.

    ``provenance`` is the record stored on the sealed snapshot. It is
    projected with ``public_provenance`` and compared with the sealed image
    identity. It is not an assessment outcome and it is not sent to the model.
    """
    if not isinstance(sealed_asset, dict):
        return None
    digest = sealed_asset.get("sha256")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest.strip().lower()) is None:
        return None
    byte_length = sealed_asset.get("byteLength")
    if not isinstance(byte_length, int) or isinstance(byte_length, bool) or byte_length < 0:
        return None
    if availability not in _AVAILABILITY:
        availability = "not_checked"
    if availability == "not_checked":
        checked_at = None
    comparison = sealed_asset.get("clientHashStatus")
    if comparison not in _COMPARISON:
        comparison = "not_supplied"
    media_type = sealed_asset.get("mediaType")
    asset_id = sealed_asset.get("assetId")
    received_at = sealed_asset.get("receivedAt")
    retention = sealed_asset.get("retention")
    consent = sealed_asset.get("consentVersion")
    documented = "source_linked" if outcome == "POTENTIAL_MANIPULATION" else "none_recorded"
    record_id = ""
    if isinstance(snapshot_id, str) and len(snapshot_id) == 32 and all(char in "0123456789abcdef" for char in snapshot_id):
        record_id = snapshot_id
    sealed_image = {
        "sha256": digest.strip().lower(),
        "byteLength": byte_length,
        "mediaType": media_type if isinstance(media_type, str) else "",
    }
    return {
        "version": "image-evidence-1",
        "snapshotId": record_id,
        "fileIdentity": {
            "sha256": digest.strip().lower(),
            "mediaType": media_type if isinstance(media_type, str) else "",
            "byteLength": byte_length,
            "assetId": asset_id if isinstance(asset_id, str) else "",
        },
        "receipt": {
            "receivedAt": received_at if isinstance(received_at, str) else "",
            "clientHashStatus": comparison,
            "comparison": _COMPARISON[comparison],
        },
        "retentionAtSeal": {
            "retention": retention if isinstance(retention, str) else "",
            "consentVersion": consent if isinstance(consent, str) else "",
            "statement": RETENTION_STATEMENT,
        },
        "currentFile": {
            "availability": availability,
            "checkedAt": checked_at,
        },
        "embeddedMetadata": public_embedded_metadata(embedded) if embedded is not None else {"status": "not_extracted"},
        "provenance": public_provenance(provenance, sealed_image),
        "alteration": {
            "documentedEvidence": documented,
            "technicalIndicators": "not_examined",
            "originalComparison": "no_separate_original",
        },
    }
