"""Sealed C2PA provenance records.

A record is built from the server image identity, a confirmed trust-policy
pin, and a reader result. Client-supplied provenance is rejected. Credential
statuses stay separate from the six claim-assessment outcomes. A trusted
credential does not establish that the pictured event happened.

PEM text, private keys, and certificate bytes are not stored. A historical
snapshot with no record stays not examined and is not rewritten.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping

from app.c2pa_statuses import ASSESSMENT_OUTCOMES, CREDENTIAL_STATUSES, FAILURE_CODES
from app.limits import MAX_IMAGE_BYTES

RECORD_VERSION = "c2pa-provenance-1"
READER_VERSION = "c2pa-reader-2"
NATIVE_LIBRARY_VERSION = "0.92.0"
HISTORICAL_VERSION = "absent"
HISTORICAL_STATUS = "not_examined"
EVENT_DEPICTION = "not_established"

READER_TECHNICAL_CODES = frozenset({
    "reader_timeout",
    "reader_crash",
    "reader_unavailable",
    "memory_limit",
    "trust_configuration",
})
TECHNICAL_FAILURE_CODES = READER_TECHNICAL_CODES | FAILURE_CODES
REJECTION_CODES = frozenset({
    "client_provenance",
    "identity_mismatch",
    "invalid_record",
    "leaked_material",
})

MEDIA_TYPES = frozenset({
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
})
ROOT_USES = frozenset({"active", "verify-only"})
PURPOSES = frozenset({"policy", "suspension"})
MANIFEST_ROLES = frozenset({"active", "ingredient", "unreferenced"})
MANIFEST_STATUSES = frozenset({
    "credentials_malformed",
    "credentials_invalid",
    "credentials_untrusted",
    "credentials_trusted",
})
CHECK_VALUES = {
    "signature": frozenset({"valid", "invalid", "missing", "not_checked"}),
    "assetBinding": frozenset({"bound", "mismatch", "missing", "malformed", "not_checked"}),
    "certificateTrust": frozenset({"trusted", "untrusted", "not_checked"}),
    "certificateValidity": frozenset({"inside_at_asserted_time", "expired", "outside", "not_checked"}),
    "revocation": frozenset({"not_revoked", "revoked", "skipped", "unknown", "inaccessible", "not_checked"}),
    "timestamp": frozenset({"trusted", "absent", "untrusted", "malformed", "outside_validity", "not_checked"}),
}
UNCHECKED = {name: "not_checked" for name in CHECK_VALUES}

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_LABEL = re.compile(r"^[A-Za-z0-9:._~/#?&=%+-]{1,200}$")
_MAX_MANIFESTS = 16

_POLICY_KEYS = frozenset({
    "releaseSequence",
    "activationDigest",
    "suspensionDigest",
    "manifestBundleSha256",
    "timestampBundleSha256",
    "rootUse",
    "purpose",
})
_IMAGE_KEYS = frozenset({"sha256", "byteLength", "mediaType"})
_READER_KEYS = frozenset({"readerVersion", "nativeLibraryVersion"})
_RESULT_KEYS = frozenset({"kind", "status", "failureCode", "checks", "manifests"})
_RECORD_KEYS = frozenset({"version", "verifiedAt", "image", "reader", "policy", "result"})
_MANIFEST_KEYS = frozenset({"label", "role", "status", "checks"})
_READER_RESULT_KEYS = frozenset({
    "version",
    "status",
    "failureCode",
    "checks",
    "manifests",
    "actions",
    "actionsWithheld",
})
_FORBIDDEN_KEYS = frozenset({
    "assessment",
    "certificate",
    "certificateBytes",
    "manifestTrustPem",
    "password",
    "pem",
    "privateKey",
    "private_key",
    "raw",
    "secret",
    "store",
    "storeJson",
    "timestampTrustPem",
    "token",
})
_LEAK_MARKERS = (
    "-----BEGIN",
    "PRIVATE KEY",
    "BEGIN CERTIFICATE",
    "BEGIN TRUSTED",
)


def build_provenance_record(
    *,
    sha256: str,
    byte_length: int,
    media_type: str,
    verified_at: str,
    release_sequence: int | None = None,
    activation_digest: str | None = None,
    suspension_digest: str | None = None,
    manifest_bundle_sha256: str | None = None,
    timestamp_bundle_sha256: str | None = None,
    manifest_trust_pem: str | None = None,
    timestamp_trust_pem: str | None = None,
    root_use: str | None = None,
    purpose: str | None = None,
    reader_result: Mapping | None = None,
    failure_code: str | None = None,
    native_library_version: str = NATIVE_LIBRARY_VERSION,
) -> dict:
    """Build one sealed record from server inputs.

    Bundle PEM text is hashed and discarded. The returned record has no
    action list and no assessment outcome.
    """
    image, image_error = _image(sha256, byte_length, media_type)
    if image_error:
        return _rejected(image_error)
    if not isinstance(verified_at, str) or _TIMESTAMP.fullmatch(verified_at) is None:
        return _rejected("invalid_record")
    if native_library_version != NATIVE_LIBRARY_VERSION:
        return _rejected("invalid_record")
    policy, policy_error = _policy(
        release_sequence,
        activation_digest,
        suspension_digest,
        manifest_bundle_sha256,
        timestamp_bundle_sha256,
        manifest_trust_pem,
        timestamp_trust_pem,
        root_use,
        purpose,
    )
    if policy_error:
        return _rejected(policy_error)
    result, result_error = _result(reader_result, failure_code, policy is not None)
    if result_error:
        return _rejected(result_error)
    record = {
        "version": RECORD_VERSION,
        "verifiedAt": verified_at,
        "image": image,
        "reader": {
            "readerVersion": READER_VERSION,
            "nativeLibraryVersion": NATIVE_LIBRARY_VERSION,
        },
        "policy": policy,
        "result": result,
    }
    if _leaks(record):
        return _rejected("leaked_material")
    return {"ok": True, "record": record}


def validate_provenance_record(record, sealed_image: Mapping) -> dict:
    """Accept an exact sealed record whose image identity matches.

    The input mapping is not modified. A valid result is a new mapping
    with the same fields. Missing or extra fields are rejected rather
    than filled in.
    """
    if not isinstance(record, Mapping):
        return _rejected("invalid_record")
    if _forbidden_key(record) or _leaks(record):
        return _rejected("leaked_material")
    if set(record) != _RECORD_KEYS or record.get("version") != RECORD_VERSION:
        return _rejected("invalid_record")
    if not isinstance(record.get("verifiedAt"), str) or _TIMESTAMP.fullmatch(record["verifiedAt"]) is None:
        return _rejected("invalid_record")
    image = _exact_image(record.get("image"))
    if image is None:
        return _rejected("invalid_record")
    sealed = _exact_image(sealed_image)
    if sealed is None:
        return _rejected("invalid_record")
    if sealed != image:
        return _rejected("identity_mismatch")
    reader = record.get("reader")
    if not isinstance(reader, Mapping) or set(reader) != _READER_KEYS:
        return _rejected("invalid_record")
    if reader.get("readerVersion") != READER_VERSION or reader.get("nativeLibraryVersion") != NATIVE_LIBRARY_VERSION:
        return _rejected("invalid_record")
    policy = _exact_policy(record.get("policy"))
    if policy is False:
        return _rejected("invalid_record")
    result = _exact_result(record.get("result"), policy is not None)
    if result is None:
        return _rejected("invalid_record")
    if result["status"] in ASSESSMENT_OUTCOMES or result["failureCode"] in ASSESSMENT_OUTCOMES:
        return _rejected("invalid_record")
    stored = {
        "version": RECORD_VERSION,
        "verifiedAt": record["verifiedAt"],
        "image": image,
        "reader": {
            "readerVersion": READER_VERSION,
            "nativeLibraryVersion": NATIVE_LIBRARY_VERSION,
        },
        "policy": policy,
        "result": result,
    }
    return {"ok": True, "record": stored}


def public_provenance(record, sealed_image: Mapping | None = None) -> dict:
    """Return the allowlisted projection of a sealed record.

    A missing record stays the historical not-examined state. An invalid
    record becomes a technical failure that does not repeat the input.
    """
    if record is None:
        return _historical()
    if sealed_image is None:
        return _unreadable()
    checked = validate_provenance_record(record, sealed_image)
    if not checked["ok"]:
        return _unreadable()
    stored = checked["record"]
    projected = {
        "version": stored["version"],
        "verifiedAt": stored["verifiedAt"],
        "image": dict(stored["image"]),
        "reader": dict(stored["reader"]),
        "policy": None if stored["policy"] is None else dict(stored["policy"]),
        "result": _project_result(stored["result"]),
        "eventDepiction": EVENT_DEPICTION,
    }
    return projected


def reject_client_provenance(_supplied: object) -> dict:
    """Reject provenance supplied by a caller.

    A value that already looks like a sealed record is still rejected.
    The server builder is the only source of a record.
    """
    return _rejected("client_provenance")


def _historical() -> dict:
    return {
        "version": HISTORICAL_VERSION,
        "status": HISTORICAL_STATUS,
        "eventDepiction": EVENT_DEPICTION,
    }


def _unreadable() -> dict:
    return {
        "version": RECORD_VERSION,
        "result": {
            "kind": "technical",
            "status": "verification_failed",
            "failureCode": "trust_configuration",
            "checks": None,
            "manifests": [],
        },
        "eventDepiction": EVENT_DEPICTION,
    }


def _rejected(code: str) -> dict:
    if code not in REJECTION_CODES:
        code = "invalid_record"
    return {"ok": False, "failureCode": code}


def _image(sha256: str, byte_length: int, media_type: str):
    image = {"sha256": sha256, "byteLength": byte_length, "mediaType": media_type}
    exact = _exact_image(image)
    if exact is None:
        return None, "invalid_record"
    return exact, None


def _exact_image(value):
    if not isinstance(value, Mapping) or set(value) != _IMAGE_KEYS:
        return None
    digest = value.get("sha256")
    length = value.get("byteLength")
    media = value.get("mediaType")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        return None
    if isinstance(length, bool) or not isinstance(length, int) or length < 0 or length > MAX_IMAGE_BYTES:
        return None
    if media not in MEDIA_TYPES:
        return None
    return {"sha256": digest, "byteLength": length, "mediaType": media}


def _policy(
    release_sequence,
    activation_digest,
    suspension_digest,
    manifest_bundle_sha256,
    timestamp_bundle_sha256,
    manifest_trust_pem,
    timestamp_trust_pem,
    root_use,
    purpose,
):
    supplied = (
        release_sequence,
        activation_digest,
        suspension_digest,
        manifest_bundle_sha256,
        timestamp_bundle_sha256,
        manifest_trust_pem,
        timestamp_trust_pem,
        root_use,
        purpose,
    )
    if all(item is None for item in supplied):
        return None, None
    if _pem_leaks(manifest_trust_pem) or _pem_leaks(timestamp_trust_pem):
        return None, "leaked_material"
    manifest_hash, manifest_error = _bundle_hash(manifest_bundle_sha256, manifest_trust_pem)
    timestamp_hash, timestamp_error = _bundle_hash(timestamp_bundle_sha256, timestamp_trust_pem)
    if manifest_error or timestamp_error:
        return None, manifest_error or timestamp_error
    policy = _exact_policy({
        "releaseSequence": release_sequence,
        "activationDigest": activation_digest,
        "suspensionDigest": suspension_digest,
        "manifestBundleSha256": manifest_hash,
        "timestampBundleSha256": timestamp_hash,
        "rootUse": root_use,
        "purpose": purpose,
    })
    if policy is False or policy is None:
        return None, "invalid_record"
    return policy, None


def _bundle_hash(supplied, pem):
    if pem is None and supplied is None:
        return None, "invalid_record"
    if pem is not None:
        if not isinstance(pem, str) or "\x00" in pem or pem.strip() == "":
            return None, "invalid_record"
        digest = hashlib.sha256(pem.encode("utf-8")).hexdigest()
        if supplied is not None and supplied != digest:
            return None, "invalid_record"
        return digest, None
    if not isinstance(supplied, str) or _SHA256.fullmatch(supplied) is None:
        return None, "invalid_record"
    return supplied, None


def _exact_policy(value):
    if value is None:
        return None
    if not isinstance(value, Mapping) or set(value) != _POLICY_KEYS:
        return False
    sequence = value.get("releaseSequence")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        return False
    activation = value.get("activationDigest")
    suspension = value.get("suspensionDigest")
    manifest = value.get("manifestBundleSha256")
    timestamp = value.get("timestampBundleSha256")
    if any(not isinstance(item, str) or _SHA256.fullmatch(item) is None for item in (activation, suspension, manifest, timestamp)):
        return False
    if value.get("rootUse") not in ROOT_USES or value.get("purpose") not in PURPOSES:
        return False
    return {
        "releaseSequence": sequence,
        "activationDigest": activation,
        "suspensionDigest": suspension,
        "manifestBundleSha256": manifest,
        "timestampBundleSha256": timestamp,
        "rootUse": value["rootUse"],
        "purpose": value["purpose"],
    }


def _result(reader_result, failure_code, policy_present: bool):
    if reader_result is None and failure_code is None:
        return None, "invalid_record"
    if reader_result is None:
        if failure_code not in TECHNICAL_FAILURE_CODES:
            return None, "invalid_record"
        if failure_code in ASSESSMENT_OUTCOMES:
            return None, "invalid_record"
        return _technical_result(failure_code), None
    if not isinstance(reader_result, Mapping):
        return None, "invalid_record"
    if _forbidden_key(reader_result) or _leaks(reader_result):
        return None, "leaked_material"
    if set(reader_result) - _READER_RESULT_KEYS:
        return None, "invalid_record"
    if reader_result.get("version") != READER_VERSION:
        return None, "invalid_record"
    if reader_result.get("actions") != [] or reader_result.get("actionsWithheld") is not True:
        return None, "invalid_record"
    status = reader_result.get("status")
    if status in ASSESSMENT_OUTCOMES:
        return None, "invalid_record"
    if status == "verification_failed":
        code = reader_result.get("failureCode")
        if failure_code is not None and failure_code != code:
            return None, "invalid_record"
        if code not in TECHNICAL_FAILURE_CODES:
            return None, "invalid_record"
        if reader_result.get("checks") is not None or reader_result.get("manifests") not in (None, []):
            return None, "invalid_record"
        return _technical_result(code), None
    if status not in CREDENTIAL_STATUSES:
        return None, "invalid_record"
    if not policy_present:
        return None, "invalid_record"
    if "failureCode" in reader_result and reader_result.get("failureCode") is not None:
        return None, "invalid_record"
    if failure_code is not None:
        return None, "invalid_record"
    manifests = _manifests(reader_result.get("manifests"), status, reader_result.get("checks"))
    if manifests is None:
        return None, "invalid_record"
    checks = _checks_for(status, reader_result.get("checks"), manifests)
    if checks is False:
        return None, "invalid_record"
    return {
        "kind": "credential",
        "status": status,
        "failureCode": None,
        "checks": checks,
        "manifests": manifests,
    }, None


def _technical_result(code: str) -> dict:
    return {
        "kind": "technical",
        "status": "verification_failed",
        "failureCode": code,
        "checks": None,
        "manifests": [],
    }


def _exact_result(value, policy_present: bool):
    if not isinstance(value, Mapping) or set(value) != _RESULT_KEYS:
        return None
    kind = value.get("kind")
    status = value.get("status")
    code = value.get("failureCode")
    if kind == "technical":
        if status != "verification_failed" or code not in TECHNICAL_FAILURE_CODES:
            return None
        if value.get("checks") is not None or value.get("manifests") != []:
            return None
        return _technical_result(code)
    if kind != "credential" or not policy_present:
        return None
    if status not in CREDENTIAL_STATUSES or code is not None:
        return None
    if code in TECHNICAL_FAILURE_CODES:
        return None
    manifests = _manifests(value.get("manifests"), status, value.get("checks"))
    if manifests is None:
        return None
    checks = _checks_for(status, value.get("checks"), manifests)
    if checks is False:
        return None
    return {
        "kind": "credential",
        "status": status,
        "failureCode": None,
        "checks": checks,
        "manifests": manifests,
    }


def _checks_for(status: str, checks, manifests: list):
    if status in {"no_credentials", "not_performed"}:
        if checks is not None or manifests != []:
            return False
        return None
    if len(manifests) > 1:
        if checks is not None:
            return False
        return None
    cleaned = _exact_checks(checks)
    if cleaned is None:
        return False
    if manifests == []:
        if status != "credentials_malformed" or cleaned != UNCHECKED:
            return False
        return cleaned
    if cleaned != manifests[0]["checks"] or status != manifests[0]["status"]:
        return False
    return cleaned


def _exact_checks(value):
    if not isinstance(value, Mapping) or set(value) != set(CHECK_VALUES):
        return None
    cleaned = {}
    for name, allowed in CHECK_VALUES.items():
        item = value.get(name)
        if item not in allowed:
            return None
        cleaned[name] = item
    return cleaned


def _manifests(value, status: str, _checks):
    if value is None:
        if status == "not_performed":
            return []
        return None
    if not isinstance(value, list) or len(value) > _MAX_MANIFESTS:
        return None
    cleaned = []
    labels = []
    for item in value:
        if not isinstance(item, Mapping) or set(item) != _MANIFEST_KEYS:
            return None
        label = item.get("label")
        role = item.get("role")
        manifest_status = item.get("status")
        if not isinstance(label, str) or _LABEL.fullmatch(label) is None or label in labels:
            return None
        if role not in MANIFEST_ROLES or manifest_status not in MANIFEST_STATUSES:
            return None
        checks = _exact_checks(item.get("checks"))
        if checks is None:
            return None
        labels.append(label)
        cleaned.append({
            "label": label,
            "role": role,
            "status": manifest_status,
            "checks": checks,
        })
    if not cleaned:
        return []
    if cleaned[0]["role"] != "active":
        return None
    if any(item["role"] == "active" for item in cleaned[1:]):
        return None
    if [item["label"] for item in cleaned[1:]] != sorted(item["label"] for item in cleaned[1:]):
        return None
    if len(cleaned) > 1 and status != _aggregate(cleaned):
        return None
    return cleaned


def _aggregate(entries: list[dict]) -> str:
    statuses = [item["status"] for item in entries]
    if "credentials_malformed" in statuses:
        return "credentials_malformed"
    if "credentials_invalid" in statuses:
        return "credentials_invalid"
    if "credentials_untrusted" in statuses:
        return "credentials_untrusted"
    if statuses and all(item == "credentials_trusted" for item in statuses):
        return "credentials_trusted"
    return "credentials_malformed"


def _project_result(result: dict) -> dict:
    manifests = []
    for item in result["manifests"]:
        manifests.append({
            "label": item["label"],
            "role": item["role"],
            "status": item["status"],
            "checks": dict(item["checks"]),
        })
    checks = None if result["checks"] is None else dict(result["checks"])
    return {
        "kind": result["kind"],
        "status": result["status"],
        "failureCode": result["failureCode"],
        "checks": checks,
        "manifests": manifests,
    }


def _pem_leaks(value) -> bool:
    if value is None:
        return False
    if not isinstance(value, str):
        return True
    return "PRIVATE KEY" in value


def _leaks(value) -> bool:
    if isinstance(value, Mapping):
        return any(_leaks(key) or _leaks(item) for key, item in value.items())
    if isinstance(value, list):
        return any(_leaks(item) for item in value)
    if isinstance(value, str):
        return any(marker in value for marker in _LEAK_MARKERS)
    return False


def _forbidden_key(value) -> bool:
    if isinstance(value, Mapping):
        if any(key in _FORBIDDEN_KEYS for key in value):
            return True
        return any(_forbidden_key(item) for item in value.values())
    if isinstance(value, list):
        return any(_forbidden_key(item) for item in value)
    return False
