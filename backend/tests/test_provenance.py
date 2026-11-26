"""Provenance records are built from in-memory fixtures.

These tests do not open a ledger, read environment files, or contact a
network. Bundle text exists only inside the test process.
"""

import copy

from app.provenance import (
    CREDENTIAL_STATUSES,
    EVENT_DEPICTION,
    HISTORICAL_STATUS,
    HISTORICAL_VERSION,
    NATIVE_LIBRARY_VERSION,
    READER_VERSION,
    RECORD_VERSION,
    TECHNICAL_FAILURE_CODES,
    build_provenance_record,
    public_provenance,
    reject_client_provenance,
    validate_provenance_record,
)
from app.trust_store import ASSESSMENT_OUTCOMES, FAILURE_CODES

WHEN = "2026-11-20T00:00:00Z"
IMAGE = {
    "sha256": "ab" * 32,
    "byteLength": 128,
    "mediaType": "image/jpeg",
}
MANIFEST_PEM = "-----BEGIN CERTIFICATE-----\nTUFOSUZFU1Q=\n-----END CERTIFICATE-----\n"
TIMESTAMP_PEM = "-----BEGIN CERTIFICATE-----\nVElNRVNUQU1Q\n-----END CERTIFICATE-----\n"
PRIVATE_PEM = "-----BEGIN PRIVATE KEY-----\nU0VDUkVU\n-----END PRIVATE KEY-----\n"


def _checks(**overrides):
    checks = {
        "signature": "valid",
        "assetBinding": "bound",
        "certificateTrust": "trusted",
        "certificateValidity": "inside_at_asserted_time",
        "revocation": "not_revoked",
        "timestamp": "trusted",
    }
    checks.update(overrides)
    return checks


def _unchecked():
    return {name: "not_checked" for name in _checks()}


def _manifest(status, checks, label="urn:c2pa:active", role="active"):
    return {"label": label, "role": role, "status": status, "checks": checks}


def _reader(status, checks, manifests):
    body = {
        "version": READER_VERSION,
        "status": status,
        "actions": [],
        "actionsWithheld": True,
    }
    if status == "not_performed":
        body["checks"] = None
        return body
    body["checks"] = checks
    body["manifests"] = manifests
    return body


def _build(status="credentials_trusted", **overrides):
    checks = _checks()
    if status == "credentials_invalid":
        checks = _checks(signature="invalid", assetBinding="mismatch")
    elif status == "credentials_untrusted":
        checks = _checks(certificateTrust="untrusted")
    elif status == "credentials_malformed":
        checks = _unchecked()
    arguments = {
        "sha256": IMAGE["sha256"],
        "byte_length": IMAGE["byteLength"],
        "media_type": IMAGE["mediaType"],
        "verified_at": WHEN,
        "release_sequence": 4,
        "activation_digest": "cd" * 32,
        "suspension_digest": "ef" * 32,
        "manifest_trust_pem": MANIFEST_PEM,
        "timestamp_trust_pem": TIMESTAMP_PEM,
        "root_use": "verify-only",
        "purpose": "suspension",
        "reader_result": _reader(
            status,
            None if status in {"no_credentials", "not_performed"} else checks,
            [] if status in {"no_credentials", "credentials_malformed"} else [_manifest(status, checks)],
        ),
    }
    if status == "not_performed":
        arguments["media_type"] = "image/gif"
        arguments["reader_result"] = _reader(status, None, None)
    arguments.update(overrides)
    return build_provenance_record(**arguments)


def _assert_rejected(result, code):
    assert result["ok"] is False
    assert result["failureCode"] == code
    assert "record" not in result
    rendered = str(result)
    assert "BEGIN CERTIFICATE" not in rendered
    assert "PRIVATE KEY" not in rendered
    assert "U0VDUkVU" not in rendered


def test_credential_record_keeps_policy_and_discards_bundles():
    built = _build()
    assert built["ok"] is True
    record = built["record"]
    assert record["version"] == RECORD_VERSION
    assert record["verifiedAt"] == WHEN
    assert record["image"] == IMAGE
    assert record["reader"] == {
        "readerVersion": READER_VERSION,
        "nativeLibraryVersion": NATIVE_LIBRARY_VERSION,
    }
    policy = record["policy"]
    assert policy["releaseSequence"] == 4
    assert policy["activationDigest"] == "cd" * 32
    assert policy["suspensionDigest"] == "ef" * 32
    assert policy["rootUse"] == "verify-only"
    assert policy["purpose"] == "suspension"
    assert policy["manifestBundleSha256"] != policy["timestampBundleSha256"]
    rendered = str(record)
    assert "BEGIN CERTIFICATE" not in rendered
    assert "TUFOSUZFU1Q" not in rendered
    assert "VElNRVNUQU1Q" not in rendered
    assert "actions" not in record["result"]
    assert record["result"]["kind"] == "credential"
    assert record["result"]["failureCode"] is None
    assert "assessment" not in record
    checked = validate_provenance_record(record, IMAGE)
    assert checked["ok"] is True
    assert checked["record"] == record
    assert checked["record"] is not record


def test_every_credential_status_is_accepted():
    seen = set()
    for status in CREDENTIAL_STATUSES:
        built = _build(status)
        assert built["ok"] is True, status
        assert built["record"]["result"]["status"] == status
        assert built["record"]["result"]["kind"] == "credential"
        assert built["record"]["result"]["status"] not in ASSESSMENT_OUTCOMES
        image = dict(IMAGE)
        if status == "not_performed":
            image["mediaType"] = "image/gif"
        checked = validate_provenance_record(built["record"], image)
        assert checked["ok"] is True, status
        assert checked["record"] == built["record"]
        seen.add(status)
    assert seen == {
        "credentials_trusted",
        "credentials_untrusted",
        "credentials_invalid",
        "credentials_malformed",
        "no_credentials",
        "not_performed",
    }


def test_technical_failure_records_cover_every_known_code():
    assert "trust_configuration" in FAILURE_CODES
    seen = set()
    for code in TECHNICAL_FAILURE_CODES:
        built = build_provenance_record(
            sha256=IMAGE["sha256"],
            byte_length=IMAGE["byteLength"],
            media_type=IMAGE["mediaType"],
            verified_at=WHEN,
            failure_code=code,
        )
        assert built["ok"] is True, code
        result = built["record"]["result"]
        assert result == {
            "kind": "technical",
            "status": "verification_failed",
            "failureCode": code,
            "checks": None,
            "manifests": [],
        }
        assert built["record"]["policy"] is None
        assert result["status"] not in ASSESSMENT_OUTCOMES
        seen.add(code)
    assert seen == TECHNICAL_FAILURE_CODES
    pinned = _build(
        failure_code="reader_timeout",
        reader_result={
            "version": READER_VERSION,
            "status": "verification_failed",
            "failureCode": "reader_timeout",
            "checks": None,
            "manifests": [],
            "actions": [],
            "actionsWithheld": True,
        },
    )
    assert pinned["ok"] is True
    assert pinned["record"]["policy"]["releaseSequence"] == 4
    assert pinned["record"]["result"]["manifests"] == []
    assert pinned["record"]["result"]["checks"] is None


def test_invalid_hashes_lengths_and_identity_are_rejected():
    _assert_rejected(_build(sha256="AB" * 32), "invalid_record")
    _assert_rejected(_build(sha256="ab" * 31), "invalid_record")
    _assert_rejected(_build(byte_length=True), "invalid_record")
    _assert_rejected(_build(byte_length=-1), "invalid_record")
    _assert_rejected(_build(media_type="image/tiff"), "invalid_record")
    _assert_rejected(_build(verified_at="2026-11-20T00:00:00+00:00"), "invalid_record")
    _assert_rejected(_build(activation_digest="CD" * 32), "invalid_record")
    _assert_rejected(_build(release_sequence=True), "invalid_record")
    _assert_rejected(_build(release_sequence=0), "invalid_record")
    _assert_rejected(_build(root_use="active-again"), "invalid_record")
    _assert_rejected(_build(purpose="emergency"), "invalid_record")
    _assert_rejected(
        _build(manifest_bundle_sha256="11" * 32, manifest_trust_pem=MANIFEST_PEM),
        "invalid_record",
    )
    built = _build()
    record = built["record"]
    _assert_rejected(validate_provenance_record(record, {**IMAGE, "sha256": "ff" * 32}), "identity_mismatch")
    _assert_rejected(validate_provenance_record(record, {**IMAGE, "byteLength": 129}), "identity_mismatch")
    _assert_rejected(validate_provenance_record(record, {**IMAGE, "mediaType": "image/png"}), "identity_mismatch")
    _assert_rejected(validate_provenance_record(record, {"sha256": IMAGE["sha256"]}), "invalid_record")


def test_missing_and_unexpected_fields_are_rejected():
    built = _build()
    record = copy.deepcopy(built["record"])
    del record["verifiedAt"]
    _assert_rejected(validate_provenance_record(record, IMAGE), "invalid_record")
    extra = copy.deepcopy(built["record"])
    extra["note"] = "added later"
    _assert_rejected(validate_provenance_record(extra, IMAGE), "invalid_record")
    result = copy.deepcopy(built["record"])
    result["result"]["actions"] = []
    _assert_rejected(validate_provenance_record(result, IMAGE), "invalid_record")
    _assert_rejected(_build(reader_result=None, failure_code=None), "invalid_record")
    partial = _build(root_use=None)
    _assert_rejected(partial, "invalid_record")
    _assert_rejected(_build(reader_result={"version": READER_VERSION, "status": "credentials_trusted"}), "invalid_record")


def test_invalid_status_combinations_are_rejected():
    trusted = _reader("credentials_trusted", _checks(), [_manifest("credentials_trusted", _checks())])
    trusted["failureCode"] = "reader_timeout"
    _assert_rejected(_build(reader_result=trusted), "invalid_record")
    technical = {
        "version": READER_VERSION,
        "status": "verification_failed",
        "failureCode": "reader_crash",
        "checks": _checks(),
        "manifests": [],
        "actions": [],
        "actionsWithheld": True,
    }
    _assert_rejected(_build(reader_result=technical, failure_code="reader_crash"), "invalid_record")
    technical["checks"] = None
    technical["manifests"] = [_manifest("credentials_trusted", _checks())]
    _assert_rejected(_build(reader_result=technical, failure_code="reader_crash"), "invalid_record")
    _assert_rejected(
        build_provenance_record(
            sha256=IMAGE["sha256"],
            byte_length=IMAGE["byteLength"],
            media_type=IMAGE["mediaType"],
            verified_at=WHEN,
            failure_code="credentials_trusted",
        ),
        "invalid_record",
    )
    no_policy = _build(release_sequence=None, activation_digest=None, suspension_digest=None,
                       manifest_trust_pem=None, timestamp_trust_pem=None, root_use=None, purpose=None)
    _assert_rejected(no_policy, "invalid_record")
    absent = _reader("no_credentials", None, [_manifest("credentials_trusted", _checks())])
    _assert_rejected(_build(reader_result=absent), "invalid_record")


def test_assessment_outcomes_are_not_credential_statuses():
    for outcome in ASSESSMENT_OUTCOMES:
        reader = _reader(outcome, _checks(), [_manifest("credentials_trusted", _checks())])
        reader["status"] = outcome
        _assert_rejected(_build(reader_result=reader), "invalid_record")
        _assert_rejected(
            build_provenance_record(
                sha256=IMAGE["sha256"],
                byte_length=IMAGE["byteLength"],
                media_type=IMAGE["mediaType"],
                verified_at=WHEN,
                failure_code=outcome,
            ),
            "invalid_record",
        )


def test_pem_certificate_and_secret_text_does_not_leave_the_builder():
    built = _build()
    rendered = str(built)
    assert "BEGIN CERTIFICATE" not in rendered
    assert "PRIVATE KEY" not in rendered
    rejected = build_provenance_record(
        sha256=IMAGE["sha256"],
        byte_length=IMAGE["byteLength"],
        media_type=IMAGE["mediaType"],
        verified_at=WHEN,
        release_sequence=1,
        activation_digest="cd" * 32,
        suspension_digest="ef" * 32,
        manifest_trust_pem=PRIVATE_PEM,
        timestamp_trust_pem=TIMESTAMP_PEM,
        root_use="active",
        purpose="policy",
        reader_result=_reader("no_credentials", None, []),
    )
    _assert_rejected(rejected, "leaked_material")
    poisoned = copy.deepcopy(built["record"])
    poisoned["result"]["manifests"][0]["label"] = "-----BEGIN CERTIFICATE-----"
    _assert_rejected(validate_provenance_record(poisoned, IMAGE), "leaked_material")
    stored = copy.deepcopy(built["record"])
    stored["policy"]["manifestTrustPem"] = MANIFEST_PEM
    _assert_rejected(validate_provenance_record(stored, IMAGE), "leaked_material")


def test_client_supplied_provenance_is_rejected():
    built = _build()
    _assert_rejected(reject_client_provenance(built["record"]), "client_provenance")
    _assert_rejected(reject_client_provenance({"c2pa": "credentials_trusted", "pem": MANIFEST_PEM}), "client_provenance")
    _assert_rejected(reject_client_provenance(None), "client_provenance")


def test_records_are_not_rewritten_and_projection_is_allowlisted():
    reader = _reader("credentials_trusted", _checks(), [_manifest("credentials_trusted", _checks())])
    built = _build(reader_result=reader)
    record = built["record"]
    original = copy.deepcopy(record)
    reader["checks"]["signature"] = "invalid"
    reader["manifests"][0]["checks"]["signature"] = "invalid"
    assert record == original
    record["image"]["sha256"] = "00" * 32
    checked = validate_provenance_record(original, IMAGE)
    assert checked["record"]["image"]["sha256"] == IMAGE["sha256"]
    assert original["image"]["sha256"] == IMAGE["sha256"]
    historical = public_provenance(None)
    assert historical == {
        "version": HISTORICAL_VERSION,
        "status": HISTORICAL_STATUS,
        "eventDepiction": EVENT_DEPICTION,
    }
    assert historical["version"] != RECORD_VERSION
    projected = public_provenance(original, IMAGE)
    assert projected["eventDepiction"] == EVENT_DEPICTION
    assert projected["result"]["status"] == "credentials_trusted"
    assert projected["result"]["kind"] == "credential"
    assert set(projected) == {
        "version",
        "verifiedAt",
        "image",
        "reader",
        "policy",
        "result",
        "eventDepiction",
    }
    assert "actions" not in projected["result"]
    assert "BEGIN CERTIFICATE" not in str(projected)
    unreadable = public_provenance({"version": "c2pa-provenance-1", "pem": PRIVATE_PEM}, IMAGE)
    assert unreadable["result"]["kind"] == "technical"
    assert unreadable["result"]["status"] == "verification_failed"
    assert unreadable["result"]["manifests"] == []
    assert "PRIVATE KEY" not in str(unreadable)
    assert "U0VDUkVU" not in str(unreadable)
    assert public_provenance(original, None)["result"]["failureCode"] == "trust_configuration"


def test_multiple_manifests_keep_the_reader_aggregate():
    trusted = _checks()
    untrusted = _checks(certificateTrust="untrusted")
    reader = _reader("credentials_untrusted", None, [
        _manifest("credentials_trusted", trusted, "urn:c2pa:active"),
        _manifest("credentials_untrusted", untrusted, "urn:c2pa:ingredient", "ingredient"),
    ])
    built = _build(reader_result=reader)
    assert built["ok"] is True
    assert built["record"]["result"]["checks"] is None
    assert built["record"]["result"]["status"] == "credentials_untrusted"
    reversed_reader = _reader("credentials_untrusted", None, [
        _manifest("credentials_trusted", trusted, "urn:c2pa:active"),
        _manifest("credentials_untrusted", untrusted, "urn:c2pa:z", "ingredient"),
        _manifest("credentials_untrusted", untrusted, "urn:c2pa:a", "ingredient"),
    ])
    _assert_rejected(_build(reader_result=reversed_reader), "invalid_record")
