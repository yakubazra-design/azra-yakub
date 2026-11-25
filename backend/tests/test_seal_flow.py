"""Seal orchestration. Temporary files and databases only.

The reader and trust store are injected. Nothing here opens the live ledger,
contacts a network, or sends provenance to the assessment prompt.
"""

import hashlib
import json
import os
import sqlite3
import struct
import threading
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from secrets import token_hex

import pytest

from app.assetstore import AssetStore
from app.c2pa_reader import VERIFICATION_SETTINGS
from app.c2pa_statuses import ASSESSMENT_OUTCOMES
from app.images import IMAGE_CONSENT_VERSION
from app.ledger import Ledger, LedgerError
from app.prompts import assess_prompt
from app.provenance import READER_VERSION, build_provenance_record
from app.seal_flow import confirm_for_commit, prepare_sealed_provenance
from app.trust_store import failure

WHEN = "2026-11-20T00:00:00Z"
MANIFEST = """-----BEGIN CERTIFICATE-----
MIIBgjCCASegAwIBAgIUf98FTbkr9AXqo88d1kMUOTvK+mYwCgYIKoZIzj0EAwIw
FjEUMBIGA1UEAwwLcmMtbWFuaWZlc3QwHhcNMjYxMTIxMDU0OTAyWhcNMzYxMTE4
MDU0OTAyWjAWMRQwEgYDVQQDDAtyYy1tYW5pZmVzdDBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABIF6zbb0OzJnCynsMdrD6soHz04UdhCfffigXqf2bozdm/xVVQ9Q
LqdXmt3r56SWb5hClqWasZEhTSDy/Ap1TaOjUzBRMB0GA1UdDgQWBBSMVqRAAaX8
kQo02SODHRRg8ck/azAfBgNVHSMEGDAWgBSMVqRAAaX8kQo02SODHRRg8ck/azAP
BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0kAMEYCIQDBZcN9op7D/STyI/Uj
9NyI7VsrnCx7aMpYDtbo3DGhQAIhAKngYjLdHYC8CWfLtTVydr69u4NKMga4JZVH
na/jS6t7
-----END CERTIFICATE-----
"""
TIMESTAMP = """-----BEGIN CERTIFICATE-----
MIIBgzCCASmgAwIBAgIUNVjgWcyuRjRrvsEUwGLo/sW+howwCgYIKoZIzj0EAwIw
FzEVMBMGA1UEAwwMcmMtdGltZXN0YW1wMB4XDTI2MTEyMTA1NDkwMloXDTM2MTEx
ODA1NDkwMlowFzEVMBMGA1UEAwwMcmMtdGltZXN0YW1wMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAE8fcqITlmHdfb/nq3Odanji9b/0YR3LKSHS2G+DPd4a+j5sgp
EBohPaDpOduB/n16sF5PWrz+YVFSpV3fkc7pV6NTMFEwHQYDVR0OBBYEFG4MBpn6
mFx9dAQ3McXdmasR2tSVMB8GA1UdIwQYMBaAFG4MBpn6mFx9dAQ3McXdmasR2tSV
MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgXo/uyybp6wLTqySb
49poci+5KmJjk0lVAM9hsNFEzccCIQDRwIAZyM31nqvIPiDJx7BqpZFqjgvBb18G
453HVEbZxA==
-----END CERTIFICATE-----
"""
MANIFEST_NEXT = """-----BEGIN CERTIFICATE-----
MIIBizCCATGgAwIBAgIUNFZ9RGatu2BBxuTne020Xrx1ZxswCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQcmMtbWFuaWZlc3QtbmV4dDAeFw0yNjExMjEwNTQ5MDJaFw0z
NjExMTgwNTQ5MDJaMBsxGTAXBgNVBAMMEHJjLW1hbmlmZXN0LW5leHQwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAARgLmzZKrgCjLLOtkswRVSEA1OHSIJoJI/Zu0lJ
BkSBkF+HSOC2bl9dJQBAa+7yESMfD7jc9ycFruxc2Ny6CByvo1MwUTAdBgNVHQ4E
FgQUqy9NAq74MXLOOq9loINq2Aa9dzMwHwYDVR0jBBgwFoAUqy9NAq74MXLOOq9l
oINq2Aa9dzMwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEA33nN
1yepCwRThS+pMk0EbupBZRgW2z9qREaEkUdazA0CIAxW5RtIIWd+/k8pbZcEgU16
WTcR9JiR1lHLB419z7E9
-----END CERTIFICATE-----
"""
TIMESTAMP_NEXT = """-----BEGIN CERTIFICATE-----
MIIBjTCCATOgAwIBAgIUBOSBYAsTyl3vxbEnr5J4CR4b090wCgYIKoZIzj0EAwIw
HDEaMBgGA1UEAwwRcmMtdGltZXN0YW1wLW5leHQwHhcNMjYxMTIxMDU0OTAyWhcN
MzYxMTE4MDU0OTAyWjAcMRowGAYDVQQDDBFyYy10aW1lc3RhbXAtbmV4dDBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABJWPoASgc95Bxbllml6pRy2X2ulTqS26vVv2
AwTllomT3MYCaFLU9gXjCVO70b4CdiYNIUEas6vclxL8rT/G31OjUzBRMB0GA1Ud
DgQWBBRCnpKXxdrbk9RVq7jkraPV5wPwCTAfBgNVHSMEGDAWgBRCnpKXxdrbk9RV
q7jkraPV5wPwCTAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQDE
ATqhsjaN4hcTcfI0vE53LCq46TzBCVEEDPxX4jxq4AIgPcq45vVlmyuEVHqD+qhn
lEpUGoMFmcpcRV0pHT4RPyY=
-----END CERTIFICATE-----
"""
ACTIVATION = "ab" * 32
SUSPENSION = "cd" * 32
ACTIVATION_NEXT = "11" * 32
SUSPENSION_NEXT = "22" * 32


def _png() -> bytes:
    def chunk(tag: bytes, payload: bytes) -> bytes:
        crc = zlib.crc32(tag + payload) & 0xFFFFFFFF
        return struct.pack(">I", len(payload)) + tag + payload + struct.pack(">I", crc)

    header = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    pixels = zlib.compress(b"\x00\xff\x00\x00")
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", pixels) + chunk(b"IEND", b"")


def _gif() -> bytes:
    return (
        b"GIF89a"
        + b"\x01\x00\x01\x00\x80\x00\x00\xff\x00\x00\x00\x00\x00"
        + b"!\xf9\x04\x00\x00\x00\x00\x00"
        + b",\x00\x00\x00\x00\x01\x00\x01\x00\x00"
        + b"\x02\x02D\x01\x00;"
    )


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _text_sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _plant(tmp_path: Path, payload: bytes) -> tuple[Path, str, str]:
    directory = tmp_path / "assets"
    directory.mkdir(mode=0o700, parents=True)
    storage = token_hex(16) + ".bin"
    path = directory / storage
    path.write_bytes(payload)
    os.chmod(path, 0o600)
    return directory, storage, _sha(payload)


class Store:
    def __init__(self, pins, selects=(), decisions=()):
        self.pins = list(pins)
        self.selects = list(selects)
        self.decisions = list(decisions)
        self.revalidated = []

    def pin(self):
        return self.pins.pop(0)

    def select(self):
        return self.selects.pop(0)

    def revalidate(self, pinned):
        self.revalidated.append(pinned)
        return self.decisions.pop(0)


class Reader:
    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    def __call__(self, data, *, manifest_trust_pem, timestamp_trust_pem, settings):
        self.calls.append({
            "data": bytes(data),
            "manifest": manifest_trust_pem,
            "timestamp": timestamp_trust_pem,
            "settings": dict(settings),
        })
        result = self.results.pop(0)
        if callable(result):
            return result(data)
        return result


def _pin(sequence, manifest, timestamp, activation=ACTIVATION, suspension=SUSPENSION):
    return {
        "status": "pinned",
        "failureCode": None,
        "credentialStatus": None,
        "assessment": None,
        "releaseSequence": sequence,
        "activationDigest": activation,
        "suspensionDigest": suspension,
        "manifestTrustPem": manifest,
        "timestampTrustPem": timestamp,
    }


def _select(
    sequence,
    manifest,
    timestamp,
    activation=ACTIVATION,
    suspension=SUSPENSION,
    root_use="active",
    purpose="policy",
):
    selected = _pin(sequence, manifest, timestamp, activation, suspension)
    selected["status"] = "selected"
    selected["rootUse"] = root_use
    selected["purpose"] = purpose
    return selected


def _confirmed(sequence, activation=ACTIVATION):
    return {
        "status": "confirmed",
        "failureCode": None,
        "credentialStatus": None,
        "assessment": None,
        "releaseSequence": sequence,
        "activationDigest": activation,
    }


def _checks(**overrides):
    values = {
        "signature": "valid",
        "assetBinding": "bound",
        "certificateTrust": "trusted",
        "certificateValidity": "inside_at_asserted_time",
        "revocation": "not_revoked",
        "timestamp": "trusted",
    }
    values.update(overrides)
    return values


def _unchecked():
    return {name: "not_checked" for name in _checks()}


def _manifest(status, checks, label="urn:c2pa:active"):
    return {"label": label, "role": "active", "status": status, "checks": checks}


def _credential(status, checks=None, manifests=None, label="urn:c2pa:active"):
    if status == "credentials_malformed":
        checks = _unchecked()
        manifests = []
    elif status in {"no_credentials", "not_performed"}:
        checks = None
        manifests = [] if status == "no_credentials" else None
    elif checks is None:
        checks = _checks()
    if manifests is None and status not in {"no_credentials", "not_performed"}:
        manifests = [_manifest(status, checks, label)]
    body = {
        "version": READER_VERSION,
        "status": status,
        "checks": checks,
        "actions": [],
        "actionsWithheld": True,
    }
    if manifests is not None:
        body["manifests"] = manifests
    return body


def _technical_reader(code):
    return {
        "version": READER_VERSION,
        "status": "verification_failed",
        "failureCode": code,
        "checks": None,
        "manifests": [],
        "actions": [],
        "actionsWithheld": True,
    }


def _store_for(*sequences):
    pins = []
    selects = []
    decisions = []
    bundles = (
        (MANIFEST, TIMESTAMP, ACTIVATION, SUSPENSION),
        (MANIFEST_NEXT, TIMESTAMP_NEXT, ACTIVATION_NEXT, SUSPENSION_NEXT),
    )
    for index, sequence in enumerate(sequences):
        manifest, timestamp, activation, suspension = bundles[index]
        pins.append(_pin(sequence, manifest, timestamp, activation, suspension))
        selects.append(_select(sequence, manifest, timestamp, activation, suspension))
        decisions.append(_confirmed(sequence, activation))
        selects.append(_select(sequence, manifest, timestamp, activation, suspension))
    return Store(pins, selects, decisions)


def _run(directory, storage, digest, payload, media, store, reader, **overrides):
    arguments = {
        "asset_directory": directory,
        "storage_name": storage,
        "sha256": digest,
        "byte_length": len(payload),
        "media_type": media,
        "trust_store": store,
        "reader": reader,
        "verified_at": WHEN,
    }
    arguments.update(overrides)
    return prepare_sealed_provenance(**arguments)


def _assert_offline(call, payload):
    assert call["data"] == payload
    assert call["settings"] == dict(VERIFICATION_SETTINGS)
    assert call["settings"]["verify.remote_manifest_fetch"] is False
    assert call["settings"]["verify.ocsp_fetch"] is False
    assert call["settings"]["verify.ocsp_fetch_should_override"] is False


def _assert_no_secret(record):
    raw = json.dumps(record)
    assert "BEGIN CERTIFICATE" not in raw
    assert "PRIVATE KEY" not in raw
    assert "POTENTIAL_MANIPULATION" not in raw
    assert record["result"]["status"] not in ASSESSMENT_OUTCOMES
    assert record["result"]["failureCode"] not in ASSESSMENT_OUTCOMES


def test_credential_results_keep_their_status_and_drop_the_bundles(tmp_path):
    payload = _png()
    directory, storage, digest = _plant(tmp_path, payload)
    cases = {
        "credentials_trusted": _checks(),
        "credentials_untrusted": _checks(certificateTrust="untrusted"),
        "credentials_invalid": _checks(signature="invalid"),
        "credentials_malformed": None,
        "no_credentials": None,
    }
    for status, checks in cases.items():
        store = _store_for(4)
        reader = Reader([_credential(status, checks, label=f"urn:c2pa:{status}")])
        result = _run(directory, storage, digest, payload, "image/png", store, reader)
        record = result["provenance"]
        assert result["status"] == "ready"
        assert record["result"]["status"] == status
        assert record["result"]["kind"] == "credential"
        assert record["policy"]["releaseSequence"] == 4
        assert record["policy"]["manifestBundleSha256"] == _text_sha(MANIFEST)
        assert record["policy"]["timestampBundleSha256"] == _text_sha(TIMESTAMP)
        assert record["image"]["sha256"] == digest
        _assert_no_secret(record)
        _assert_offline(reader.calls[0], payload)
        assert reader.calls[0]["manifest"] == MANIFEST
        assert reader.calls[0]["timestamp"] == TIMESTAMP


def test_unsupported_format_is_not_performed(tmp_path):
    payload = _gif()
    directory, storage, digest = _plant(tmp_path, payload)
    store = _store_for(2)
    reader = Reader([_credential("not_performed")])
    result = _run(directory, storage, digest, payload, "image/gif", store, reader)
    assert result["provenance"]["result"]["status"] == "not_performed"
    assert result["provenance"]["result"]["checks"] is None
    assert result["provenance"]["result"]["manifests"] == []
    _assert_offline(reader.calls[0], payload)
    _assert_no_secret(result["provenance"])


def test_trust_store_and_reader_failures_stay_technical(tmp_path):
    payload = _png()
    directory, storage, digest = _plant(tmp_path, payload)
    refusals = (
        failure("no_committed_policy"),
        failure("trust_configuration"),
        failure("activation_record_corrupt"),
        failure("witness_corrupt"),
    )
    for refusal in refusals:
        store = Store([refusal])
        reader = Reader([_credential("credentials_trusted")])
        result = _run(directory, storage, digest, payload, "image/png", store, reader)
        assert result["status"] == "ready"
        assert result["provenance"]["result"]["kind"] == "technical"
        assert result["provenance"]["result"]["status"] == "verification_failed"
        assert result["provenance"]["result"]["failureCode"] == refusal["failureCode"]
        assert result["provenance"]["policy"] is None
        assert reader.calls == []
        _assert_no_secret(result["provenance"])

    for code in ("reader_timeout", "reader_crash"):
        store = _store_for(2)
        reader = Reader([_technical_reader(code)])
        result = _run(directory, storage, digest, payload, "image/png", store, reader)
        assert result["provenance"]["result"]["failureCode"] == code
        assert result["provenance"]["result"]["kind"] == "technical"
        assert result["provenance"]["policy"]["releaseSequence"] == 2
        assert len(reader.calls) == 1
        _assert_no_secret(result["provenance"])


def test_image_identity_is_checked_before_and_after_the_reader(tmp_path):
    payload = _png()
    directory, storage, digest = _plant(tmp_path, payload)
    store = _store_for(2)
    reader = Reader([_credential("credentials_trusted", label="urn:c2pa:should-not-run")])
    before = _run(
        directory,
        storage,
        "ab" * 32,
        payload,
        "image/png",
        store,
        reader,
        untrusted_client_sha256=digest,
    )
    assert before == {"status": "aborted", "provenance": None, "failureCode": "identity_mismatch"}
    assert reader.calls == []
    assert store.pins

    path = directory / storage
    def tamper(_data):
        path.write_bytes(b"\x00" * len(payload))
        return _credential("credentials_trusted", label="urn:c2pa:stale")

    store = _store_for(2)
    reader = Reader([tamper])
    after = _run(directory, storage, digest, payload, "image/png", store, reader)
    assert after["status"] == "aborted"
    assert after["provenance"] is None
    assert len(reader.calls) == 1
    assert store.decisions
    assert "stale" not in json.dumps(after)

    mismatched = _plant(tmp_path / "type", payload)
    store = _store_for(2)
    reader = Reader([_credential("credentials_trusted")])
    typed = _run(mismatched[0], mismatched[1], mismatched[2], payload, "image/jpeg", store, reader)
    assert typed["status"] == "aborted"
    assert reader.calls == []


def test_superseded_policy_is_retried_once_and_the_stale_result_is_discarded(tmp_path):
    payload = _png()
    directory, storage, digest = _plant(tmp_path, payload)
    store = _store_for(2, 5)
    store.decisions[0] = failure("policy_superseded", releaseSequence=5)
    del store.selects[1]  # revalidation fails before the confirmation select
    store.pins.append(_pin(9, MANIFEST, TIMESTAMP))
    reader = Reader([
        _credential("credentials_trusted", label="urn:c2pa:stale-policy"),
        _credential("no_credentials"),
    ])
    result = _run(directory, storage, digest, payload, "image/png", store, reader)
    record = result["provenance"]
    assert record["policy"]["releaseSequence"] == 5
    assert record["policy"]["activationDigest"] == ACTIVATION_NEXT
    assert record["policy"]["manifestBundleSha256"] == _text_sha(MANIFEST_NEXT)
    assert record["result"]["status"] == "no_credentials"
    raw = json.dumps(record)
    assert "stale-policy" not in raw
    assert "BEGIN CERTIFICATE" not in raw
    assert len(reader.calls) == 2
    assert reader.calls[0]["manifest"] == MANIFEST
    assert reader.calls[1]["manifest"] == MANIFEST_NEXT
    assert store.pins
    assert len(store.revalidated) == 2


def test_a_second_authorization_failure_discards_both_readings(tmp_path):
    payload = _png()
    directory, storage, digest = _plant(tmp_path, payload)
    store = Store(
        [
            _pin(2, MANIFEST, TIMESTAMP),
            failure("witness_unavailable"),
            _pin(8, MANIFEST_NEXT, TIMESTAMP_NEXT, ACTIVATION_NEXT, SUSPENSION_NEXT),
        ],
        [_select(2, MANIFEST, TIMESTAMP)],
        [failure("root_suspended")],
    )
    reader = Reader([_credential("credentials_trusted", label="urn:c2pa:discard-me")])
    result = _run(directory, storage, digest, payload, "image/png", store, reader)
    record = result["provenance"]
    assert record["result"] == {
        "kind": "technical",
        "status": "verification_failed",
        "failureCode": "witness_unavailable",
        "checks": None,
        "manifests": [],
    }
    assert record["policy"] is None
    assert "discard-me" not in json.dumps(record)
    assert "POTENTIAL_MANIPULATION" not in json.dumps(record)
    assert len(reader.calls) == 1
    assert len(store.pins) == 1


def test_suspension_retries_once_and_a_repeated_suspension_fails_closed(tmp_path):
    payload = _png()
    directory, storage, digest = _plant(tmp_path, payload)
    store = _store_for(2, 6)
    store.decisions[0] = failure("root_suspended")
    del store.selects[1]  # revalidation fails before the confirmation select
    reader = Reader([
        _credential("credentials_trusted", label="urn:c2pa:old-root"),
        _credential("credentials_untrusted", _checks(certificateTrust="untrusted"), label="urn:c2pa:new-root"),
    ])
    result = _run(directory, storage, digest, payload, "image/png", store, reader)
    assert result["provenance"]["policy"]["releaseSequence"] == 6
    assert result["provenance"]["result"]["status"] == "credentials_untrusted"
    assert "old-root" not in json.dumps(result)

    blocked = Store(
        [_pin(2, MANIFEST, TIMESTAMP), failure("root_suspended")],
        [_select(2, MANIFEST, TIMESTAMP)],
        [failure("root_suspended")],
    )
    reader = Reader([_credential("credentials_trusted", label="urn:c2pa:suspended-reading")])
    result = _run(directory, storage, digest, payload, "image/png", store=blocked, reader=reader)
    assert result["provenance"]["result"]["failureCode"] == "root_suspended"
    assert result["provenance"]["policy"] is None
    assert "suspended-reading" not in json.dumps(result)
    assert len(reader.calls) == 1


def test_client_provenance_and_client_hashes_are_not_authoritative(tmp_path):
    payload = _png()
    directory, storage, digest = _plant(tmp_path, payload)
    store = _store_for(2)
    reader = Reader([_credential("credentials_trusted")])
    client = {
        "version": "c2pa-provenance-1",
        "policy": {"activationDigest": "99" * 32},
        "result": {"status": "POTENTIAL_MANIPULATION"},
    }
    result = _run(
        directory,
        storage,
        digest,
        payload,
        "image/png",
        store,
        reader,
        client_provenance=client,
        untrusted_client_sha256="ff" * 32,
    )
    raw = json.dumps(result)
    assert "99" * 32 not in raw
    assert "ff" * 32 not in raw
    assert result["provenance"]["image"]["sha256"] == digest
    assert result["provenance"]["result"]["status"] == "credentials_trusted"


def test_a_reader_assessment_outcome_is_not_stored(tmp_path):
    payload = _png()
    directory, storage, digest = _plant(tmp_path, payload)
    store = _store_for(2)
    reader = Reader([{
        "version": READER_VERSION,
        "status": "POTENTIAL_MANIPULATION",
        "checks": None,
        "manifests": [],
        "actions": [],
        "actionsWithheld": True,
    }])
    result = _run(directory, storage, digest, payload, "image/png", store, reader)
    assert result["provenance"]["result"]["failureCode"] == "trust_configuration"
    assert result["provenance"]["result"]["kind"] == "technical"
    assert "POTENTIAL_MANIPULATION" not in json.dumps(result)


def test_provenance_is_not_sent_to_the_assessment_prompt(tmp_path, monkeypatch):
    payload = _png()
    directory, storage, digest = _plant(tmp_path, payload)
    calls = []

    def forbidden(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("The seal workflow called the assessment prompt.")

    monkeypatch.setattr("app.prompts.assess_prompt", forbidden)
    store = _store_for(2)
    reader = Reader([_credential("credentials_trusted", label="urn:c2pa:prompt-secret")])
    result = _run(directory, storage, digest, payload, "image/png", store, reader)
    assert calls == []
    prompt = assess_prompt({
        "primaryClaim": "The event happened.",
        "verifiablePoints": ["The event happened."],
        "sources": [],
        "independence": {},
        "timeline": {},
        "sealedImage": True,
    })
    assert "urn:c2pa:prompt-secret" not in prompt
    assert "credentials_trusted" not in prompt
    assert "BEGIN CERTIFICATE" not in prompt
    assert result["provenance"]["result"]["status"] not in prompt


def test_technical_failure_still_seals_and_an_identity_change_does_not(tmp_path, monkeypatch):
    payload = _png()
    path = tmp_path / "ledger.sqlite"
    ledger = Ledger(path)
    owner = ledger.create_owner()
    investigation = ledger.create_investigation(owner, "claim", "The event happened.")
    storage = AssetStore.for_ledger(path).write(
        token_hex(16), payload, owner_id=owner, investigation_id=investigation,
    )
    digest = _sha(payload)
    assert ledger.save_image_asset(
        owner,
        investigation,
        storage[:-4],
        digest,
        len(payload),
        "image/png",
        "not_supplied",
        storage,
        IMAGE_CONSENT_VERSION,
    )[0] == "saved"
    directory = path.parent / "assets"

    def explode(*_args, **_kwargs):
        raise AssertionError("The C2PA workflow opened a ledger write transaction.")

    monkeypatch.setattr(Ledger, "_transaction", explode)
    store = _store_for(3)
    reader = Reader([_technical_reader("reader_timeout")])
    prepared = _run(directory, storage, digest, payload, "image/png", store, reader)
    assert prepared["status"] == "ready"
    assert prepared["provenance"]["result"]["failureCode"] == "reader_timeout"
    monkeypatch.undo()

    expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    assert ledger.seal_assessment(
        owner,
        investigation,
        "ab" * 32,
        {"primaryClaim": "The event happened."},
        expires,
        provenance=prepared["provenance"],
        authorize=lambda _record: {"ok": True, "failureCode": None},
    )
    connection = sqlite3.connect(path)
    try:
        raw = connection.execute(
            "SELECT snapshot_json FROM assessment_snapshots WHERE investigation_id = ?",
            (investigation,),
        ).fetchone()[0]
    finally:
        connection.close()
    stored = json.loads(raw)
    assert stored["provenance"]["result"]["failureCode"] == "reader_timeout"
    assert stored["sealedAsset"]["sha256"] == digest
    assert "BEGIN CERTIFICATE" not in raw
    assert ledger.create_investigation(owner, "claim", "Another claim.")

    other = tmp_path / "changed"
    changed_dir, changed_name, changed_digest = _plant(other, payload)
    store = _store_for(3)
    reader = Reader([_credential("credentials_trusted")])
    aborted = _run(
        changed_dir,
        changed_name,
        changed_digest,
        payload,
        "image/png",
        store,
        reader,
        sha256="cd" * 32,
    )
    assert aborted["status"] == "aborted"
    assert aborted["provenance"] is None
    assert reader.calls == []


def test_same_sequence_root_use_change_is_not_stored(tmp_path):
    payload = _png()
    directory, storage, digest = _plant(tmp_path, payload)
    store = Store(
        [_pin(4, MANIFEST, TIMESTAMP), _pin(4, MANIFEST, TIMESTAMP)],
        [
            _select(4, MANIFEST, TIMESTAMP, root_use="active"),
            _select(4, MANIFEST, TIMESTAMP, root_use="verify-only"),
            _select(4, MANIFEST, TIMESTAMP, root_use="verify-only"),
            _select(4, MANIFEST, TIMESTAMP, root_use="verify-only"),
        ],
        [_confirmed(4), _confirmed(4)],
    )
    reader = Reader([
        _credential("credentials_trusted", label="urn:c2pa:stale-active"),
        _credential("credentials_trusted", label="urn:c2pa:confirmed-verify-only"),
    ])
    result = _run(directory, storage, digest, payload, "image/png", store, reader)
    record = result["provenance"]
    assert record["policy"]["releaseSequence"] == 4
    assert record["policy"]["rootUse"] == "verify-only"
    assert record["policy"]["purpose"] == "policy"
    assert record["result"]["manifests"][0]["label"] == "urn:c2pa:confirmed-verify-only"
    assert record["policy"]["manifestBundleSha256"] == _text_sha(reader.calls[1]["manifest"])
    raw = json.dumps(record)
    assert "stale-active" not in raw
    assert "BEGIN CERTIFICATE" not in raw
    assert len(reader.calls) == 2
    assert reader.calls[1]["manifest"] == MANIFEST
    assert reader.calls[1]["timestamp"] == TIMESTAMP


def test_purpose_and_selection_mismatch_discard_the_reading(tmp_path):
    payload = _png()
    directory, storage, digest = _plant(tmp_path, payload)
    purpose = Store(
        [_pin(3, MANIFEST, TIMESTAMP), _pin(3, MANIFEST, TIMESTAMP)],
        [
            _select(3, MANIFEST, TIMESTAMP, purpose="policy"),
            _select(3, MANIFEST, TIMESTAMP, purpose="suspension"),
            _select(3, MANIFEST, TIMESTAMP, purpose="suspension"),
            _select(3, MANIFEST, TIMESTAMP, purpose="suspension"),
        ],
        [_confirmed(3), _confirmed(3)],
    )
    reader = Reader([
        _credential("credentials_trusted", label="urn:c2pa:stale-purpose"),
        _credential("credentials_untrusted", _checks(certificateTrust="untrusted"), label="urn:c2pa:confirmed-purpose"),
    ])
    result = _run(directory, storage, digest, payload, "image/png", purpose, reader)
    assert result["provenance"]["policy"]["purpose"] == "suspension"
    assert result["provenance"]["policy"]["rootUse"] == "active"
    assert result["provenance"]["result"]["status"] == "credentials_untrusted"
    assert "stale-purpose" not in json.dumps(result)
    assert len(reader.calls) == 2

    replaced = Store(
        [
            _pin(3, MANIFEST, TIMESTAMP),
            _pin(6, MANIFEST_NEXT, TIMESTAMP_NEXT, ACTIVATION_NEXT, SUSPENSION_NEXT),
        ],
        [
            _select(3, MANIFEST, TIMESTAMP),
            _select(6, MANIFEST_NEXT, TIMESTAMP_NEXT, ACTIVATION_NEXT, SUSPENSION_NEXT),
            _select(6, MANIFEST_NEXT, TIMESTAMP_NEXT, ACTIVATION_NEXT, SUSPENSION_NEXT),
            _select(6, MANIFEST_NEXT, TIMESTAMP_NEXT, ACTIVATION_NEXT, SUSPENSION_NEXT),
        ],
        [_confirmed(3), _confirmed(6, ACTIVATION_NEXT)],
    )
    reader = Reader([
        _credential("credentials_trusted", label="urn:c2pa:stale-selection"),
        _credential("no_credentials"),
    ])
    result = _run(directory, storage, digest, payload, "image/png", replaced, reader)
    record = result["provenance"]
    assert record["policy"]["releaseSequence"] == 6
    assert record["policy"]["manifestBundleSha256"] == _text_sha(MANIFEST_NEXT)
    assert record["policy"]["manifestBundleSha256"] == _text_sha(reader.calls[1]["manifest"])
    assert record["result"]["status"] == "no_credentials"
    assert "stale-selection" not in json.dumps(record)
    assert reader.calls[0]["manifest"] == MANIFEST
    assert reader.calls[1]["manifest"] == MANIFEST_NEXT

    downgraded = Store(
        [
            _pin(3, MANIFEST, TIMESTAMP),
            _pin(9, MANIFEST_NEXT, TIMESTAMP_NEXT, ACTIVATION_NEXT, SUSPENSION_NEXT),
        ],
        [_select(3, MANIFEST, TIMESTAMP), failure("policy_downgrade")],
        [_confirmed(3)],
    )
    reader = Reader([_credential("credentials_trusted", label="urn:c2pa:downgraded-reading")])
    result = _run(directory, storage, digest, payload, "image/png", downgraded, reader)
    assert result["provenance"]["result"]["failureCode"] == "policy_downgrade"
    assert result["provenance"]["policy"] is None
    assert "downgraded-reading" not in json.dumps(result)
    assert len(reader.calls) == 1
    assert len(downgraded.pins) == 1


def test_failed_final_authorization_discards_both_credential_results(tmp_path):
    payload = _png()
    directory, storage, digest = _plant(tmp_path, payload)
    store = Store(
        [
            _pin(4, MANIFEST, TIMESTAMP),
            _pin(4, MANIFEST, TIMESTAMP),
            _pin(8, MANIFEST_NEXT, TIMESTAMP_NEXT, ACTIVATION_NEXT, SUSPENSION_NEXT),
        ],
        [
            _select(4, MANIFEST, TIMESTAMP, root_use="active"),
            _select(4, MANIFEST, TIMESTAMP, root_use="verify-only"),
            _select(4, MANIFEST, TIMESTAMP, purpose="policy"),
            _select(4, MANIFEST, TIMESTAMP, purpose="suspension"),
        ],
        [_confirmed(4), _confirmed(4)],
    )
    reader = Reader([
        _credential("credentials_trusted", label="urn:c2pa:first-stale"),
        _credential("credentials_trusted", label="urn:c2pa:second-stale"),
    ])
    result = _run(directory, storage, digest, payload, "image/png", store, reader)
    record = result["provenance"]
    assert record["result"] == {
        "kind": "technical",
        "status": "verification_failed",
        "failureCode": "policy_superseded",
        "checks": None,
        "manifests": [],
    }
    assert record["policy"] is None
    raw = json.dumps(record)
    assert "first-stale" not in raw
    assert "second-stale" not in raw
    assert "BEGIN CERTIFICATE" not in raw
    assert len(reader.calls) == 2
    assert len(store.pins) == 1


def test_normalized_bundle_hashes_match_the_reader_inputs(tmp_path):
    payload = _png()
    directory, storage, digest = _plant(tmp_path, payload)
    padded_manifest = "\n" + MANIFEST + "\n"
    padded_timestamp = TIMESTAMP + "\n\n"
    assert padded_manifest != MANIFEST
    assert padded_timestamp != TIMESTAMP
    store = Store(
        [_pin(2, padded_manifest, padded_timestamp)],
        [
            _select(2, padded_manifest, padded_timestamp),
            _select(2, padded_manifest, padded_timestamp),
        ],
        [_confirmed(2)],
    )
    reader = Reader([_credential("credentials_trusted", label="urn:c2pa:normalized")])
    result = _run(directory, storage, digest, payload, "image/png", store, reader)
    call = reader.calls[0]
    record = result["provenance"]
    assert call["manifest"] == MANIFEST
    assert call["timestamp"] == TIMESTAMP
    assert call["manifest"] != padded_manifest
    assert call["timestamp"] != padded_timestamp
    assert record["policy"]["manifestBundleSha256"] == _text_sha(call["manifest"])
    assert record["policy"]["timestampBundleSha256"] == _text_sha(call["timestamp"])
    assert record["policy"]["manifestBundleSha256"] != _text_sha(padded_manifest)
    assert record["policy"]["timestampBundleSha256"] != _text_sha(padded_timestamp)
    assert record["policy"]["rootUse"] == "active"
    assert record["policy"]["purpose"] == "policy"
    raw = json.dumps(record)
    assert "BEGIN CERTIFICATE" not in raw
    assert padded_manifest not in raw
    assert padded_timestamp not in raw


class CommitStore:
    def __init__(self, result):
        self.result = result
        self.calls = 0
        self._lock = threading.Lock()

    def select(self):
        with self._lock:
            self.calls += 1
            result = self.result
        if isinstance(result, BaseException):
            raise result
        return result

    def read_image(self, *_args, **_kwargs):
        raise AssertionError("The commit check tried to read an image.")


def _expires() -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=5)).replace(microsecond=0).isoformat()


def _claim() -> dict:
    return {
        "primaryClaim": "The event happened.",
        "verifiablePoints": ["The event happened."],
        "sources": [],
        "independence": {},
        "timeline": {},
    }


def _commit_case(tmp_path: Path):
    payload = _png()
    path = tmp_path / "ledger.sqlite"
    ledger = Ledger(path)
    owner = ledger.create_owner()
    investigation = ledger.create_investigation(owner, "claim", "The event happened.")
    storage = AssetStore.for_ledger(path).write(
        token_hex(16), payload, owner_id=owner, investigation_id=investigation,
    )
    digest = _sha(payload)
    assert ledger.save_image_asset(
        owner,
        investigation,
        token_hex(16),
        digest,
        len(payload),
        "image/png",
        "not_supplied",
        storage,
        IMAGE_CONSENT_VERSION,
    )[0] == "saved"
    return ledger, owner, investigation, storage, payload, digest


def _policy_record(digest: str, payload: bytes, **overrides):
    arguments = {
        "sha256": digest,
        "byte_length": len(payload),
        "media_type": "image/png",
        "verified_at": WHEN,
        "release_sequence": 4,
        "activation_digest": ACTIVATION,
        "suspension_digest": SUSPENSION,
        "manifest_trust_pem": MANIFEST,
        "timestamp_trust_pem": TIMESTAMP,
        "root_use": "active",
        "purpose": "policy",
        "reader_result": _credential("credentials_trusted", label="urn:c2pa:commit"),
    }
    arguments.update(overrides)
    built = build_provenance_record(**arguments)
    assert built["ok"] is True
    return built["record"]


def _commit_pin(**overrides):
    pin = {
        "releaseSequence": 4,
        "activationDigest": ACTIVATION,
        "suspensionDigest": SUSPENSION,
        "manifestTrustPem": MANIFEST,
        "timestampTrustPem": TIMESTAMP,
        "rootUse": "active",
        "purpose": "policy",
    }
    pin.update(overrides)
    return pin


def _fresh(**overrides):
    selected = _select(4, MANIFEST, TIMESTAMP)
    selected.update(overrides)
    return selected


def _snapshot_rows(ledger: Ledger):
    connection = sqlite3.connect(ledger.path)
    try:
        return connection.execute("SELECT id, snapshot_json FROM assessment_snapshots").fetchall()
    finally:
        connection.close()


def _seal(ledger, owner, investigation, digest, payload, store, pin=None, record=None, authorize=None, token="ab" * 32):
    if record is None:
        record = _policy_record(digest, payload)
    if authorize is None and store is not None:
        chosen = _commit_pin() if pin is None else pin
        authorize = lambda stored, chosen=chosen, store=store: confirm_for_commit(store, chosen, stored)
    return ledger.seal_assessment(
        owner,
        investigation,
        token,
        _claim(),
        _expires(),
        provenance=record,
        authorize=authorize,
    )


def test_matching_policy_authorizes_snapshot_insertion(tmp_path):
    ledger, owner, investigation, _storage, payload, digest = _commit_case(tmp_path)
    store = CommitStore(_fresh())
    pin = _commit_pin(manifestTrustPem="\n" + MANIFEST, timestampTrustPem=TIMESTAMP + "\n")
    snapshot_id = _seal(ledger, owner, investigation, digest, payload, store, pin=pin)
    rows = _snapshot_rows(ledger)
    stored = json.loads(rows[0][1])
    decision = confirm_for_commit(store, pin, stored["provenance"])
    assert snapshot_id == rows[0][0]
    assert decision == {"ok": True, "failureCode": None}
    assert stored["provenance"]["policy"]["manifestBundleSha256"] == _text_sha(MANIFEST)
    assert stored["provenance"]["policy"]["timestampBundleSha256"] == _text_sha(TIMESTAMP)
    assert stored["provenance"]["policy"]["rootUse"] == "active"
    assert stored["provenance"]["result"]["status"] == "credentials_trusted"
    assert "BEGIN CERTIFICATE" not in rows[0][1]
    assert "BEGIN CERTIFICATE" not in json.dumps(decision)
    assert store.calls == 2


@pytest.mark.parametrize(
    ("changed", "code"),
    [
        ({"releaseSequence": 9}, "policy_superseded"),
        ({"activationDigest": ACTIVATION_NEXT}, "policy_downgrade"),
        ({"suspensionDigest": SUSPENSION_NEXT}, "policy_downgrade"),
        ({"rootUse": "verify-only"}, "policy_downgrade"),
        ({"purpose": "suspension"}, "policy_downgrade"),
        ({"manifestTrustPem": MANIFEST_NEXT}, "policy_downgrade"),
        ({"timestampTrustPem": TIMESTAMP_NEXT}, "policy_downgrade"),
    ],
)
def test_a_changed_policy_rejects_snapshot_insertion(tmp_path, changed, code):
    ledger, owner, investigation, _storage, payload, digest = _commit_case(tmp_path)
    store = CommitStore(_fresh(**changed))
    with pytest.raises(LedgerError, match="unavailable") as caught:
        _seal(ledger, owner, investigation, digest, payload, store)
    assert caught.value.failure_code == code
    assert _snapshot_rows(ledger) == []
    assert store.calls == 1
    assert "BEGIN CERTIFICATE" not in str(caught.value)
    assert code not in ASSESSMENT_OUTCOMES


def test_witness_unavailability_and_store_exceptions_roll_back(tmp_path):
    ledger, owner, investigation, _storage, payload, digest = _commit_case(tmp_path)
    unavailable = CommitStore(failure("witness_unavailable"))
    with pytest.raises(LedgerError, match="unavailable") as caught:
        _seal(ledger, owner, investigation, digest, payload, unavailable)
    assert caught.value.failure_code == "witness_unavailable"
    assert _snapshot_rows(ledger) == []

    broken = CommitStore(RuntimeError("witness socket down"))
    with pytest.raises(LedgerError, match="unavailable") as caught:
        _seal(ledger, owner, investigation, digest, payload, broken, token="cd" * 32)
    assert caught.value.failure_code == "trust_configuration"
    assert "socket" not in str(caught.value)
    assert _snapshot_rows(ledger) == []

    suspended = CommitStore(failure("root_suspended"))
    with pytest.raises(LedgerError, match="unavailable") as caught:
        _seal(ledger, owner, investigation, digest, payload, suspended, token="ef" * 32)
    assert caught.value.failure_code == "root_suspended"
    assert _snapshot_rows(ledger) == []


def test_a_raised_callback_rolls_back_and_a_later_seal_can_commit(tmp_path):
    ledger, owner, investigation, _storage, payload, digest = _commit_case(tmp_path)
    record = _policy_record(digest, payload)

    def explode(_stored):
        raise RuntimeError("selection failed after the transaction began")

    with pytest.raises(LedgerError, match="unavailable") as caught:
        _seal(ledger, owner, investigation, digest, payload, None, record=record, authorize=explode)
    assert caught.value.failure_code == "trust_configuration"
    assert "selection failed" not in str(caught.value)
    assert _snapshot_rows(ledger) == []

    store = CommitStore(_fresh())
    snapshot_id = _seal(
        ledger, owner, investigation, digest, payload, store, record=record, token="12" * 32,
    )
    rows = _snapshot_rows(ledger)
    assert snapshot_id == rows[0][0]
    assert len(rows) == 1
    connection = sqlite3.connect(ledger.path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="sealed snapshot"):
            connection.execute(
                "UPDATE assessment_snapshots SET snapshot_json = ? WHERE id = ?",
                ('{"provenance":{"result":{"status":"credentials_trusted"}}}', snapshot_id),
            )
        connection.rollback()
    finally:
        connection.close()


def test_technical_records_skip_credential_authorization(tmp_path):
    ledger, owner, investigation, _storage, payload, digest = _commit_case(tmp_path)
    built = build_provenance_record(
        sha256=digest,
        byte_length=len(payload),
        media_type="image/png",
        verified_at=WHEN,
        failure_code="reader_timeout",
    )
    assert built["ok"] is True
    assert built["record"]["policy"] is None

    def forbidden(_stored):
        raise AssertionError("A technical record invoked credential authorization.")

    snapshot_id = _seal(
        ledger, owner, investigation, digest, payload, None, record=built["record"], authorize=forbidden,
    )
    stored = json.loads(_snapshot_rows(ledger)[0][1])
    assert snapshot_id
    assert stored["provenance"]["result"] == {
        "kind": "technical",
        "status": "verification_failed",
        "failureCode": "reader_timeout",
        "checks": None,
        "manifests": [],
    }
    assert stored["provenance"]["result"]["status"] not in ASSESSMENT_OUTCOMES
    assert stored["sealedAsset"]["sha256"] == digest


def test_a_credential_record_without_a_callback_is_rejected(tmp_path):
    ledger, owner, investigation, _storage, payload, digest = _commit_case(tmp_path)
    record = _policy_record(digest, payload)
    context = _claim()
    context["provenance"] = _policy_record(digest, payload, activation_digest=ACTIVATION_NEXT)
    with pytest.raises(LedgerError, match="unavailable") as caught:
        ledger.seal_assessment(
            owner, investigation, "ab" * 32, context, _expires(), provenance=record,
        )
    assert caught.value.failure_code == "trust_configuration"
    assert _snapshot_rows(ledger) == []
    assert ACTIVATION_NEXT not in str(caught.value)


def test_asset_identity_is_rechecked_before_authorization(tmp_path):
    ledger, owner, investigation, storage, payload, digest = _commit_case(tmp_path)
    (ledger.path.parent / "assets" / storage).write_bytes(b"\x00" * len(payload))
    called = []

    def authorize(record):
        called.append(record)
        return {"ok": True, "failureCode": None}

    with pytest.raises(LedgerError, match="unavailable"):
        _seal(ledger, owner, investigation, digest, payload, None, authorize=authorize)
    assert called == []
    assert _snapshot_rows(ledger) == []


def test_authorization_is_invoked_once_immediately_before_insert(tmp_path):
    ledger, owner, investigation, _storage, payload, digest = _commit_case(tmp_path)
    store = CommitStore(_fresh())
    order = []
    real_connect = ledger._connect

    def connect():
        connection = real_connect()

        def trace(statement):
            if "INSERT INTO assessment_snapshots" in statement:
                order.append("insert")

        connection.set_trace_callback(trace)
        return connection

    ledger._connect = connect

    def authorize(record):
        order.append("authorize")
        decision = confirm_for_commit(store, _commit_pin(), record)
        assert decision["ok"] is True
        assert store.calls == 1
        return decision

    snapshot_id = _seal(ledger, owner, investigation, digest, payload, None, authorize=authorize)
    assert order == ["authorize", "insert"]
    assert snapshot_id
    assert store.calls == 1
    assert len(_snapshot_rows(ledger)) == 1


def test_a_record_hash_mismatch_is_not_authorized(tmp_path):
    ledger, owner, investigation, _storage, payload, digest = _commit_case(tmp_path)
    record = _policy_record(digest, payload)
    record["policy"] = dict(record["policy"])
    record["policy"]["manifestBundleSha256"] = "ab" * 32
    store = CommitStore(_fresh())
    with pytest.raises(LedgerError, match="unavailable") as caught:
        _seal(ledger, owner, investigation, digest, payload, store, record=record)
    assert caught.value.failure_code == "trust_configuration"
    assert _snapshot_rows(ledger) == []
    assert store.calls == 1


def test_concurrent_authorized_seals_commit_separate_snapshots(tmp_path):
    ledger, owner, investigation, _storage, payload, digest = _commit_case(tmp_path)
    record = _policy_record(digest, payload)
    store = CommitStore(_fresh())
    found = []
    errors = []
    gate = threading.Lock()

    def run(token):
        try:
            snapshot_id = _seal(
                ledger, owner, investigation, digest, payload, store, record=record, token=token,
            )
            with gate:
                found.append(snapshot_id)
        except Exception as exc:
            with gate:
                errors.append(exc)

    threads = [threading.Thread(target=run, args=(token_hex(32),)) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert len(found) == 2
    assert len(set(found)) == 2
    rows = _snapshot_rows(ledger)
    assert len(rows) == 2
    assert all("BEGIN CERTIFICATE" not in row[1] for row in rows)
    assert store.calls == 2
