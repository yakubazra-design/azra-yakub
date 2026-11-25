"""Sealed snapshots persist a server-built provenance record.

Every database is created under pytest's temporary directory. The live
ledger is not opened.
"""

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from app.assetstore import AssetStore
from app.ledger import Ledger, LedgerError
from app.provenance import READER_VERSION, build_provenance_record

WHEN = "2026-11-20T00:00:00Z"
PAYLOAD = b"jpeg-bytes"
MANIFEST_PEM = "-----BEGIN CERTIFICATE-----\nTUFOSUZFU1Q=\n-----END CERTIFICATE-----\n"
TIMESTAMP_PEM = "-----BEGIN CERTIFICATE-----\nVElNRVNUQU1Q\n-----END CERTIFICATE-----\n"


def _future() -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=10)).replace(microsecond=0).isoformat()


def _context():
    return {
        "primaryClaim": "The event happened.",
        "verifiablePoints": ["The event happened."],
        "sources": [],
        "independence": {},
        "timeline": {},
    }


def _reader(status="credentials_trusted"):
    checks = {
        "signature": "valid",
        "assetBinding": "bound",
        "certificateTrust": "trusted",
        "certificateValidity": "inside_at_asserted_time",
        "revocation": "not_revoked",
        "timestamp": "trusted",
    }
    return {
        "version": READER_VERSION,
        "status": status,
        "checks": checks,
        "manifests": [{
            "label": "urn:c2pa:active",
            "role": "active",
            "status": status,
            "checks": checks,
        }],
        "actions": [],
        "actionsWithheld": True,
    }


def _record(digest: str, length: int, media_type: str, **overrides):
    arguments = {
        "sha256": digest,
        "byte_length": length,
        "media_type": media_type,
        "verified_at": WHEN,
        "release_sequence": 2,
        "activation_digest": "cd" * 32,
        "suspension_digest": "ef" * 32,
        "manifest_trust_pem": MANIFEST_PEM,
        "timestamp_trust_pem": TIMESTAMP_PEM,
        "root_use": "active",
        "purpose": "policy",
        "reader_result": _reader(),
    }
    arguments.update(overrides)
    built = build_provenance_record(**arguments)
    assert built["ok"] is True
    return built["record"]


def _investigation(tmp_path, payload=PAYLOAD, media_type="image/jpeg"):
    path = tmp_path / "ledger.sqlite"
    ledger = Ledger(path)
    owner = ledger.create_owner()
    investigation = ledger.create_investigation(owner, "claim", "The event happened.")
    store = AssetStore.for_ledger(path)
    asset_id = hashlib.sha256(payload + media_type.encode()).hexdigest()[:32]
    storage = store.write(asset_id, payload, owner_id=owner, investigation_id=investigation)
    digest = hashlib.sha256(payload).hexdigest()
    status, _previous = ledger.save_image_asset(
        owner,
        investigation,
        asset_id,
        digest,
        len(payload),
        media_type,
        "not_supplied",
        storage,
        "image-upload-1",
    )
    assert status == "saved"
    return ledger, owner, investigation, digest


def _allow(_record):
    return {"ok": True, "failureCode": None}


def _stored(ledger: Ledger):
    conn = sqlite3.connect(ledger.path)
    try:
        rows = conn.execute("SELECT id, owner_id, token_hash, snapshot_json FROM assessment_snapshots").fetchall()
    finally:
        conn.close()
    return rows


def test_server_provenance_is_stored_with_the_snapshot(tmp_path):
    ledger, owner, investigation, digest = _investigation(tmp_path)
    record = _record(digest, len(PAYLOAD), "image/jpeg")
    token_hash = "ab" * 32
    snapshot_id = ledger.seal_assessment(
        owner, investigation, token_hash, _context(), _future(), provenance=record, authorize=_allow,
    )
    rows = _stored(ledger)
    assert snapshot_id
    assert len(rows) == 1
    assert rows[0][0] == snapshot_id
    assert rows[0][1] == owner
    assert rows[0][2] == token_hash
    stored = json.loads(rows[0][3])
    assert stored["provenance"] == record
    assert stored["sealedAsset"]["sha256"] == stored["provenance"]["image"]["sha256"]
    assert stored["sealedAsset"]["byteLength"] == stored["provenance"]["image"]["byteLength"]
    assert stored["sealedAsset"]["mediaType"] == stored["provenance"]["image"]["mediaType"]
    assert "BEGIN CERTIFICATE" not in rows[0][3]
    consumed, status = ledger.consume_assessment(owner, investigation, token_hash)
    assert status == "ok"
    assert consumed["provenance"]["result"]["status"] == "credentials_trusted"
    assert ledger.consume_assessment(owner, investigation, token_hash)[1] == "used"


def test_client_provenance_is_discarded_even_when_it_would_validate(tmp_path):
    ledger, owner, investigation, digest = _investigation(tmp_path)
    client_record = _record(digest, len(PAYLOAD), "image/jpeg", activation_digest="11" * 32)
    server_record = _record(digest, len(PAYLOAD), "image/jpeg", activation_digest="22" * 32)
    context = _context()
    context["provenance"] = client_record
    snapshot_id = ledger.seal_assessment(
        owner, investigation, "ab" * 32, context, _future(), provenance=server_record, authorize=_allow,
    )
    stored = json.loads(_stored(ledger)[0][3])
    assert snapshot_id
    assert stored["provenance"]["policy"]["activationDigest"] == "22" * 32
    assert "11" * 32 not in _stored(ledger)[0][3]
    bare = Ledger(tmp_path / "bare.sqlite")
    bare_owner = bare.create_owner()
    bare_case = bare.create_investigation(bare_owner, "claim", "The event happened.")
    store = AssetStore.for_ledger(bare.path)
    asset_id = "aa" * 16
    storage = store.write(asset_id, PAYLOAD, owner_id=bare_owner, investigation_id=bare_case)
    digest = hashlib.sha256(PAYLOAD).hexdigest()
    assert bare.save_image_asset(
        bare_owner, bare_case, asset_id, digest, len(PAYLOAD), "image/jpeg",
        "not_supplied", storage, "image-upload-1",
    )[0] == "saved"
    client_only = _context()
    client_only["provenance"] = _record(digest, len(PAYLOAD), "image/jpeg", activation_digest="33" * 32)
    assert bare.seal_assessment(bare_owner, bare_case, "cd" * 32, client_only, _future())
    bare_json = _stored(bare)[0][3]
    assert "provenance" not in json.loads(bare_json)
    assert "33" * 32 not in bare_json


def test_mismatched_and_invalid_provenance_are_not_persisted(tmp_path):
    ledger, owner, investigation, digest = _investigation(tmp_path)
    cases = [
        _record("ab" * 32, len(PAYLOAD), "image/jpeg"),
        _record(digest, len(PAYLOAD) + 1, "image/jpeg"),
        _record(digest, len(PAYLOAD), "image/png"),
        {"version": "c2pa-provenance-1", "result": {"status": "POTENTIAL_MANIPULATION"}},
    ]
    for record in cases:
        with pytest.raises(LedgerError, match="unavailable"):
            ledger.seal_assessment(
                owner, investigation, "ab" * 32, _context(), _future(), provenance=record,
            )
        assert _stored(ledger) == []
        assert "POTENTIAL_MANIPULATION" not in str(LedgerError)
        assert "BEGIN CERTIFICATE" not in str(LedgerError)


def test_no_image_and_legacy_snapshots_stay_without_provenance(tmp_path):
    ledger = Ledger(tmp_path / "ledger.sqlite")
    owner = ledger.create_owner()
    investigation = ledger.create_investigation(owner, "claim", "The event happened.")
    assert ledger.seal_assessment(owner, investigation, "ab" * 32, _context(), _future())
    stored = json.loads(_stored(ledger)[0][3])
    assert "provenance" not in stored
    assert "sealedAsset" not in stored
    consumed, status = ledger.consume_assessment(owner, investigation, "ab" * 32)
    assert status == "ok"
    assert "provenance" not in consumed

    other = ledger.create_investigation(owner, "claim", "Another claim.")
    record = _record("ab" * 32, 4, "image/jpeg")
    with pytest.raises(LedgerError, match="unavailable"):
        ledger.seal_assessment(owner, other, "cd" * 32, _context(), _future(), provenance=record)
    assert len(_stored(ledger)) == 1


def test_sealed_provenance_cannot_be_replaced(tmp_path):
    ledger, owner, investigation, digest = _investigation(tmp_path)
    record = _record(digest, len(PAYLOAD), "image/jpeg")
    snapshot_id = ledger.seal_assessment(
        owner, investigation, "ab" * 32, _context(), _future(), provenance=record, authorize=_allow,
    )
    conn = sqlite3.connect(ledger.path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="sealed snapshot"):
            conn.execute(
                "UPDATE assessment_snapshots SET snapshot_json = ? WHERE id = ?",
                (json.dumps({"provenance": {"result": {"status": "credentials_trusted"}}}), snapshot_id),
            )
        conn.rollback()
        raw = conn.execute(
            "SELECT snapshot_json FROM assessment_snapshots WHERE id = ?",
            (snapshot_id,),
        ).fetchone()[0]
    finally:
        conn.close()
    assert json.loads(raw)["provenance"] == record


def test_ownership_and_token_behavior_stay_unchanged(tmp_path):
    ledger, owner, investigation, digest = _investigation(tmp_path)
    record = _record(digest, len(PAYLOAD), "image/jpeg")
    stranger = ledger.create_owner()
    assert ledger.seal_assessment(
        stranger, investigation, "ff" * 32, _context(), _future(), provenance=record,
    ) is None
    assert _stored(ledger) == []
    token_hash = "12" * 32
    assert ledger.seal_assessment(
        owner, investigation, token_hash, _context(), _future(), provenance=record, authorize=_allow,
    )
    assert ledger.consume_assessment(stranger, investigation, token_hash)[1] == "invalid"
    consumed, status = ledger.consume_assessment(owner, investigation, token_hash)
    assert status == "ok"
    assert consumed["provenance"]["image"]["sha256"] == digest
    assert ledger.consume_assessment(owner, investigation, token_hash)[1] == "used"


def test_technical_provenance_does_not_ask_for_commit_authorization(tmp_path):
    ledger, owner, investigation, digest = _investigation(tmp_path)
    built = build_provenance_record(
        sha256=digest,
        byte_length=len(PAYLOAD),
        media_type="image/jpeg",
        verified_at=WHEN,
        failure_code="witness_unavailable",
    )
    assert built["ok"] is True
    assert built["record"]["policy"] is None

    snapshot_id = ledger.seal_assessment(
        owner,
        investigation,
        "ab" * 32,
        _context(),
        _future(),
        provenance=built["record"],
    )
    stored = json.loads(_stored(ledger)[0][3])
    assert snapshot_id
    assert stored["provenance"]["result"]["failureCode"] == "witness_unavailable"
    assert stored["provenance"]["result"]["status"] == "verification_failed"
    assert stored["provenance"]["policy"] is None
    assert "BEGIN CERTIFICATE" not in _stored(ledger)[0][3]


def test_failed_authorization_leaves_no_snapshot_row(tmp_path):
    ledger, owner, investigation, digest = _investigation(tmp_path)
    record = _record(digest, len(PAYLOAD), "image/jpeg")
    with pytest.raises(LedgerError, match="unavailable") as missing:
        ledger.seal_assessment(
            owner, investigation, "ab" * 32, _context(), _future(), provenance=record,
        )
    assert missing.value.failure_code == "trust_configuration"
    assert _stored(ledger) == []

    snapshot_id = ledger.seal_assessment(
        owner, investigation, "cd" * 32, _context(), _future(), provenance=record, authorize=_allow,
    )
    assert snapshot_id
    assert len(_stored(ledger)) == 1

    def deny(_stored_record):
        return {"ok": False, "failureCode": "policy_superseded"}

    with pytest.raises(LedgerError, match="unavailable") as denied:
        ledger.seal_assessment(
            owner, investigation, "ef" * 32, _context(), _future(), provenance=record, authorize=deny,
        )
    assert denied.value.failure_code == "policy_superseded"
    rows = _stored(ledger)
    assert len(rows) == 1
    assert rows[0][0] == snapshot_id
    assert json.loads(rows[0][3])["provenance"] == record

    def explode(_stored_record):
        raise RuntimeError("trust store down")

    with pytest.raises(LedgerError, match="unavailable") as exploded:
        ledger.seal_assessment(
            owner, investigation, "12" * 32, _context(), _future(), provenance=record, authorize=explode,
        )
    assert exploded.value.failure_code == "trust_configuration"
    assert "trust store" not in str(exploded.value)
    assert len(_stored(ledger)) == 1
    assert _stored(ledger)[0][0] == snapshot_id
