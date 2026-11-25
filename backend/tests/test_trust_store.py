"""Trust-store publication, witness, and root-control tests.

Keys, directories, and service doubles exist only inside pytest's temporary
directory. Nothing here contacts a network or opens the investigation ledger.
"""

import base64
import copy
import datetime
import os
import shutil
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.trust_store import (
    ASSESSMENT_OUTCOMES,
    CREDENTIAL_STATUSES,
    DOMAIN_ACTIVATE,
    DOMAIN_ADMIN_KEY,
    DOMAIN_APPROVAL,
    DOMAIN_RELEASE,
    DOMAIN_REVIEW,
    DOMAIN_SUSPENSION,
    FAILURE_CODES,
    WitnessReply,
    WitnessTransportError,
    WitnessValue,
    RootReply,
    SignedRelease,
    TrustStore,
    _N,
    activation_document,
    canonical_json,
    confirmation_digest,
    failure,
    mac_bytes,
    parse_canonical,
    public_spki,
    root_mac_message,
    sha256_digest,
    sha256_hex,
    sign_document,
    spki_fingerprint,
    suspension_digest,
    witness_mac_message,
    write_pin_file,
)

WHEN = "2026-11-20T00:00:00Z"
LATER = "2026-11-20T02:00:00Z"
NOT_BEFORE = "2026-01-01T00:00:00Z"
NOT_AFTER = "2027-01-01T00:00:00Z"
ADMINS = ("admin-one", "admin-two")
RUNTIME = "trust-runtime"
_ROLE_DOMAIN = {
    "trust-approver": DOMAIN_APPROVAL,
    "security-administrator": DOMAIN_SUSPENSION,
    "security-reviewer": DOMAIN_REVIEW,
}


def _assert_code(result, code):
    assert result["status"] == "verification_failed"
    assert result["failureCode"] == code
    assert result["failureCode"] in FAILURE_CODES
    assert result["credentialStatus"] is None
    assert result["assessment"] is None
    assert result["status"] not in CREDENTIAL_STATUSES
    assert result["status"] not in ASSESSMENT_OUTCOMES
    assert result["failureCode"] not in ASSESSMENT_OUTCOMES
    assert "manifestTrustPem" not in result


def _fsync(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(data)
    descriptor = os.open(temporary, os.O_RDWR)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    _fsync(path.parent)


class DirectoryWitness:
    """Temporary-directory witness with monotonic compare-and-set."""

    def __init__(self, directory, *, mac_key, readers, advancers):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True)
        self.path = self.directory / "state.json"
        self.audit = self.directory / "audit.log"
        self.mac_key = mac_key
        self.readers = set(readers)
        self.advancers = set(advancers)
        self.lock = threading.Lock()
        self.drop_next_response = False
        self.corrupt_mac = False
        self.unavailable = False
        self.applied_writes = 0

    def snapshot(self) -> bytes:
        if not self.path.exists():
            return b""
        return self.path.read_bytes()

    def read(self, caller_id):
        with self.lock:
            if self.unavailable:
                return self._reply("unavailable", WitnessValue(), None, "unavailable", mac=False)
            if caller_id not in self.readers and caller_id not in self.advancers:
                value = self._value()
                return self._reply("rejected", value, None, "unauthorized")
            value = self._value()
            kind = "empty" if value.empty else "record"
            return self._reply(kind, value, None, "")

    def compare_and_set(self, caller_id, expected, new, request_id):
        with self.lock:
            if self.unavailable:
                return self._reply("unavailable", WitnessValue(), None, "unavailable", mac=False)
            current = self._value()
            if caller_id not in self.advancers:
                self._audit("rejected-unauthorized")
                return self._reply("rejected", current, request_id, "unauthorized")
            state = self._state()
            known = next((item for item in state["applied"] if item["requestId"] == request_id.hex()), None)
            proposed = {
                "activationDigest": new.activation_digest.hex(),
                "requestId": request_id.hex(),
                "sequence": new.sequence,
                "suspensionDigest": new.suspension_digest.hex(),
            }
            if known is not None:
                same = (
                    known["sequence"] == proposed["sequence"]
                    and known["activationDigest"] == proposed["activationDigest"]
                    and known["suspensionDigest"] == proposed["suspensionDigest"]
                )
                reason = "" if same else "replay"
                kind = "idempotent" if same else "rejected"
                self._audit("idempotent" if same else "rejected-replay")
                return self._reply(kind, current, request_id, reason)
            if not current.empty and _value_equal(current, new):
                self._audit("idempotent")
                return self._reply("idempotent", current, request_id, "")
            if current.empty:
                acceptable = expected.empty and new.sequence == 1
                reason = "stale"
            else:
                acceptable = (
                    expected.sequence == current.sequence
                    and expected.activation_digest == current.activation_digest
                    and expected.suspension_digest == current.suspension_digest
                    and new.sequence == current.sequence + 1
                )
                reason = "conflict" if expected.sequence == current.sequence else "stale"
            if not acceptable or new.sequence < 1:
                self._audit("rejected-" + reason)
                return self._reply("rejected", current, request_id, reason)
            state["applied"].append(proposed)
            state["current"] = proposed
            self._store(state)
            self.applied_writes += 1
            self._audit("applied")
            if self.drop_next_response:
                self.drop_next_response = False
                raise WitnessTransportError("response lost")
            return self._reply("applied", new, request_id, "")

    def _state(self):
        if not self.path.exists():
            return {"applied": [], "current": None}
        parsed = parse_canonical(self.path.read_bytes(), top_null=("current",))
        return parsed

    def _store(self, state) -> None:
        _atomic(self.path, canonical_json(state, top_null=("current",)))

    def _value(self):
        current = self._state()["current"]
        if current is None:
            return WitnessValue()
        return WitnessValue(
            current["sequence"],
            bytes.fromhex(current["activationDigest"]),
            bytes.fromhex(current["suspensionDigest"]),
        )

    def _reply(self, kind, value, request_id, reason, mac=True):
        digest = mac_bytes(self.mac_key, witness_mac_message(kind, value, request_id, reason)) if mac else b""
        if mac and self.corrupt_mac and digest:
            digest = digest[:-1] + bytes([digest[-1] ^ 0x01])
        return WitnessReply(kind, value, request_id, reason, digest)

    def _audit(self, label) -> None:
        with self.audit.open("ab") as handle:
            handle.write(label.encode("ascii") + b"\n")
            handle.flush()
            os.fsync(handle.fileno())


def _value_equal(current, new) -> bool:
    return (
        current.sequence == new.sequence
        and current.activation_digest == new.activation_digest
        and current.suspension_digest == new.suspension_digest
    )


class DirectoryRootLog:
    """Append-only root-control log outside the trust-store directory."""

    def __init__(self, directory, *, mac_key, readers, admins):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True)
        self.path = self.directory / "log.json"
        self.mac_key = mac_key
        self.readers = set(readers)
        self.admins = set(admins)
        self.lock = threading.Lock()
        self.unavailable = False
        self.serve_previous = False
        self.entries = []
        self.previous_entries = []
        self.previous_generation = 0

    def snapshot(self) -> bytes:
        if not self.path.exists():
            return b""
        return self.path.read_bytes()

    def read(self, caller_id):
        with self.lock:
            if self.unavailable:
                return RootReply("unavailable", [], 0, "unavailable", b"")
            if caller_id not in self.readers and caller_id not in self.admins:
                return self._reply("rejected", self.entries, len(self.entries), "unauthorized")
            if self.serve_previous:
                return self._reply("record", self.previous_entries, self.previous_generation, "")
            return self._reply("record", self.entries, len(self.entries), "")

    def append_suspension(self, caller_ids, fingerprint, witness_sequence, at):
        with self.lock:
            if not self._admins(caller_ids):
                return self._reply("rejected", self.entries, len(self.entries), "unauthorized")
            if any(item["type"] == "root-suspended" and item["fingerprint"] == fingerprint for item in self.entries):
                return self._reply("rejected", self.entries, len(self.entries), "conflict")
            entry = {
                "administrators": sorted(caller_ids),
                "at": at,
                "fingerprint": fingerprint,
                "generation": len(self.entries) + 1,
                "type": "root-suspended",
                "witnessSequence": witness_sequence,
            }
            if not self._extend(entry):
                return self._reply("rejected", self.entries, len(self.entries), "conflict")
            return self._reply("appended", self.entries, len(self.entries), "")

    def append_replacement(self, caller_ids, fingerprint, confirmations, at):
        with self.lock:
            if not self._admins(caller_ids) or len(confirmations) != 2:
                return self._reply("rejected", self.entries, len(self.entries), "unauthorized")
            if any(item["type"] == "root-replaced" for item in self.entries):
                return self._reply("rejected", self.entries, len(self.entries), "conflict")
            if any(item["type"] == "root-suspended" and item["fingerprint"] == fingerprint for item in self.entries):
                return self._reply("rejected", self.entries, len(self.entries), "conflict")
            entry = {
                "at": at,
                "confirmations": confirmations,
                "fingerprint": fingerprint,
                "generation": len(self.entries) + 1,
                "type": "root-replaced",
            }
            if not self._extend(entry):
                return self._reply("rejected", self.entries, len(self.entries), "conflict")
            return self._reply("appended", self.entries, len(self.entries), "")

    def force_shorter(self) -> bool:
        with self.lock:
            before = self.snapshot()
            changed = self._extend_entries([])
            return changed is False and self.snapshot() == before

    def _admins(self, caller_ids) -> bool:
        return (
            isinstance(caller_ids, tuple)
            and len(caller_ids) == 2
            and len(set(caller_ids)) == 2
            and set(caller_ids) <= self.admins
        )

    def _extend(self, entry) -> bool:
        return self._extend_entries(self.entries + [entry])

    def _extend_entries(self, new_entries) -> bool:
        if new_entries[: len(self.entries)] != self.entries or len(new_entries) != len(self.entries) + 1:
            return False
        self.previous_entries = copy.deepcopy(self.entries)
        self.previous_generation = len(self.entries)
        self.entries = new_entries
        _atomic(self.path, canonical_json({"entries": self.entries, "generation": len(self.entries)}))
        return True

    def _reply(self, kind, entries, generation, reason):
        message = root_mac_message(kind, entries, generation, reason)
        return RootReply(kind, entries, generation, reason, mac_bytes(self.mac_key, message))


def _certificate(common_name: str) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


class Person:
    def __init__(self, person_id, role, key_id=None, document=None):
        self.person_id = person_id
        self.role = role
        self.key_id = key_id or person_id + "-key"
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.document = document or sha256_hex(person_id.encode("ascii"))


def _authorize(root_key, person, status="authorized"):
    spki = public_spki(person.key.public_key())
    body = {
        "documentFingerprint": person.document,
        "keyId": person.key_id,
        "notAfter": NOT_AFTER,
        "notBefore": NOT_BEFORE,
        "personId": person.person_id,
        "role": person.role,
        "spki": base64.b64encode(spki).decode("ascii"),
        "spkiFingerprint": spki_fingerprint(spki),
        "status": status,
    }
    return {"body": body, "signature": sign_document(root_key, DOMAIN_ADMIN_KEY, body)}


def _entry(label, at=WHEN):
    return {"certificateFingerprint": sha256_hex(label.encode("ascii")), "suspendedAt": at}


class Fixture:
    def __init__(self, tmp_path, *, caller=RUNTIME):
        self.tmp_path = Path(tmp_path)
        self.trust = self.tmp_path / "trust"
        self.local_path = self.tmp_path / "app-state" / "high-water.json"
        self.pin_path = self.tmp_path / "deploy" / "root-pin.json"
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.root_spki = public_spki(self.root_key.public_key())
        self.signer = Person("person-signer", "release-signer")
        self.approver_a = Person("person-a", "trust-approver")
        self.approver_b = Person("person-b", "trust-approver")
        self.security = Person("person-sec", "security-administrator")
        self.reviewer = Person("person-rev", "security-reviewer")
        self.manifest = _certificate("manifest-anchor")
        self.timestamp = _certificate("timestamp-anchor")
        self.witness_key = b"w" * 32
        self.root_key_mac = b"r" * 32
        self.witness = DirectoryWitness(
            self.tmp_path / "witness",
            mac_key=self.witness_key,
            readers={caller, "auditor"},
            advancers={caller},
        )
        self.root_log = DirectoryRootLog(
            self.tmp_path / "root-control",
            mac_key=self.root_key_mac,
            readers={caller, "auditor"},
            admins=set(ADMINS),
        )
        write_pin_file(self.pin_path, active_spki=self.root_spki)
        self.saved_pin = self.pin_path.read_bytes()
        self.authorizations = [
            _authorize(self.root_key, person)
            for person in (self.signer, self.approver_a, self.approver_b, self.security, self.reviewer)
        ]
        self.store = TrustStore(
            self.trust,
            self.local_path,
            self.pin_path,
            self.witness,
            self.root_log,
            witness_mac_key=self.witness_key,
            root_mac_key=self.root_key_mac,
            caller_id=caller,
        )

    def signed(self, sequence, *, purpose="policy", suspensions=None, approvers=None, authorizations=None, root_key=None, root_spki=None, when=WHEN):
        suspensions = [] if suspensions is None else sorted(suspensions, key=lambda item: item["certificateFingerprint"])
        root_spki = self.root_spki if root_spki is None else root_spki
        root_key = self.root_key if root_key is None else root_key
        body = {
            "manifestDigest": sha256_hex(self.manifest),
            "purpose": purpose,
            "releaseSequence": sequence,
            "rootFingerprint": spki_fingerprint(root_spki),
            "suspensionDigest": suspension_digest(suspensions).hex(),
            "suspensions": suspensions,
            "timestampDigest": sha256_hex(self.timestamp),
            "validFrom": when,
        }
        approvals = []
        release_digest = sha256_hex(canonical_json(body))
        for person in approvers or (self.approver_a, self.approver_b):
            approval = {
                "approvedAt": when,
                "keyId": person.key_id,
                "personId": person.person_id,
                "releaseDigest": release_digest,
                "releaseSequence": sequence,
                "role": person.role,
            }
            approvals.append({
                "body": approval,
                "signature": sign_document(person.key, _ROLE_DOMAIN[person.role], approval),
            })
        activation = activation_document(release_digest, sequence, body["suspensionDigest"])
        return SignedRelease(
            body,
            sign_document(self.signer.key, DOMAIN_RELEASE, body),
            self.manifest,
            self.timestamp,
            approvals,
            self.authorizations if authorizations is None else authorizations,
            sign_document(self.signer.key, DOMAIN_ACTIVATE, activation),
        )

    def publish(self, sequence=1, **kwargs):
        return self.store.publish(self.signed(sequence, **kwargs))

    def authorizations_for(self, root_key, people=None, status_for=None):
        records = []
        for person in people or (self.signer, self.approver_a, self.approver_b, self.security, self.reviewer):
            status = "authorized" if not status_for else status_for(person)
            records.append(_authorize(root_key, person, status))
        return records


def test_separate_bundles_and_two_person_publication(tmp_path):
    fixture = Fixture(tmp_path)
    assert fixture.store.select()["failureCode"] == "no_committed_policy"
    selected = fixture.publish()
    assert selected["status"] == "selected"
    assert selected["releaseSequence"] == 1
    assert selected["credentialStatus"] is None
    assert selected["assessment"] is None
    assert selected["status"] not in ASSESSMENT_OUTCOMES
    assert selected["manifestTrustPem"].encode() == fixture.manifest
    assert selected["timestampTrustPem"].encode() == fixture.timestamp
    assert selected["manifestTrustPem"] != selected["timestampTrustPem"]
    release = fixture.trust / "releases" / "1"
    assert (release / "manifest.pem").read_bytes() == fixture.manifest
    assert (release / "timestamp.pem").read_bytes() == fixture.timestamp
    assert fixture.manifest not in fixture.timestamp
    pinned = fixture.store.pin()
    assert pinned["status"] == "pinned"
    assert fixture.store.revalidate(pinned)["status"] == "confirmed"


def test_activation_selection_and_recovery_at_every_step(tmp_path):
    def stage(name, stop):
        fixture = Fixture(tmp_path / name)
        assert fixture.publish()["releaseSequence"] == 1
        signed = fixture.signed(2)
        if stop == "before":
            return fixture, signed
        assert fixture.store.write_release(signed)["status"] == "staged"
        if stop == "release":
            return fixture, signed
        assert fixture.store.write_activation(2, signed.activation_signature)["status"] == "activation"
        if stop == "activation":
            return fixture, signed
        assert fixture.store.record_pending(2)["status"] == "pending"
        if stop == "pending":
            return fixture, signed
        assert fixture.store.advance_witness()["status"] == "witness"
        if stop == "witness":
            return fixture, signed
        assert fixture.store.promote_local()["status"] == "promoted"
        return fixture, signed

    before, _signed = stage("before", "before")
    assert before.store.recover()["action"] == "none"
    assert before.store.select()["releaseSequence"] == 1

    released, signed = stage("release", "release")
    assert released.store.select()["releaseSequence"] == 1
    _assert_code(released.store.write_release(signed), "sequence_conflict")
    assert released.store.recover()["action"] == "none"
    assert released.store.select()["releaseSequence"] == 1
    assert not (released.trust / "activations" / "2").exists()

    activated, _signed = stage("activation", "activation")
    assert activated.store.select()["releaseSequence"] == 1
    assert (activated.trust / "activations" / "2").is_file()
    assert (activated.trust / "activations" / "1").is_file()
    recovered = activated.store.recover()
    assert recovered["action"] == "completed"
    assert activated.store.select()["releaseSequence"] == 2

    pending, _signed = stage("pending", "pending")
    assert pending.store.select()["releaseSequence"] == 1
    assert pending.store.recover()["action"] == "completed"
    assert pending.store.select()["releaseSequence"] == 2

    witnessed, _signed = stage("witness", "witness")
    assert witnessed.store.select()["releaseSequence"] == 2
    assert witnessed.store.recover()["action"] == "completed"
    assert witnessed.store.select()["releaseSequence"] == 2

    promoted, earlier = stage("promoted", "promoted")
    assert promoted.store.recover()["action"] == "none"
    selected = promoted.store.select()
    assert selected["releaseSequence"] == 2
    superseded = promoted.store.revalidate({
        "releaseSequence": 1,
        "activationDigest": "ab" * 32,
        "suspensionDigest": sha256_hex(canonical_json([])),
    })
    _assert_code(superseded, "policy_superseded")
    _assert_code(promoted.store.write_release(earlier), "policy_downgrade")


def test_concurrent_publishers_conflict_on_the_same_sequence(tmp_path):
    fixture = Fixture(tmp_path)
    assert fixture.publish()["releaseSequence"] == 1
    signed = fixture.signed(2)
    barrier = threading.Barrier(2)
    results = []

    def attempt():
        barrier.wait()
        results.append(fixture.store.write_release(signed))

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    statuses = sorted(item["status"] if item["status"] != "verification_failed" else item["failureCode"] for item in results)
    assert statuses == ["sequence_conflict", "staged"]
    assert fixture.store.select()["releaseSequence"] == 1
    body = (fixture.trust / "releases" / "2" / "release.json").read_bytes()
    assert body == canonical_json(signed.body)


def test_witness_retry_replay_conflict_and_outage(tmp_path):
    fixture = Fixture(tmp_path)
    assert fixture.publish()["releaseSequence"] == 1
    signed = fixture.signed(2)
    assert fixture.store.write_release(signed)["status"] == "staged"
    assert fixture.store.write_activation(2, signed.activation_signature)["status"] == "activation"
    assert fixture.store.record_pending(2)["status"] == "pending"
    before = fixture.witness.snapshot()
    applied = fixture.witness.applied_writes
    fixture.witness.drop_next_response = True
    advanced = fixture.store.advance_witness()
    assert advanced["status"] == "witness"
    assert fixture.witness.applied_writes == applied + 1
    assert fixture.store.advance_witness()["status"] == "witness"
    assert fixture.witness.applied_writes == applied + 1
    assert fixture.witness.snapshot() != before

    request_id = sha256_digest(b"realitycheck-witness-request-v1\x00" + bytes.fromhex(fixture.store.select()["activationDigest"]))[:16]
    current = fixture.witness.read(RUNTIME)
    stale = fixture.witness.compare_and_set(
        RUNTIME,
        WitnessValue(),
        WitnessValue(1, b"\x02" * 32, b"\x03" * 32),
        b"\x11" * 16,
    )
    assert stale.kind == "rejected"
    conflict = fixture.witness.compare_and_set(
        RUNTIME,
        current.value,
        WitnessValue(current.value.sequence + 1, b"\x04" * 32, b"\x05" * 32),
        request_id,
    )
    assert conflict.kind == "rejected"
    assert conflict.reason == "replay"
    outsider = fixture.witness.compare_and_set(
        "intruder",
        current.value,
        WitnessValue(current.value.sequence + 1, b"\x06" * 32, b"\x07" * 32),
        b"\x22" * 16,
    )
    assert outsider.kind == "rejected"
    assert outsider.reason == "unauthorized"
    held = fixture.witness.snapshot()
    assert fixture.witness.snapshot() == held
    fixture.witness.unavailable = True
    _assert_code(fixture.store.select(), "witness_unavailable")
    fixture.witness.unavailable = False
    fixture.witness.corrupt_mac = True
    _assert_code(fixture.store.select(), "witness_corrupt")
    fixture.witness.corrupt_mac = False
    assert fixture.store.select()["releaseSequence"] == 2


def test_restored_local_state_and_missing_activation_fail_closed(tmp_path):
    fixture = Fixture(tmp_path)
    assert fixture.publish()["releaseSequence"] == 1
    saved_local = fixture.local_path.read_bytes()
    saved_trust = tmp_path / "vm-snapshot"
    saved_state = tmp_path / "vm-local.json"
    shutil.copytree(fixture.trust, saved_trust)
    saved_state.write_bytes(saved_local)
    assert fixture.publish(2)["releaseSequence"] == 2
    witness_bytes = fixture.witness.snapshot()
    restored = TrustStore(
        saved_trust,
        saved_state,
        fixture.pin_path,
        fixture.witness,
        fixture.root_log,
        witness_mac_key=fixture.witness_key,
        root_mac_key=fixture.root_key_mac,
        caller_id=RUNTIME,
    )
    _assert_code(restored.select(), "sequence_state_stale")
    fixture.local_path.write_bytes(saved_local)
    _assert_code(fixture.store.select(), "sequence_state_stale")
    fixture.local_path.unlink()
    _assert_code(fixture.store.select(), "sequence_state_stale")
    assert fixture.witness.snapshot() == witness_bytes
    fresh = Fixture(tmp_path / "missing-activation")
    assert fresh.publish()["releaseSequence"] == 1
    (fresh.trust / "activations" / "1").unlink()
    _assert_code(fresh.store.select(), "activation_record_missing")
    assert (fresh.trust / "releases" / "1").is_dir()


def test_suspension_history_cannot_move_backward(tmp_path):
    fixture = Fixture(tmp_path)
    assert fixture.publish()["releaseSequence"] == 1
    first = _entry("alpha")
    assert fixture.publish(2, purpose="suspension", suspensions=[first], approvers=(fixture.security, fixture.reviewer))["releaseSequence"] == 2
    both = [first, _entry("beta", LATER)]
    selected = fixture.publish(3, purpose="suspension", suspensions=both, approvers=(fixture.security, fixture.reviewer))
    assert selected["releaseSequence"] == 3
    witnessed = fixture.witness.snapshot()
    regression = fixture.signed(4, suspensions=[first])
    _assert_code(fixture.store.write_release(regression), "suspension_regression")
    assert fixture.witness.snapshot() == witnessed
    parsed = parse_canonical(fixture.local_path.read_bytes(), top_null=("committed", "pending"))
    parsed["committed"]["suspensions"] = [first]
    parsed["committed"]["suspensionDigest"] = suspension_digest([first]).hex()
    fixture.local_path.write_bytes(canonical_json(parsed, top_null=("committed", "pending")))
    _assert_code(fixture.store.select(), "suspension_state_stale")
    assert fixture.witness.snapshot() == witnessed


def test_suspension_requires_both_signatures(tmp_path):
    fixture = Fixture(tmp_path)
    assert fixture.publish()["releaseSequence"] == 1
    witnessed = fixture.witness.snapshot()
    first = _entry("alpha")
    second_admin = Person("person-sec-2", "security-administrator")
    second_reviewer = Person("person-rev-2", "security-reviewer")
    same_person = Person("person-sec", "security-reviewer", "person-sec-review", fixture.security.document)
    shared_document = Person("person-other", "security-reviewer", document=fixture.security.document)

    def reject(approvers, authorizations, code):
        signed = fixture.signed(
            2,
            purpose="suspension",
            suspensions=[first],
            approvers=approvers,
            authorizations=authorizations,
        )
        _assert_code(fixture.store.publish(signed), code)
        assert fixture.witness.snapshot() == witnessed
        assert fixture.store.select()["releaseSequence"] == 1
        assert not (fixture.trust / "releases" / "2").exists()

    reject((fixture.security,), fixture.authorizations, "unauthorized_approval")
    reject((fixture.reviewer,), fixture.authorizations, "unauthorized_approval")
    reject(
        (fixture.security, second_admin),
        fixture.authorizations + [_authorize(fixture.root_key, second_admin)],
        "unauthorized_approval",
    )
    reject(
        (fixture.reviewer, second_reviewer),
        fixture.authorizations + [_authorize(fixture.root_key, second_reviewer)],
        "unauthorized_approval",
    )
    reject(
        (fixture.security, same_person),
        fixture.authorizations + [_authorize(fixture.root_key, same_person)],
        "duplicate_approver",
    )
    reject(
        (fixture.security, shared_document),
        fixture.authorizations + [_authorize(fixture.root_key, shared_document)],
        "duplicate_approver",
    )


def test_copied_release_is_rejected_for_another_sequence(tmp_path):
    fixture = Fixture(tmp_path)
    selected = fixture.publish()
    assert selected["releaseSequence"] == 1
    shutil.copytree(fixture.trust / "releases" / "1", fixture.trust / "releases" / "9")
    _assert_code(fixture.store.inspect(9), "activation_record_corrupt")
    historical = fixture.store.inspect(1)
    assert historical["status"] == "historical"
    assert historical["releaseSequence"] == 1
    assert historical["manifestTrustPem"].encode() == fixture.manifest
    assert historical["timestampTrustPem"].encode() == fixture.timestamp
    current = fixture.store.select()
    assert current["releaseSequence"] == 1
    assert current["manifestTrustPem"] == selected["manifestTrustPem"]


def test_malformed_witness_responses_fail_closed(tmp_path):
    fixture = Fixture(tmp_path)
    assert fixture.publish()["releaseSequence"] == 1
    witnessed = fixture.witness.snapshot()
    original = fixture.witness.read
    current = original(RUNTIME)

    def truncated(_caller):
        reply = original(_caller)
        return WitnessReply(reply.kind, reply.value, reply.request_id, reply.reason, reply.mac[:-1])

    def missing(_caller):
        return WitnessReply("record", None, None, "", None)

    def raising(_caller):
        raise RuntimeError("truncated response")

    for reader in (lambda _caller: b"\x00\x01", lambda _caller: object(), missing, truncated, raising):
        fixture.store.witness.read = reader
        _assert_code(fixture.store.select(), "witness_corrupt")
        assert fixture.witness.snapshot() == witnessed
        assert "manifestTrustPem" not in fixture.store.select()

    fixture.store.witness.read = original
    signed = fixture.signed(2)
    assert fixture.store.write_release(signed)["status"] == "staged"
    assert fixture.store.write_activation(2, signed.activation_signature)["status"] == "activation"
    assert fixture.store.record_pending(2)["status"] == "pending"
    original_compare = fixture.witness.compare_and_set

    def bad_compare(*_args):
        return b"\x00\x01"

    fixture.witness.compare_and_set = bad_compare
    _assert_code(fixture.store.advance_witness(), "witness_corrupt")
    assert fixture.witness.snapshot() == witnessed
    fixture.witness.compare_and_set = original_compare
    assert fixture.store.select()["releaseSequence"] == 1
    assert current.value.sequence == 1


def test_duplicate_person_revocation_and_substituted_approval(tmp_path):
    fixture = Fixture(tmp_path)
    assert fixture.publish()["releaseSequence"] == 1
    second = Person("person-a", "trust-approver", "person-a-other")
    duplicate = fixture.signed(
        2,
        approvers=(fixture.approver_a, second),
        authorizations=fixture.authorizations + [_authorize(fixture.root_key, second)],
    )
    _assert_code(fixture.store.write_release(duplicate), "duplicate_approver")

    revoked = fixture.authorizations_for(
        fixture.root_key,
        status_for=lambda person: "revoked" if person.person_id == "person-a" else "authorized",
    )
    _assert_code(
        fixture.store.write_release(fixture.signed(2, authorizations=revoked)),
        "unauthorized_approval",
    )

    substituted = fixture.signed(2)
    forged = dict(substituted.approvals[0]["body"])
    forged["releaseDigest"] = "ab" * 32
    substituted.approvals[0] = {
        "body": forged,
        "signature": sign_document(fixture.approver_a.key, DOMAIN_APPROVAL, forged),
    }
    _assert_code(fixture.store.write_release(substituted), "approval_substitution")
    assert fixture.store.select()["releaseSequence"] == 1


def test_high_s_signature_is_rejected(tmp_path):
    fixture = Fixture(tmp_path)
    signed = fixture.signed(1)
    r_value = int.from_bytes(signed.signature[:32], "big")
    s_value = int.from_bytes(signed.signature[32:], "big")
    assert s_value <= _N // 2
    signed.signature = r_value.to_bytes(32, "big") + (_N - s_value).to_bytes(32, "big")
    _assert_code(fixture.store.write_release(signed), "untrusted_admin_key")
    signed = fixture.signed(1)
    signed.signature = b"\x30" + bytes(70)
    _assert_code(fixture.store.write_release(signed), "untrusted_admin_key")


def test_root_suspension_survives_an_old_pin_and_replacement_needs_two_confirmations(tmp_path):
    fixture = Fixture(tmp_path)
    assert fixture.publish()["releaseSequence"] == 1
    fingerprint = spki_fingerprint(fixture.root_spki)
    _assert_code(fixture.store.suspend_root(("admin-one",), fingerprint, WHEN), "root_recovery_incomplete")
    suspended = fixture.store.suspend_root(ADMINS, fingerprint, WHEN)
    assert suspended["status"] == "root-suspended"
    selected = fixture.store.select()
    assert selected["releaseSequence"] == 1
    assert selected["rootUse"] == "verify-only"
    fixture.pin_path.write_bytes(fixture.saved_pin)
    restored = fixture.store.select()
    assert restored["rootUse"] == "verify-only"
    assert restored["releaseSequence"] == 1
    _assert_code(fixture.store.write_release(fixture.signed(2)), "root_suspended")

    replacement = ec.generate_private_key(ec.SECP256R1())
    replacement_spki = public_spki(replacement.public_key())
    replacement_fingerprint = spki_fingerprint(replacement_spki)
    one = [{"personId": "admin-one", "statementDigest": confirmation_digest(replacement_fingerprint)}]
    _assert_code(fixture.store.replace_root(ADMINS, replacement_fingerprint, one, LATER), "root_recovery_incomplete")
    assert fixture.root_log.snapshot().find(b"root-replaced") < 0
    direct = fixture.root_log.append_replacement(ADMINS, replacement_fingerprint, one, LATER)
    assert direct.kind == "rejected"
    assert fixture.root_log.force_shorter() is True

    confirmations = [
        {"personId": "admin-two", "statementDigest": confirmation_digest(replacement_fingerprint)},
        {"personId": "admin-one", "statementDigest": confirmation_digest(replacement_fingerprint)},
    ]
    replaced = fixture.store.replace_root(ADMINS, replacement_fingerprint, confirmations, LATER)
    assert replaced["status"] == "root-replaced"
    _assert_code(fixture.store.select(), "root_pin_inconsistent")
    write_pin_file(
        fixture.pin_path,
        active_spki=replacement_spki,
        verify_only=((fixture.root_spki, 1),),
    )
    historical = fixture.store.inspect(1)
    assert historical["status"] == "historical"
    assert historical["rootUse"] == "verify-only"
    assert historical["manifestTrustPem"].encode() == fixture.manifest
    authorizations = fixture.authorizations_for(replacement)
    published = fixture.publish(2, authorizations=authorizations, root_key=replacement, root_spki=replacement_spki)
    assert published["status"] == "selected"
    assert published["rootUse"] == "active"
    _assert_code(fixture.store.write_release(fixture.signed(3)), "root_suspended")
    fixture.pin_path.write_bytes(fixture.saved_pin)
    _assert_code(fixture.store.select(), "root_pin_inconsistent")
    assert b"root-suspended" in fixture.root_log.snapshot()


def test_root_log_missing_stale_and_inconsistent_states(tmp_path):
    fixture = Fixture(tmp_path)
    assert fixture.publish()["releaseSequence"] == 1
    fingerprint = spki_fingerprint(fixture.root_spki)
    assert fixture.store.suspend_root(ADMINS, fingerprint, WHEN)["status"] == "root-suspended"
    fixture.root_log.unavailable = True
    _assert_code(fixture.store.select(), "root_suspension_unavailable")
    fixture.root_log.unavailable = False
    fixture.root_log.serve_previous = True
    _assert_code(fixture.store.select(), "sequence_state_stale")
    fixture.root_log.serve_previous = False
    assert fixture.store.select()["rootUse"] == "verify-only"
    write_pin_file(
        fixture.pin_path,
        active_spki=fixture.root_spki,
        verify_only=((public_spki(ec.generate_private_key(ec.SECP256R1()).public_key()), 1),),
    )
    _assert_code(fixture.store.select(), "root_pin_inconsistent")
    fixture.pin_path.unlink()
    _assert_code(fixture.store.select(), "root_pin_unavailable")


def test_local_high_water_stays_outside_the_trust_root(tmp_path):
    fixture = Fixture(tmp_path)
    nested = TrustStore(
        fixture.trust,
        fixture.trust / "high-water.json",
        fixture.pin_path,
        fixture.witness,
        fixture.root_log,
        witness_mac_key=fixture.witness_key,
        root_mac_key=fixture.root_key_mac,
        caller_id=RUNTIME,
    )
    _assert_code(nested.select(), "trust_configuration")
    _assert_code(failure("POTENTIAL_MANIPULATION"), "trust_configuration")
