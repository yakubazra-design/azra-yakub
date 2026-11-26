"""Trust-policy publication, activation, and selection.

Releases, approvals, and activations are immutable files. Readers select the
sequence named by the external witness when the local high-water record and
the activation file carry the same digests. A newer activation file stays
pending until the witness advances. This module does not open the
investigation ledger, does not read environment secrets, and does not contact
a network or a cloud KMS.
"""

from __future__ import annotations

import base64
import datetime
import errno
import hashlib
import hmac
import json
import os
import re
import shutil
import ssl
import threading
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from app.c2pa_statuses import ASSESSMENT_OUTCOMES, CREDENTIAL_STATUSES, FAILURE_CODES

MAX_TRUST_BUNDLE_BYTES = 64 * 1024
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

DOMAIN_RELEASE = "realitycheck-trust-release-v1"
DOMAIN_ACTIVATE = "realitycheck-trust-activate-v1"
DOMAIN_ADMIN_KEY = "realitycheck-admin-key-v1"
DOMAIN_APPROVAL = "realitycheck-trust-approval-v1"
DOMAIN_SUSPENSION = "realitycheck-trust-suspension-v1"
DOMAIN_REVIEW = "realitycheck-trust-review-v1"
_CONFIRM = b"realitycheck-root-confirm-v1\x00"
_REQUEST = b"realitycheck-witness-request-v1\x00"

_ROLE_DOMAIN = {
    "trust-approver": DOMAIN_APPROVAL,
    "security-administrator": DOMAIN_SUSPENSION,
    "security-reviewer": DOMAIN_REVIEW,
}
_RELEASE_KEYS = {
    "manifestDigest",
    "purpose",
    "releaseSequence",
    "rootFingerprint",
    "suspensionDigest",
    "suspensions",
    "timestampDigest",
    "validFrom",
}
_APPROVAL_KEYS = {
    "approvedAt",
    "keyId",
    "personId",
    "releaseDigest",
    "releaseSequence",
    "role",
}
_AUTHORIZATION_KEYS = {
    "documentFingerprint",
    "keyId",
    "notAfter",
    "notBefore",
    "personId",
    "role",
    "spki",
    "spkiFingerprint",
    "status",
}
_ACTIVATION_KEYS = {"releaseDigest", "releaseSequence", "suspensionDigest"}
_ENTRY_KEYS = {"certificateFingerprint", "suspendedAt"}
_ROLES = set(_ROLE_DOMAIN) | {"release-signer"}

class CanonicalError(ValueError):
    """A document is not in the canonical form signed releases use."""


class WitnessTransportError(Exception):
    """A witness write may have been applied, but its response was lost."""


@dataclass(frozen=True)
class WitnessValue:
    sequence: int | None = None
    activation_digest: bytes | None = None
    suspension_digest: bytes | None = None

    @property
    def empty(self) -> bool:
        return self.sequence is None


class WitnessReply:
    def __init__(self, kind, value, request_id, reason, mac):
        self.kind = kind
        self.value = value
        self.request_id = request_id
        self.reason = reason
        self.mac = mac


class RootReply:
    def __init__(self, kind, entries, generation, reason, mac):
        self.kind = kind
        self.entries = entries
        self.generation = generation
        self.reason = reason
        self.mac = mac


class SignedRelease:
    """One fully signed release. The store verifies it and does not hold private keys."""

    def __init__(self, body, signature, manifest_pem, timestamp_pem, approvals, authorizations, activation_signature):
        self.body = body
        self.signature = signature
        self.manifest_pem = manifest_pem
        self.timestamp_pem = timestamp_pem
        self.approvals = approvals
        self.authorizations = authorizations
        self.activation_signature = activation_signature

    @property
    def sequence(self):
        return self.body.get("releaseSequence") if isinstance(self.body, dict) else None


def failure(code: str, **extra) -> dict:
    if code not in FAILURE_CODES:
        code = "trust_configuration"
    body = {
        "status": "verification_failed",
        "failureCode": code,
        "credentialStatus": None,
        "assessment": None,
    }
    body.update(extra)
    return body


def _ok(status: str, **extra) -> dict:
    body = {
        "status": status,
        "failureCode": None,
        "credentialStatus": None,
        "assessment": None,
    }
    body.update(extra)
    return body


def _separated(result: dict) -> dict:
    """Technical results stay outside credential findings and assessment outcomes."""
    if result.get("status") in CREDENTIAL_STATUSES | ASSESSMENT_OUTCOMES:
        return failure("trust_configuration")
    if result.get("failureCode") in CREDENTIAL_STATUSES | ASSESSMENT_OUTCOMES:
        return failure("trust_configuration")
    return result


def canonical_json(value, *, top_null=()):
    checked = _check(value, top_null=set(top_null), top=True)
    encoded = json.dumps(checked, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return encoded.encode("utf-8")


def _check(value, *, top_null, top):
    if value is None:
        raise CanonicalError("null")
    if isinstance(value, bool):
        raise CanonicalError("bool")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise CanonicalError("nfc")
        return value
    if isinstance(value, list):
        return [_check(item, top_null=top_null, top=False) for item in value]
    if isinstance(value, dict):
        checked = {}
        for key in sorted(value, key=lambda item: item.encode("utf-8")):
            if not isinstance(key, str) or unicodedata.normalize("NFC", key) != key:
                raise CanonicalError("key")
            item = value[key]
            if item is None:
                if not (top and key in top_null):
                    raise CanonicalError("null")
                checked[key] = None
                continue
            checked[key] = _check(item, top_null=top_null, top=False)
        return checked
    raise CanonicalError("type")


def _pairs(pairs):
    seen = set()
    result = {}
    for key, item in pairs:
        if key in seen:
            raise CanonicalError("duplicate")
        seen.add(key)
        result[key] = item
    return result


def _parse_int(text):
    if text.startswith("-"):
        digits = text[1:]
        if not digits.isdigit() or text == "-0" or (len(digits) > 1 and digits.startswith("0")):
            raise ValueError("integer")
        return -int(digits)
    if not text.isdigit() or (len(text) > 1 and text.startswith("0")):
        raise ValueError("integer")
    return int(text)


def _reject_float(_text):
    raise ValueError("float")


def parse_canonical(data: bytes, *, top_null=()):
    if not isinstance(data, bytes) or data.startswith(b"\xef\xbb\xbf") or data.endswith((b"\n", b"\r")):
        raise CanonicalError("encoding")
    try:
        text = data.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_parse_int,
            parse_float=_reject_float,
        )
    except (UnicodeError, json.JSONDecodeError, CanonicalError, ValueError) as error:
        raise CanonicalError("json") from error
    try:
        encoded = canonical_json(value, top_null=top_null)
    except CanonicalError as error:
        raise CanonicalError("shape") from error
    if encoded != data:
        raise CanonicalError("canonical")
    return value


def sha256_digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def confirmation_digest(fingerprint: str) -> str:
    return hashlib.sha256(_CONFIRM + bytes.fromhex(fingerprint)).hexdigest()


def suspension_digest(entries) -> bytes:
    return sha256_digest(canonical_json(entries))


def public_spki(public_key) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def spki_fingerprint(spki: bytes) -> str:
    return sha256_hex(spki)


def _domain_payload(domain: str, payload: bytes) -> bytes:
    if not isinstance(domain, str) or not domain.isascii():
        raise CanonicalError("domain")
    return domain.encode("ascii") + b"\x00" + payload


def sign_raw(private_key, domain: str, payload: bytes) -> bytes:
    der = private_key.sign(_domain_payload(domain, payload), ec.ECDSA(hashes.SHA256()))
    r_value, s_value = utils.decode_dss_signature(der)
    if s_value > _N // 2:
        s_value = _N - s_value
    return r_value.to_bytes(32, "big") + s_value.to_bytes(32, "big")


def sign_document(private_key, domain: str, document: dict) -> bytes:
    return sign_raw(private_key, domain, canonical_json(document))


def verify_raw(spki: bytes, domain: str, payload: bytes, signature: bytes) -> bool:
    if not isinstance(signature, bytes) or len(signature) != 64 or not isinstance(spki, bytes):
        return False
    r_value = int.from_bytes(signature[:32], "big")
    s_value = int.from_bytes(signature[32:], "big")
    if r_value <= 0 or s_value <= 0 or r_value >= _N or s_value > _N // 2:
        return False
    try:
        key = serialization.load_der_public_key(spki)
    except (ValueError, TypeError):
        return False
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
        return False
    der = utils.encode_dss_signature(r_value, s_value)
    try:
        key.verify(der, _domain_payload(domain, payload), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def verify_document(spki: bytes, domain: str, document: dict, signature: bytes) -> bool:
    try:
        payload = canonical_json(document)
    except CanonicalError:
        return False
    return verify_raw(spki, domain, payload, signature)


def witness_mac_message(kind: str, value: WitnessValue, request_id: bytes | None, reason: str) -> bytes:
    record = None
    if not value.empty:
        record = {
            "activationDigest": value.activation_digest.hex(),
            "sequence": value.sequence,
            "suspensionDigest": value.suspension_digest.hex(),
        }
    return canonical_json(
        {
            "kind": kind,
            "reason": reason,
            "record": record,
            "requestId": request_id.hex() if request_id else "",
        },
        top_null=("record",),
    )


def mac_bytes(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


def root_mac_message(kind: str, entries, generation: int, reason: str) -> bytes:
    return canonical_json({
        "entries": entries,
        "generation": generation,
        "kind": kind,
        "reason": reason,
    })


def valid_bundle(pem: bytes) -> bool:
    if not isinstance(pem, (bytes, bytearray)):
        return False
    blob = bytes(pem)
    if not blob or len(blob) > MAX_TRUST_BUNDLE_BYTES or b"\x00" in blob or b"PRIVATE KEY-----" in blob:
        return False
    try:
        text = blob.decode("utf-8")
    except UnicodeError:
        return False
    rest = text.strip()
    begin = "-----BEGIN CERTIFICATE-----"
    end_mark = "-----END CERTIFICATE-----"
    found = False
    while rest:
        rest = rest.lstrip("\n")
        if not rest:
            break
        if not rest.startswith(begin):
            return False
        end = rest.find(end_mark)
        if end < 0:
            return False
        end += len(end_mark)
        block = rest[:end]
        rest = rest[end:]
        try:
            der = ssl.PEM_cert_to_DER_cert(block)
        except (ssl.SSLError, ValueError):
            return False
        if not der:
            return False
        found = True
    return found and not rest.strip()


def _timestamp(value) -> bool:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        return False
    try:
        datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


def _hex64(value) -> bool:
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def _identifier(value) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 128 and value.isascii() and "\x00" not in value


def _b64_spki(value):
    if not isinstance(value, str) or not value or any(char.isspace() for char in value):
        return None
    try:
        der = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        return None
    try:
        key = serialization.load_der_public_key(der)
    except (ValueError, TypeError):
        return None
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
        return None
    if public_spki(key) != der:
        return None
    return der


def _entry_set(entries) -> set[bytes]:
    return {canonical_json(entry) for entry in entries}


def _fsync_dir(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    _fsync_dir(path.parent)


def _exclusive_write(path: Path, data: bytes) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.partial")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.link(temporary, path)
    except FileExistsError:
        os.unlink(temporary)
        return False
    os.unlink(temporary)
    _fsync_dir(path.parent)
    return True


def _inside(child: Path, parent: Path) -> bool:
    try:
        target = child.resolve()
        root = parent.resolve()
    except OSError:
        return True
    return target == root or root in target.parents


def write_pin_file(path: Path, *, active_spki: bytes, verify_only=()) -> None:
    active = _pin_key(active_spki)
    others = []
    for spki, ceiling in verify_only:
        if not isinstance(ceiling, int) or isinstance(ceiling, bool) or ceiling < 1:
            raise CanonicalError("ceiling")
        item = _pin_key(spki)
        item["throughSequence"] = ceiling
        others.append(item)
    others.sort(key=lambda item: item["fingerprint"])
    if any(item["fingerprint"] == active["fingerprint"] for item in others):
        raise CanonicalError("pin")
    _atomic_write(path, canonical_json({"active": active, "verifyOnly": others}))


def _pin_key(spki: bytes) -> dict:
    der = bytes(spki)
    _b64 = base64.b64encode(der).decode("ascii")
    if _b64_spki(_b64) != der:
        raise CanonicalError("spki")
    return {"fingerprint": spki_fingerprint(der), "spki": _b64}


def activation_document(release_digest: str, sequence: int, suspension: str) -> dict:
    return {
        "releaseDigest": release_digest,
        "releaseSequence": sequence,
        "suspensionDigest": suspension,
    }


class TrustStore:
    """File-backed releases plus injected witness and root-control services."""

    def __init__(self, trust_root, local_path, pin_path, witness, root_control, *, witness_mac_key, root_mac_key, caller_id):
        self.trust_root = Path(trust_root)
        self.local_path = Path(local_path)
        self.pin_path = Path(pin_path)
        self.witness = witness
        self.root_control = root_control
        self.witness_mac_key = bytes(witness_mac_key)
        self.root_mac_key = bytes(root_mac_key)
        self.caller_id = caller_id
        self._lock = threading.Lock()
        self._layout_error = None
        if (
            not isinstance(self.caller_id, str)
            or not self.caller_id
            or len(self.witness_mac_key) < 32
            or len(self.root_mac_key) < 32
            or _inside(self.local_path, self.trust_root)
            or _inside(self.pin_path, self.trust_root)
            or self.local_path.resolve() == self.pin_path.resolve()
        ):
            self._layout_error = failure("trust_configuration")
            return
        self.releases = self.trust_root / "releases"
        self.activations = self.trust_root / "activations"
        self.releases.mkdir(parents=True, exist_ok=True)
        self.activations.mkdir(parents=True, exist_ok=True)
        self.local_path.parent.mkdir(parents=True, exist_ok=True)

    def publish(self, signed: SignedRelease) -> dict:
        for step in (
            lambda: self.write_release(signed),
            lambda: self.write_activation(signed.sequence, signed.activation_signature),
            lambda: self.record_pending(signed.sequence),
            lambda: self.advance_witness(),
            lambda: self.promote_local(),
        ):
            result = step()
            if result["status"] == "verification_failed":
                return result
        return self.select()

    def write_release(self, signed: SignedRelease) -> dict:
        blocked = self._gate()
        if blocked:
            return blocked
        checked = self._check_signed(signed)
        if checked["status"] == "verification_failed":
            return checked
        witness, error = self._read_witness()
        if error:
            return error
        local, error = self._read_local(required=witness is not None and not witness.empty)
        if error:
            return error
        root_state, error = self._read_root_state(local)
        if error:
            return error
        sequence = signed.sequence
        expected = 1 if witness.empty else witness.sequence + 1
        if sequence < expected:
            return failure("policy_downgrade")
        if sequence > expected:
            return failure("sequence_state_inconsistent")
        if local is not None and local["pending"] is not None:
            return failure("sequence_state_inconsistent")
        if not witness.empty:
            if local is None or local["committed"] is None:
                return failure("sequence_state_stale")
            mismatch = _committed_mismatch(local["committed"], witness)
            if mismatch:
                return failure(mismatch)
        root_error = self._verify_authorizations_against_pin(
            signed.body["rootFingerprint"],
            signed.authorizations,
        )
        if root_error:
            return root_error
        previous = [] if local is None or local["committed"] is None else local["committed"]["suspensions"]
        if local is not None and local["committed"] is not None and not previous and local["committed"]["suspensionDigest"] != sha256_hex(canonical_json([])):
            return failure("suspension_history_unavailable")
        coverage = _coverage(previous, signed.body["suspensions"], signed.body["purpose"])
        if coverage:
            return failure(coverage)
        allowed = self._authorize_root(root_state, sequence, signed.body["rootFingerprint"])
        if allowed["status"] == "verification_failed":
            return allowed
        final = self.releases / str(sequence)
        if final.exists():
            return failure("sequence_conflict")
        staging = self.releases / f".partial-{sequence}-{os.getpid()}-{threading.get_ident()}"
        staging.mkdir()
        try:
            _write_bytes(staging / "release.json", canonical_json(signed.body))
            _write_bytes(staging / "release.sig", signed.signature)
            _write_bytes(staging / "manifest.pem", bytes(signed.manifest_pem))
            _write_bytes(staging / "timestamp.pem", bytes(signed.timestamp_pem))
            _write_bytes(staging / "approvals.json", canonical_json(_signed_list(signed.approvals)))
            _write_bytes(staging / "authorizations.json", canonical_json(_signed_list(signed.authorizations)))
            _fsync_dir(staging)
            os.rename(staging, final)
        except OSError as error:
            shutil.rmtree(staging, ignore_errors=True)
            if error.errno in {errno.EEXIST, errno.ENOTEMPTY}:
                return failure("sequence_conflict")
            return failure("trust_configuration")
        _fsync_dir(self.releases)
        return _ok("staged", releaseSequence=sequence)

    def write_activation(self, sequence, signature: bytes) -> dict:
        blocked = self._gate()
        if blocked:
            return blocked
        loaded, error = self._load_release(sequence)
        if error:
            return error
        body = activation_document(
            sha256_hex(canonical_json(loaded["body"])),
            sequence,
            loaded["body"]["suspensionDigest"],
        )
        signer = _release_signer(loaded["authorizations"])
        if signer is None or not verify_document(signer, DOMAIN_ACTIVATE, body, signature):
            return failure("activation_record_corrupt")
        envelope = canonical_json({"body": body, "signature": signature.hex()})
        path = self.activations / str(sequence)
        if path.exists() or not _exclusive_write(path, envelope):
            return failure("sequence_conflict")
        return _ok("activation", releaseSequence=sequence)

    def record_pending(self, sequence) -> dict:
        blocked = self._gate()
        if blocked:
            return blocked
        with self._lock:
            activation, error = self._load_activation(sequence)
            if error:
                return error
            loaded, error = self._load_release(sequence)
            if error:
                return error
            release_hex = sha256_hex(canonical_json(loaded["body"]))
            if activation["body"]["releaseDigest"] != release_hex:
                return failure("activation_inconsistent")
            if activation["body"]["suspensionDigest"] != loaded["body"]["suspensionDigest"]:
                return failure("activation_inconsistent")
            witness, error = self._read_witness()
            if error:
                return error
            local, error = self._read_local(required=not witness.empty)
            if error:
                return error
            if local is not None and local["pending"] is not None:
                if _field_matches_activation(local["pending"], activation):
                    return _ok("pending", releaseSequence=sequence)
                return failure("sequence_state_inconsistent")
            previous = []
            generation = 0 if local is None else local["rootLogGeneration"]
            committed = None if local is None else local["committed"]
            if committed is not None:
                previous = committed["suspensions"]
            elif not witness.empty:
                return failure("suspension_history_unavailable")
            coverage = _coverage(previous, loaded["body"]["suspensions"], loaded["body"]["purpose"])
            if coverage:
                return failure(coverage)
            pending = {
                "activationDigest": sha256_hex(canonical_json(activation["body"])),
                "sequence": sequence,
                "suspensionDigest": loaded["body"]["suspensionDigest"],
                "suspensions": loaded["body"]["suspensions"],
            }
            if pending["activationDigest"] != sha256_hex(canonical_json(activation["body"])):
                return failure("activation_inconsistent")
            self._write_local(committed, pending, generation)
            return _ok("pending", releaseSequence=sequence)

    def advance_witness(self) -> dict:
        blocked = self._gate()
        if blocked:
            return blocked
        with self._lock:
            local, error = self._read_local(required=True)
            if error:
                return error
            if local is None or local["pending"] is None:
                return failure("sequence_state_inconsistent")
            pending = local["pending"]
            witness, error = self._read_witness()
            if error:
                return error
            if _value_matches_field(witness, pending):
                return _ok("witness", releaseSequence=pending["sequence"])
            if witness.empty:
                if pending["sequence"] != 1 or local["committed"] is not None:
                    return failure("sequence_state_inconsistent")
                expected = WitnessValue()
            else:
                if local["committed"] is None or not _value_matches_field(witness, local["committed"]):
                    return failure("sequence_state_inconsistent")
                if pending["sequence"] != witness.sequence + 1:
                    return failure("sequence_state_inconsistent")
                expected = witness
            new = WitnessValue(
                pending["sequence"],
                bytes.fromhex(pending["activationDigest"]),
                bytes.fromhex(pending["suspensionDigest"]),
            )
            stored, error = self._cas(expected, new)
            if error:
                return error
            if stored.sequence != new.sequence:
                return failure("witness_conflict")
            return _ok("witness", releaseSequence=new.sequence)

    def promote_local(self) -> dict:
        blocked = self._gate()
        if blocked:
            return blocked
        with self._lock:
            local, error = self._read_local(required=True)
            if error:
                return error
            witness, error = self._read_witness()
            if error:
                return error
            if local is None or local["pending"] is None or witness.empty:
                return failure("sequence_state_inconsistent")
            if not _value_matches_field(witness, local["pending"]):
                return failure("sequence_state_inconsistent")
            self._write_local(local["pending"], None, local["rootLogGeneration"])
            return _ok("promoted", releaseSequence=witness.sequence)

    def recover(self) -> dict:
        blocked = self._gate()
        if blocked:
            return blocked
        witness, error = self._read_witness()
        if error:
            return error
        local, error = self._read_local(required=False)
        if error:
            return error
        if isinstance(local, dict) and local.get("status") == "verification_failed":
            return local
        if witness.empty and (local is None or (local["committed"] is None and local["pending"] is None)):
            if (self.activations / "1").is_file():
                return self._finish_forward(1)
            return _ok("recovered", action="none", releaseSequence=None)
        if witness.empty:
            if local and local["committed"] is None and local["pending"] and local["pending"]["sequence"] == 1:
                return self._finish_from_pending()
            return failure("sequence_state_inconsistent")
        if local is None:
            return failure("sequence_state_stale")
        pending = local["pending"]
        committed = local["committed"]
        if pending is not None and _value_matches_field(witness, pending):
            result = self.promote_local()
            if result["status"] == "verification_failed":
                return result
            return _ok("recovered", action="completed", releaseSequence=witness.sequence)
        if pending is not None and committed is not None and _value_matches_field(witness, committed):
            if pending["sequence"] == witness.sequence + 1:
                return self._finish_from_pending()
            return failure("sequence_state_inconsistent")
        if pending is None and committed is not None and _value_matches_field(witness, committed):
            nxt = witness.sequence + 1
            if (self.activations / str(nxt)).is_file():
                return self._finish_forward(nxt)
            return _ok("recovered", action="none", releaseSequence=witness.sequence)
        if committed is not None and committed["sequence"] < witness.sequence and (pending is None or pending["sequence"] < witness.sequence):
            return failure("sequence_state_stale")
        return failure("sequence_state_inconsistent")

    def select(self) -> dict:
        blocked = self._gate()
        if blocked:
            return blocked
        witness, error = self._read_witness()
        if error:
            return error
        if witness.empty:
            return failure("no_committed_policy")
        local, error = self._read_local(required=True)
        if error:
            return error
        if local is None:
            return failure("sequence_state_stale")
        root_state, error = self._read_root_state(local)
        if error:
            return error
        if root_state.get("inconsistent"):
            return failure("root_pin_inconsistent")
        field, code = _matching_field(local, witness)
        if code:
            return failure(code)
        activation, error = self._load_activation(witness.sequence)
        if error:
            return error
        body_digest = sha256_hex(canonical_json(activation["body"]))
        if body_digest != field["activationDigest"] or activation["body"]["suspensionDigest"] != field["suspensionDigest"]:
            return failure("activation_inconsistent")
        loaded, error = self._load_release(witness.sequence)
        if error:
            return error
        if sha256_hex(canonical_json(loaded["body"])) != activation["body"]["releaseDigest"]:
            return failure("activation_inconsistent")
        if sha256_hex(canonical_json(loaded["body"]["suspensions"])) != field["suspensionDigest"]:
            return failure("suspension_state_stale")
        if _entry_set(field["suspensions"]) != _entry_set(loaded["body"]["suspensions"]):
            return failure("suspension_state_stale")
        allowed = self._authorize_root(root_state, witness.sequence, loaded["body"]["rootFingerprint"])
        if allowed["status"] == "verification_failed":
            return allowed
        if root_state["generation"] > local["rootLogGeneration"]:
            with self._lock:
                current, error = self._read_local(required=True)
                if error or current is None:
                    return error or failure("sequence_state_stale")
                self._write_local(current["committed"], current["pending"], root_state["generation"])
        return _separated(_ok(
            "selected",
            releaseSequence=witness.sequence,
            manifestTrustPem=loaded["manifest"].decode("utf-8"),
            timestampTrustPem=loaded["timestamp"].decode("utf-8"),
            activationDigest=field["activationDigest"],
            suspensionDigest=field["suspensionDigest"],
            rootUse=allowed["rootUse"],
            purpose=loaded["body"]["purpose"],
        ))

    def pin(self) -> dict:
        selected = self.select()
        if selected["status"] != "selected":
            return selected
        return _ok(
            "pinned",
            releaseSequence=selected["releaseSequence"],
            activationDigest=selected["activationDigest"],
            suspensionDigest=selected["suspensionDigest"],
            manifestTrustPem=selected["manifestTrustPem"],
            timestampTrustPem=selected["timestampTrustPem"],
        )

    def revalidate(self, pinned: dict) -> dict:
        current = self.select()
        if current["status"] != "selected":
            return current
        same = (
            current["releaseSequence"] == pinned.get("releaseSequence")
            and current["activationDigest"] == pinned.get("activationDigest")
            and current["suspensionDigest"] == pinned.get("suspensionDigest")
        )
        if same:
            return _ok("confirmed", releaseSequence=current["releaseSequence"], activationDigest=current["activationDigest"])
        if isinstance(pinned.get("releaseSequence"), int) and current["releaseSequence"] > pinned["releaseSequence"]:
            return failure("policy_superseded", releaseSequence=current["releaseSequence"])
        return failure("policy_downgrade")

    def inspect(self, sequence: int) -> dict:
        blocked = self._gate()
        if blocked:
            return blocked
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
            return failure("trust_configuration")
        local, error = self._read_local(required=False)
        if error:
            return error
        root_state, error = self._read_root_state(local if isinstance(local, dict) and "rootLogGeneration" in local else {"rootLogGeneration": 0, "committed": None, "pending": None})
        if error:
            return error
        if root_state.get("inconsistent"):
            return failure("root_pin_inconsistent")
        loaded, error = self._load_release(sequence)
        if error:
            return error
        allowed = self._authorize_root(root_state, sequence, loaded["body"]["rootFingerprint"])
        if allowed["status"] == "verification_failed":
            return allowed
        return _separated(_ok(
            "historical",
            releaseSequence=sequence,
            rootUse=allowed["rootUse"],
            manifestTrustPem=loaded["manifest"].decode("utf-8"),
            timestampTrustPem=loaded["timestamp"].decode("utf-8"),
        ))

    def suspend_root(self, caller_ids, fingerprint: str, at: str) -> dict:
        blocked = self._gate()
        if blocked:
            return blocked
        if not _two_people(caller_ids) or not _hex64(fingerprint) or not _timestamp(at):
            return failure("root_recovery_incomplete")
        witness, error = self._read_witness()
        if error:
            return error
        if witness.empty:
            return failure("sequence_state_inconsistent")
        local, error = self._read_local(required=True)
        if error or local is None:
            return error or failure("sequence_state_stale")
        try:
            reply = self.root_control.append_suspension(tuple(caller_ids), fingerprint, witness.sequence, at)
        except WitnessTransportError:
            return failure("root_suspension_unavailable")
        error = self._authenticated_root(reply)
        if error:
            return error
        if reply.kind != "appended":
            return failure("root_recovery_incomplete")
        with self._lock:
            current, error = self._read_local(required=True)
            if error or current is None:
                return error or failure("sequence_state_stale")
            self._write_local(current["committed"], current["pending"], reply.generation)
        return _ok("root-suspended", generation=reply.generation, witnessSequence=witness.sequence)

    def replace_root(self, caller_ids, fingerprint: str, confirmations, at: str) -> dict:
        blocked = self._gate()
        if blocked:
            return blocked
        if not _two_people(caller_ids) or not _hex64(fingerprint) or not _timestamp(at):
            return failure("root_recovery_incomplete")
        if isinstance(confirmations, list):
            try:
                confirmations = sorted(confirmations, key=lambda item: item["personId"])
            except (TypeError, KeyError):
                return failure("root_recovery_incomplete")
        if not _valid_confirmations(fingerprint, confirmations):
            return failure("root_recovery_incomplete")
        try:
            reply = self.root_control.append_replacement(tuple(caller_ids), fingerprint, confirmations, at)
        except WitnessTransportError:
            return failure("root_suspension_unavailable")
        error = self._authenticated_root(reply)
        if error:
            return error
        if reply.kind != "appended":
            return failure("root_recovery_incomplete")
        local, error = self._read_local(required=False)
        if isinstance(local, dict) and "rootLogGeneration" in local:
            with self._lock:
                current, read_error = self._read_local(required=True)
                if read_error or current is None:
                    return read_error or failure("sequence_state_stale")
                self._write_local(current["committed"], current["pending"], max(current["rootLogGeneration"], reply.generation))
        return _ok("root-replaced", generation=reply.generation, fingerprint=fingerprint)

    def _finish_forward(self, sequence) -> dict:
        pending = self.record_pending(sequence)
        if pending["status"] == "verification_failed":
            return pending
        return self._finish_from_pending()

    def _finish_from_pending(self) -> dict:
        advanced = self.advance_witness()
        if advanced["status"] == "verification_failed":
            return advanced
        promoted = self.promote_local()
        if promoted["status"] == "verification_failed":
            return promoted
        return _ok("recovered", action="completed", releaseSequence=promoted["releaseSequence"])

    def _gate(self):
        return self._layout_error

    def _check_signed(self, signed: SignedRelease):
        body = signed.body
        if not isinstance(body, dict) or set(body) != _RELEASE_KEYS:
            return failure("trust_configuration")
        if body.get("purpose") not in {"policy", "suspension"}:
            return failure("trust_configuration")
        if not isinstance(body.get("releaseSequence"), int) or isinstance(body.get("releaseSequence"), bool) or body["releaseSequence"] < 1:
            return failure("trust_configuration")
        if not _hex64(body.get("manifestDigest")) or not _hex64(body.get("timestampDigest")) or not _hex64(body.get("suspensionDigest")) or not _hex64(body.get("rootFingerprint")):
            return failure("trust_configuration")
        if not _timestamp(body.get("validFrom")) or not isinstance(body.get("suspensions"), list):
            return failure("trust_configuration")
        if not valid_bundle(signed.manifest_pem) or not valid_bundle(signed.timestamp_pem):
            return failure("trust_configuration")
        if sha256_hex(bytes(signed.manifest_pem)) != body["manifestDigest"]:
            return failure("trust_configuration")
        if sha256_hex(bytes(signed.timestamp_pem)) != body["timestampDigest"]:
            return failure("trust_configuration")
        entries, entry_error = _suspension_entries(body["suspensions"])
        if entry_error:
            return failure(entry_error)
        if sha256_hex(canonical_json(entries)) != body["suspensionDigest"]:
            return failure("trust_configuration")
        try:
            canonical_json(body)
        except CanonicalError:
            return failure("trust_configuration")
        authorizations, auth_error = _authorizations(signed.authorizations)
        if auth_error:
            return failure(auth_error)
        approvals, approval_error = _approvals(signed.approvals, body, authorizations)
        if approval_error:
            return failure(approval_error)
        if body["purpose"] == "policy":
            if len(approvals) != 2 or {item["role"] for item in approvals} != {"trust-approver"}:
                return failure("unauthorized_approval")
        else:
            roles = [item["role"] for item in approvals]
            if (
                len(approvals) != 2
                or roles.count("security-administrator") != 1
                or roles.count("security-reviewer") != 1
            ):
                return failure("unauthorized_approval")
        people = [item["personId"] for item in approvals]
        documents = [item["documentFingerprint"] for item in approvals]
        if len(set(people)) != len(people) or len(set(documents)) != len(documents):
            return failure("duplicate_approver")
        signer = next(item for item in authorizations if item["role"] == "release-signer" and item["status"] == "authorized")
        if not verify_document(signer["spkiDer"], DOMAIN_RELEASE, body, signed.signature):
            return failure("untrusted_admin_key")
        return _ok("checked")

    def _authorize_root(self, root_state, sequence, fingerprint):
        if root_state.get("inconsistent"):
            return failure("root_pin_inconsistent")
        pin = root_state["pin"]
        suspended = root_state["suspensions"].get(fingerprint)
        replacement = root_state["replacement"]
        spki = _pin_spki(pin, fingerprint)
        if suspended:
            if sequence > suspended["witnessSequence"]:
                return failure("root_suspended")
            if spki is None:
                return failure("untrusted_admin_key")
            return _ok("authorized", rootUse="verify-only")
        if replacement and pin["active"]["fingerprint"] != replacement:
            return failure("root_pin_inconsistent")
        if pin["active"]["fingerprint"] != fingerprint or spki is None:
            return failure("untrusted_admin_key")
        return _ok("authorized", rootUse="active")

    def _read_root_state(self, local):
        try:
            reply = self.root_control.read(self.caller_id)
        except WitnessTransportError:
            return None, failure("root_suspension_unavailable")
        error = self._authenticated_root(reply)
        if error:
            return None, error
        if reply.kind == "unavailable":
            return None, failure("root_suspension_unavailable")
        if reply.kind != "record":
            return None, failure("root_suspension_unavailable")
        generation = local["rootLogGeneration"] if isinstance(local, dict) and "rootLogGeneration" in local else 0
        if reply.generation < generation:
            return None, failure("sequence_state_stale")
        pin, error = self._read_pin()
        if error:
            return None, error
        parsed, error = _parse_root_entries(reply.entries, pin)
        if error:
            return None, error
        parsed["generation"] = reply.generation
        parsed["pin"] = pin
        return parsed, None

    def _authenticated_root(self, reply):
        if reply is None or reply.kind == "unavailable":
            return failure("root_suspension_unavailable")
        try:
            message = root_mac_message(reply.kind, reply.entries, reply.generation, reply.reason)
        except CanonicalError:
            return failure("root_suspension_unavailable")
        expected = mac_bytes(self.root_mac_key, message)
        if not isinstance(reply.mac, bytes) or not hmac.compare_digest(expected, reply.mac):
            return failure("root_suspension_unavailable")
        return None

    def _read_pin(self):
        if not self.pin_path.is_file():
            return None, failure("root_pin_unavailable")
        try:
            pin = parse_canonical(self.pin_path.read_bytes())
        except (OSError, CanonicalError):
            return None, failure("root_pin_unavailable")
        if not isinstance(pin, dict) or set(pin) != {"active", "verifyOnly"}:
            return None, failure("root_pin_unavailable")
        active = pin["active"]
        if not isinstance(active, dict) or set(active) != {"fingerprint", "spki"}:
            return None, failure("root_pin_unavailable")
        der = _b64_spki(active.get("spki"))
        if der is None or spki_fingerprint(der) != active.get("fingerprint"):
            return None, failure("root_pin_unavailable")
        if not isinstance(pin["verifyOnly"], list):
            return None, failure("root_pin_unavailable")
        seen = {active["fingerprint"]}
        normalized = []
        for item in pin["verifyOnly"]:
            if not isinstance(item, dict) or set(item) != {"fingerprint", "spki", "throughSequence"}:
                return None, failure("root_pin_unavailable")
            other = _b64_spki(item.get("spki"))
            ceiling = item.get("throughSequence")
            if (
                other is None
                or spki_fingerprint(other) != item.get("fingerprint")
                or item["fingerprint"] in seen
                or not isinstance(ceiling, int)
                or isinstance(ceiling, bool)
                or ceiling < 1
            ):
                return None, failure("root_pin_unavailable")
            seen.add(item["fingerprint"])
            normalized.append(item)
        if normalized != sorted(normalized, key=lambda item: item["fingerprint"]):
            return None, failure("root_pin_unavailable")
        return pin, None

    def _read_witness(self):
        try:
            reply = self.witness.read(self.caller_id)
        except WitnessTransportError:
            return None, failure("witness_unavailable")
        except Exception:
            return None, failure("witness_corrupt")
        error = self._authenticated_witness(reply)
        if error:
            return None, error
        try:
            if reply.kind == "rejected":
                return None, failure("witness_conflict")
            if reply.kind == "empty":
                if not reply.value.empty:
                    return None, failure("witness_corrupt")
                return reply.value, None
            if reply.kind != "record" or not _concrete(reply.value):
                return None, failure("witness_corrupt")
            return reply.value, None
        except Exception:
            return None, failure("witness_corrupt")

    def _cas(self, expected: WitnessValue, new: WitnessValue):
        request_id = sha256_digest(_REQUEST + new.activation_digest)[:16]

        def once():
            try:
                return self.witness.compare_and_set(self.caller_id, expected, new, request_id)
            except WitnessTransportError:
                return None

        try:
            reply = once()
        except Exception:
            return None, failure("witness_corrupt")
        if reply is None:
            try:
                reply = once()
            except Exception:
                return None, failure("witness_corrupt")
            if reply is None:
                return None, failure("witness_unavailable")
        error = self._authenticated_witness(reply)
        if error:
            return None, error
        try:
            if reply.kind == "rejected":
                return None, failure("witness_conflict")
            if reply.kind not in {"applied", "idempotent"} or not _same_value(reply.value, new):
                return None, failure("witness_conflict")
            return reply.value, None
        except Exception:
            return None, failure("witness_corrupt")

    def _authenticated_witness(self, reply):
        try:
            if not isinstance(reply, WitnessReply):
                return failure("witness_corrupt")
            if reply.kind == "unavailable":
                return failure("witness_unavailable")
            if not isinstance(reply.kind, str) or not isinstance(reply.reason, str):
                return failure("witness_corrupt")
            if not isinstance(reply.value, WitnessValue):
                return failure("witness_corrupt")
            if reply.request_id is not None and not isinstance(reply.request_id, bytes):
                return failure("witness_corrupt")
            message = witness_mac_message(reply.kind, reply.value, reply.request_id, reply.reason)
            expected = mac_bytes(self.witness_mac_key, message)
            if not isinstance(reply.mac, bytes) or len(reply.mac) != len(expected):
                return failure("witness_corrupt")
            if not hmac.compare_digest(expected, reply.mac):
                return failure("witness_corrupt")
            if reply.kind not in {"empty", "record", "applied", "idempotent", "rejected"}:
                return failure("witness_corrupt")
        except Exception:
            return failure("witness_corrupt")
        return None

    def _read_local(self, required: bool):
        if not self.local_path.exists():
            if required:
                return None, None
            return None, None
        try:
            parsed = parse_canonical(self.local_path.read_bytes(), top_null=("committed", "pending"))
        except (OSError, CanonicalError):
            return None, failure("sequence_state_inconsistent")
        if not isinstance(parsed, dict) or set(parsed) != {"committed", "pending", "rootLogGeneration"}:
            return None, failure("sequence_state_inconsistent")
        generation = parsed["rootLogGeneration"]
        if not isinstance(generation, int) or isinstance(generation, bool) or generation < 0:
            return None, failure("sequence_state_inconsistent")
        committed, error = _high_water_field(parsed["committed"])
        if error:
            return None, failure(error)
        pending, error = _high_water_field(parsed["pending"])
        if error:
            return None, failure(error)
        return {"committed": committed, "pending": pending, "rootLogGeneration": generation}, None

    def _write_local(self, committed, pending, generation) -> None:
        document = {
            "committed": committed,
            "pending": pending,
            "rootLogGeneration": generation,
        }
        _atomic_write(self.local_path, canonical_json(document, top_null=("committed", "pending")))

    def _load_release(self, sequence):
        directory = self.releases / str(sequence)
        if not directory.is_dir():
            return None, failure("activation_record_missing")
        try:
            body = parse_canonical((directory / "release.json").read_bytes())
            signature = (directory / "release.sig").read_bytes()
            manifest = (directory / "manifest.pem").read_bytes()
            timestamp = (directory / "timestamp.pem").read_bytes()
            approvals = parse_canonical((directory / "approvals.json").read_bytes())
            authorizations = parse_canonical((directory / "authorizations.json").read_bytes())
        except (OSError, CanonicalError):
            return None, failure("activation_record_corrupt")
        signed = SignedRelease(body, signature, manifest, timestamp, _unwrap_signed(approvals), _unwrap_signed(authorizations), b"")
        checked = self._check_signed(signed)
        if checked["status"] == "verification_failed":
            return None, failure("activation_record_corrupt")
        if body.get("releaseSequence") != sequence:
            return None, failure("activation_record_corrupt")
        root_error = self._verify_authorizations_against_pin(body["rootFingerprint"], signed.authorizations)
        if root_error:
            return None, root_error
        return {"body": body, "manifest": manifest, "timestamp": timestamp, "authorizations": _authorizations(signed.authorizations)[0]}, None

    def _verify_authorizations_against_pin(self, fingerprint, authorizations):
        pin, error = self._read_pin()
        if error:
            return error
        spki = _pin_spki(pin, fingerprint)
        if spki is None:
            return failure("untrusted_admin_key")
        for item in authorizations:
            if not verify_document(spki, DOMAIN_ADMIN_KEY, item["body"], item["signature"]):
                return failure("untrusted_admin_key")
        return None

    def _load_activation(self, sequence):
        path = self.activations / str(sequence)
        if not path.is_file():
            return None, failure("activation_record_missing")
        try:
            envelope = parse_canonical(path.read_bytes())
        except (OSError, CanonicalError):
            return None, failure("activation_record_corrupt")
        if not isinstance(envelope, dict) or set(envelope) != {"body", "signature"}:
            return None, failure("activation_record_corrupt")
        body = envelope["body"]
        if not isinstance(body, dict) or set(body) != _ACTIVATION_KEYS:
            return None, failure("activation_record_corrupt")
        if body.get("releaseSequence") != sequence or not _hex64(body.get("releaseDigest")) or not _hex64(body.get("suspensionDigest")):
            return None, failure("activation_record_corrupt")
        try:
            signature = bytes.fromhex(envelope["signature"])
        except (TypeError, ValueError):
            return None, failure("activation_record_corrupt")
        loaded, error = self._load_release(sequence)
        if error:
            return None, error
        signer = _release_signer(loaded["authorizations"])
        if signer is None or not verify_document(signer, DOMAIN_ACTIVATE, body, signature):
            return None, failure("activation_record_corrupt")
        return {"body": body, "signature": signature}, None


def _write_bytes(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _signed_list(items) -> list:
    listed = []
    for item in items:
        listed.append({"body": item["body"], "signature": item["signature"].hex()})
    listed.sort(key=lambda item: canonical_json(item["body"]))
    return listed


def _unwrap_signed(items):
    if not isinstance(items, list):
        return []
    unwrapped = []
    for item in items:
        if not isinstance(item, dict) or set(item) != {"body", "signature"}:
            return []
        try:
            signature = bytes.fromhex(item["signature"])
        except (TypeError, ValueError):
            return []
        unwrapped.append({"body": item["body"], "signature": signature})
    return unwrapped


def _suspension_entries(entries):
    if not isinstance(entries, list):
        return None, "trust_configuration"
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != _ENTRY_KEYS:
            return None, "trust_configuration"
        if not _hex64(entry.get("certificateFingerprint")) or not _timestamp(entry.get("suspendedAt")):
            return None, "trust_configuration"
        if entry["certificateFingerprint"] in seen:
            return None, "trust_configuration"
        seen.add(entry["certificateFingerprint"])
    fingerprints = [entry["certificateFingerprint"] for entry in entries]
    if fingerprints != sorted(fingerprints):
        return None, "trust_configuration"
    return entries, None


def _authorizations(items):
    if not isinstance(items, list) or not items:
        return None, "trust_configuration"
    parsed = []
    key_ids = set()
    documents = {}
    signers = 0
    for item in items:
        body = item.get("body") if isinstance(item, dict) else None
        signature = item.get("signature") if isinstance(item, dict) else None
        if not isinstance(body, dict) or set(body) != _AUTHORIZATION_KEYS or not isinstance(signature, bytes):
            return None, "trust_configuration"
        if body["role"] not in _ROLES or body["status"] not in {"authorized", "revoked", "suspended"}:
            return None, "trust_configuration"
        if not _identifier(body["keyId"]) or not _identifier(body["personId"]):
            return None, "trust_configuration"
        if not _hex64(body["documentFingerprint"]) or not _hex64(body["spkiFingerprint"]):
            return None, "trust_configuration"
        if not _timestamp(body["notBefore"]) or not _timestamp(body["notAfter"]) or body["notBefore"] > body["notAfter"]:
            return None, "trust_configuration"
        der = _b64_spki(body["spki"])
        if der is None or spki_fingerprint(der) != body["spkiFingerprint"]:
            return None, "trust_configuration"
        if body["keyId"] in key_ids:
            return None, "trust_configuration"
        key_ids.add(body["keyId"])
        prior = documents.get(body["documentFingerprint"])
        if prior is not None and prior != body["personId"]:
            return None, "duplicate_approver"
        documents[body["documentFingerprint"]] = body["personId"]
        if body["role"] == "release-signer" and body["status"] == "authorized":
            signers += 1
        parsed.append({**body, "spkiDer": der, "signature": signature})
    if signers != 1:
        return None, "untrusted_admin_key"
    return parsed, None


def _approvals(items, release, authorizations):
    if not isinstance(items, list):
        return None, "trust_configuration"
    by_key = {item["keyId"]: item for item in authorizations}
    suspended_people = {item["personId"] for item in authorizations if item["status"] == "suspended"}
    parsed = []
    release_digest = sha256_hex(canonical_json(release))
    for item in items:
        body = item.get("body") if isinstance(item, dict) else None
        signature = item.get("signature") if isinstance(item, dict) else None
        if not isinstance(body, dict) or set(body) != _APPROVAL_KEYS or not isinstance(signature, bytes):
            return None, "trust_configuration"
        if body["role"] not in _ROLE_DOMAIN or not _identifier(body["keyId"]) or not _identifier(body["personId"]):
            return None, "trust_configuration"
        if not _timestamp(body.get("approvedAt")) or not _hex64(body.get("releaseDigest")):
            return None, "trust_configuration"
        if not isinstance(body.get("releaseSequence"), int) or isinstance(body.get("releaseSequence"), bool):
            return None, "trust_configuration"
        authorization = by_key.get(body["keyId"])
        if authorization is None or authorization["status"] == "revoked":
            return None, "unauthorized_approval"
        if authorization["personId"] in suspended_people or authorization["personId"] != body["personId"]:
            return None, "unauthorized_approval"
        if authorization["role"] != body["role"]:
            return None, "unauthorized_approval"
        if not (authorization["notBefore"] <= body["approvedAt"] <= authorization["notAfter"]):
            return None, "unauthorized_approval"
        if not verify_document(authorization["spkiDer"], _ROLE_DOMAIN[body["role"]], body, signature):
            return None, "unauthorized_approval"
        if body["releaseDigest"] != release_digest or body["releaseSequence"] != release["releaseSequence"]:
            return None, "approval_substitution"
        parsed.append({
            "personId": body["personId"],
            "documentFingerprint": authorization["documentFingerprint"],
            "role": body["role"],
            "keyId": body["keyId"],
        })
    return parsed, None


def _release_signer(authorizations):
    if not authorizations:
        return None
    matches = [item["spkiDer"] for item in authorizations if item["role"] == "release-signer" and item["status"] == "authorized"]
    if len(matches) != 1:
        return None
    return matches[0]


def _coverage(previous, proposed, purpose):
    try:
        old = _entry_set(previous)
        new = _entry_set(proposed)
    except CanonicalError:
        return "trust_configuration"
    if not old <= new:
        return "suspension_regression"
    if purpose == "suspension" and old == new:
        return "trust_configuration"
    return None


def _high_water_field(value):
    if value is None:
        return None, None
    if not isinstance(value, dict) or set(value) != {"activationDigest", "sequence", "suspensionDigest", "suspensions"}:
        return None, "sequence_state_inconsistent"
    if not _hex64(value["activationDigest"]) or not _hex64(value["suspensionDigest"]):
        return None, "sequence_state_inconsistent"
    if not isinstance(value["sequence"], int) or isinstance(value["sequence"], bool) or value["sequence"] < 1:
        return None, "sequence_state_inconsistent"
    entries, error = _suspension_entries(value["suspensions"])
    if error:
        return None, "sequence_state_inconsistent"
    if sha256_hex(canonical_json(entries)) != value["suspensionDigest"]:
        return None, "sequence_state_inconsistent"
    return value, None


def _committed_mismatch(field, witness: WitnessValue):
    if field["sequence"] < witness.sequence:
        return "sequence_state_stale"
    if field["sequence"] > witness.sequence:
        return "sequence_state_inconsistent"
    if bytes.fromhex(field["suspensionDigest"]) != witness.suspension_digest:
        return "suspension_state_stale"
    if bytes.fromhex(field["activationDigest"]) != witness.activation_digest:
        return "activation_inconsistent"
    return None


def _matching_field(local, witness: WitnessValue):
    committed = local["committed"]
    pending = local["pending"]
    if committed is not None and committed["sequence"] > witness.sequence:
        return None, "sequence_state_inconsistent"
    for field in (pending, committed):
        if field is None or field["sequence"] != witness.sequence:
            continue
        if bytes.fromhex(field["suspensionDigest"]) != witness.suspension_digest:
            return None, "suspension_state_stale"
        if bytes.fromhex(field["activationDigest"]) != witness.activation_digest:
            return None, "activation_inconsistent"
        if sha256_hex(canonical_json(field["suspensions"])) != field["suspensionDigest"]:
            return None, "suspension_state_stale"
        return field, None
    sequences = [item["sequence"] for item in (committed, pending) if item is not None]
    if sequences and max(sequences) < witness.sequence:
        return None, "sequence_state_stale"
    return None, "sequence_state_inconsistent"


def _value_matches_field(witness: WitnessValue, field) -> bool:
    if witness.empty or field is None:
        return False
    return (
        witness.sequence == field["sequence"]
        and witness.activation_digest == bytes.fromhex(field["activationDigest"])
        and witness.suspension_digest == bytes.fromhex(field["suspensionDigest"])
    )


def _field_matches_activation(field, activation) -> bool:
    return (
        field["sequence"] == activation["body"]["releaseSequence"]
        and field["activationDigest"] == sha256_hex(canonical_json(activation["body"]))
        and field["suspensionDigest"] == activation["body"]["suspensionDigest"]
    )


def _concrete(value: WitnessValue) -> bool:
    return (
        isinstance(value.sequence, int)
        and not isinstance(value.sequence, bool)
        and value.sequence >= 1
        and isinstance(value.activation_digest, bytes)
        and len(value.activation_digest) == 32
        and isinstance(value.suspension_digest, bytes)
        and len(value.suspension_digest) == 32
    )


def _same_value(left: WitnessValue, right: WitnessValue) -> bool:
    return (
        left.sequence == right.sequence
        and left.activation_digest == right.activation_digest
        and left.suspension_digest == right.suspension_digest
    )


def _two_people(caller_ids) -> bool:
    return (
        isinstance(caller_ids, tuple)
        and len(caller_ids) == 2
        and all(_identifier(item) for item in caller_ids)
        and caller_ids[0] != caller_ids[1]
    )


def _valid_confirmations(fingerprint, confirmations) -> bool:
    if not isinstance(confirmations, list) or len(confirmations) != 2:
        return False
    expected = confirmation_digest(fingerprint)
    people = []
    normalized = []
    for item in confirmations:
        if not isinstance(item, dict) or set(item) != {"personId", "statementDigest"}:
            return False
        if not _identifier(item["personId"]) or item["statementDigest"] != expected:
            return False
        people.append(item["personId"])
        normalized.append(item)
    if len(set(people)) != 2:
        return False
    ordered = sorted(normalized, key=lambda item: item["personId"])
    return confirmations == ordered


def _pin_spki(pin, fingerprint):
    candidates = [pin["active"], *pin["verifyOnly"]]
    for item in candidates:
        if item["fingerprint"] == fingerprint:
            return _b64_spki(item["spki"])
    return None


def _parse_root_entries(entries, pin):
    if not isinstance(entries, list):
        return None, failure("root_pin_inconsistent")
    suspensions = {}
    replacement = None
    previous = 0
    for entry in entries:
        if not isinstance(entry, dict):
            return None, failure("root_pin_inconsistent")
        generation = entry.get("generation")
        if not isinstance(generation, int) or isinstance(generation, bool) or generation != previous + 1:
            return None, failure("root_pin_inconsistent")
        previous = generation
        kind = entry.get("type")
        if kind == "root-suspended":
            fingerprint = entry.get("fingerprint")
            ceiling = entry.get("witnessSequence")
            if not _hex64(fingerprint) or not isinstance(ceiling, int) or isinstance(ceiling, bool) or ceiling < 1:
                return None, failure("root_pin_inconsistent")
            if fingerprint in suspensions:
                return None, failure("root_pin_inconsistent")
            suspensions[fingerprint] = {"witnessSequence": ceiling, "generation": generation}
        elif kind == "root-replaced":
            fingerprint = entry.get("fingerprint")
            if replacement is not None or not _hex64(fingerprint) or not _valid_confirmations(fingerprint, entry.get("confirmations")):
                return None, failure("root_pin_inconsistent")
            replacement = fingerprint
        else:
            return None, failure("root_pin_inconsistent")
    inconsistent = False
    if replacement is not None and pin["active"]["fingerprint"] != replacement:
        inconsistent = True
    for item in pin["verifyOnly"]:
        logged = suspensions.get(item["fingerprint"])
        if logged is None or logged["witnessSequence"] != item["throughSequence"]:
            inconsistent = True
    if replacement is not None and replacement in suspensions:
        inconsistent = True
    return {"suspensions": suspensions, "replacement": replacement, "inconsistent": inconsistent}, None
