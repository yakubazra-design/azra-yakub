"""Server-side C2PA coordination for one seal.

The image is read and the reader runs before any snapshot write. This module
does not open a ledger transaction, does not accept client provenance, and
does not build an assessment prompt. ``seal_with_provenance`` passes a ready
record to ``Ledger.seal_assessment`` and skips that call when sealing is
aborted.

``confirm_for_commit`` is the last trust decision for a credential record.
The ledger calls it inside the snapshot transaction, immediately before
INSERT. Its successful ``select()`` is the authorization point. The trust
witness and SQLite do not share one atomic transaction: a suspension that
arrives after ``select()`` returns and before SQLite commits is outside
this boundary.

A credential preparation also returns the in-memory pin used to authorize
the read. That pin stays in this process. HTTP responses must not include it.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path

from app.assetstore import STORAGE_NAME
from app.c2pa_reader import VERIFICATION_SETTINGS, _trust_bundles
from app.c2pa_statuses import ASSESSMENT_OUTCOMES
from app.images import detect_image
from app.ledger import DeletionInProgress, LedgerError, _buffer_matches, _read_asset_buffer
from app.provenance import (
    READER_VERSION,
    TECHNICAL_FAILURE_CODES,
    build_provenance_record,
    reject_client_provenance,
)
from app.trust_store import TrustStore, failure

_RETRYABLE = frozenset({"policy_superseded", "root_suspended"})
_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_OFFLINE_SETTINGS = {
    "verify.remote_manifest_fetch": False,
    "verify.ocsp_fetch": False,
    "verify.ocsp_fetch_should_override": False,
}


def prepare_sealed_provenance(
    *,
    asset_directory: Path,
    storage_name: str,
    sha256: str,
    byte_length: int,
    media_type: str,
    trust_store,
    reader=None,
    verified_at: str | None = None,
    client_provenance=None,
    untrusted_client_sha256: str | None = None,
) -> dict:
    """Verify one stored image and build the provenance record for its seal.

    ``sha256`` is the server asset identity. ``untrusted_client_sha256`` and
    ``client_provenance`` are discarded. A returned status of ``ready`` carries
    a record the ledger can persist, including a technical C2PA failure. A
    status of ``aborted`` means the file no longer matches that identity and
    must not be sealed.

    A credential record is built only after revalidation and a fresh selection
    still match the pin that authorized the read, including root use and
    purpose. Bundle hashes are the normalized PEM strings passed to the reader.
    """
    reject_client_provenance(client_provenance)
    del untrusted_client_sha256
    if reader is None:
        from app.c2pa_reader import read_image_provenance

        reader = read_image_provenance
    stamp = verified_at if isinstance(verified_at, str) and _TIMESTAMP.fullmatch(verified_at) else (
        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    baseline = _identity(asset_directory, storage_name, sha256, byte_length, media_type)
    if baseline is None:
        return _aborted()
    if not _offline_locked():
        return _technical(baseline, stamp, "trust_configuration")
    for attempt in (1, 2):
        current = _identity(asset_directory, storage_name, sha256, byte_length, media_type)
        if current is None or current["data"] != baseline["data"]:
            return _aborted()
        authorized, code, retryable = _authorize(trust_store)
        if authorized is None:
            if attempt == 1 and retryable:
                continue
            return _technical(baseline, stamp, code)
        try:
            reader_result = reader(
                current["data"],
                manifest_trust_pem=authorized["manifest_norm"],
                timestamp_trust_pem=authorized["timestamp_norm"],
                settings=dict(VERIFICATION_SETTINGS),
            )
        except Exception:
            reader_result = _reader_crash()
        after = _identity(asset_directory, storage_name, sha256, byte_length, media_type)
        if after is None or after["data"] != baseline["data"]:
            return _aborted()
        decision = trust_store.revalidate(authorized["pinned"])
        if not _confirmed(decision, authorized):
            failure = _failure_code(decision)
            if attempt == 1 and failure in _RETRYABLE:
                continue
            return _technical(baseline, stamp, failure)
        try:
            fresh = trust_store.select()
        except Exception:
            fresh = None
        confirmed_use = _confirmed_use(fresh, authorized)
        if confirmed_use is None:
            code, retryable = _selection_failure(fresh)
            if attempt == 1 and retryable:
                continue
            return _technical(baseline, stamp, code)
        if _assessment_status(reader_result):
            return _technical(baseline, stamp, "trust_configuration")
        root_use, purpose = confirmed_use
        built = build_provenance_record(
            sha256=baseline["sha256"],
            byte_length=baseline["byte_length"],
            media_type=baseline["media_type"],
            verified_at=stamp,
            release_sequence=authorized["sequence"],
            activation_digest=authorized["activation"],
            suspension_digest=authorized["suspension"],
            manifest_bundle_sha256=authorized["manifest_sha256"],
            timestamp_bundle_sha256=authorized["timestamp_sha256"],
            manifest_trust_pem=authorized["manifest_norm"],
            timestamp_trust_pem=authorized["timestamp_norm"],
            root_use=root_use,
            purpose=purpose,
            reader_result=reader_result if isinstance(reader_result, Mapping) else _reader_crash(),
        )
        if not built.get("ok"):
            return _technical(baseline, stamp, "trust_configuration")
        ready = {"status": "ready", "provenance": built["record"], "failureCode": None}
        if built["record"].get("policy") is not None:
            ready["pin"] = _commit_pin_from(authorized, root_use, purpose)
        return ready
    return _technical(baseline, stamp, "trust_configuration")


def _identity(asset_directory: Path, storage_name: str, sha256: str, byte_length: int, media_type: str):
    if not isinstance(storage_name, str) or STORAGE_NAME.fullmatch(storage_name) is None:
        return None
    directory = Path(asset_directory)
    if directory.is_symlink() or not directory.is_dir():
        return None
    path = directory / storage_name
    if path.name != storage_name or path.parent != directory or path.is_symlink():
        return None
    data = _read_asset_buffer(path, byte_length)
    if not _buffer_matches(data, sha256, byte_length):
        return None
    if detect_image(data) != media_type:
        return None
    return {
        "data": data,
        "sha256": sha256,
        "byte_length": byte_length,
        "media_type": media_type,
    }


def _authorize(trust_store):
    try:
        pinned = trust_store.pin()
    except Exception:
        return None, "trust_configuration", False
    if not isinstance(pinned, Mapping) or pinned.get("status") != "pinned":
        code = _failure_code(pinned)
        return None, code, code in _RETRYABLE
    try:
        selected = trust_store.select()
    except Exception:
        return None, "trust_configuration", False
    if not _same_policy(pinned, selected):
        code, retryable = _selection_failure(selected)
        return None, code, retryable
    normalized = _trust_bundles(pinned.get("manifestTrustPem"), pinned.get("timestampTrustPem"))
    if normalized is None or not normalized[0] or not normalized[1]:
        return None, "trust_configuration", False
    manifest_norm, timestamp_norm = normalized
    return {
        "pinned": pinned,
        "selected": selected,
        "sequence": pinned["releaseSequence"],
        "activation": pinned["activationDigest"],
        "suspension": pinned["suspensionDigest"],
        "manifest_norm": manifest_norm,
        "timestamp_norm": timestamp_norm,
        "manifest_sha256": _sha256_text(manifest_norm),
        "timestamp_sha256": _sha256_text(timestamp_norm),
    }, None, False


def _same_policy(pinned: Mapping, selected) -> bool:
    if not isinstance(selected, Mapping) or selected.get("status") != "selected":
        return False
    return (
        selected.get("releaseSequence") == pinned.get("releaseSequence")
        and selected.get("activationDigest") == pinned.get("activationDigest")
        and selected.get("suspensionDigest") == pinned.get("suspensionDigest")
        and selected.get("manifestTrustPem") == pinned.get("manifestTrustPem")
        and selected.get("timestampTrustPem") == pinned.get("timestampTrustPem")
        and selected.get("rootUse") in {"active", "verify-only"}
        and selected.get("purpose") in {"policy", "suspension"}
    )


def _confirmed(decision, authorized: dict) -> bool:
    if not isinstance(decision, Mapping) or decision.get("status") != "confirmed":
        return False
    return (
        decision.get("releaseSequence") == authorized["sequence"]
        and decision.get("activationDigest") == authorized["activation"]
    )


def _confirmed_use(fresh, authorized: dict):
    """Return the root use and purpose still bound to this pin.

    The fresh selection must repeat the pin and the selection that authorized
    the read. Any difference, including root use or purpose, rejects this
    attempt's reader result.
    """
    pinned = authorized["pinned"]
    selected = authorized["selected"]
    if not isinstance(fresh, Mapping) or fresh.get("status") != "selected":
        return None
    for key in (
        "releaseSequence",
        "activationDigest",
        "suspensionDigest",
        "manifestTrustPem",
        "timestampTrustPem",
    ):
        value = fresh.get(key)
        if value != pinned.get(key) or value != selected.get(key):
            return None
    root_use = fresh.get("rootUse")
    purpose = fresh.get("purpose")
    if root_use != selected.get("rootUse") or purpose != selected.get("purpose"):
        return None
    if root_use not in {"active", "verify-only"} or purpose not in {"policy", "suspension"}:
        return None
    return root_use, purpose


def _selection_failure(selected):
    """Classify a selection that is not the pin which authorized the read.

    A selected policy that differs is the existing retryable supersession
    result. Other store results retry only for the two retryable failures.
    """
    if isinstance(selected, Mapping) and selected.get("status") == "selected":
        return "policy_superseded", True
    code = _failure_code(selected)
    return code, code in _RETRYABLE


def confirm_for_commit(trust_store, pin, record) -> dict:
    """Decide whether one credential record may be inserted.

    One ``select()`` is the authorization point. The fresh selection must
    carry the pin's sequence, activation digest, suspension digest,
    normalized manifest PEM, normalized timestamp PEM, root use, and
    purpose. The record's bundle hashes must be the SHA-256 of those
    normalized strings. This function does not read an image and does not
    call the C2PA reader.

    A match returns ``{"ok": True, "failureCode": None}``. Any other result
    is ``{"ok": False, "failureCode": ...}`` and must not be inserted.
    """
    if not _commit_pin(pin) or not _commit_record(record):
        return _denied("trust_configuration")
    try:
        fresh = trust_store.select()
    except Exception:
        return _denied("trust_configuration")
    if not isinstance(fresh, Mapping) or fresh.get("status") != "selected":
        return _denied(_failure_code(fresh))
    fresh_bundles = _normalized_bundles(fresh.get("manifestTrustPem"), fresh.get("timestampTrustPem"))
    pin_bundles = _normalized_bundles(pin.get("manifestTrustPem"), pin.get("timestampTrustPem"))
    if fresh_bundles is None or pin_bundles is None or fresh_bundles != pin_bundles:
        return _denied(_commit_mismatch_code(pin, fresh))
    if not _same_commit_fields(pin, fresh):
        return _denied(_commit_mismatch_code(pin, fresh))
    manifest_norm, timestamp_norm = fresh_bundles
    policy = record["policy"]
    hashes_match = (
        policy.get("manifestBundleSha256") == _sha256_text(manifest_norm)
        and policy.get("timestampBundleSha256") == _sha256_text(timestamp_norm)
    )
    fields_match = _same_commit_fields(policy, fresh)
    if not hashes_match or not fields_match:
        return _denied("trust_configuration")
    return {"ok": True, "failureCode": None}


def _commit_pin(pin) -> bool:
    if not isinstance(pin, Mapping):
        return False
    sequence = pin.get("releaseSequence")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        return False
    if pin.get("rootUse") not in {"active", "verify-only"} or pin.get("purpose") not in {"policy", "suspension"}:
        return False
    return _digest(pin.get("activationDigest")) and _digest(pin.get("suspensionDigest"))


def _commit_record(record) -> bool:
    if not isinstance(record, Mapping):
        return False
    policy = record.get("policy")
    if not isinstance(policy, Mapping):
        return False
    return (
        _digest(policy.get("activationDigest"))
        and _digest(policy.get("suspensionDigest"))
        and _digest(policy.get("manifestBundleSha256"))
        and _digest(policy.get("timestampBundleSha256"))
    )


def _normalized_bundles(manifest, timestamp):
    if not isinstance(manifest, str) or not isinstance(timestamp, str):
        return None
    normalized = _trust_bundles(manifest, timestamp)
    if normalized is None or not normalized[0] or not normalized[1]:
        return None
    return normalized


def _same_commit_fields(expected, fresh) -> bool:
    return (
        fresh.get("releaseSequence") == expected.get("releaseSequence")
        and fresh.get("activationDigest") == expected.get("activationDigest")
        and fresh.get("suspensionDigest") == expected.get("suspensionDigest")
        and fresh.get("rootUse") == expected.get("rootUse")
        and fresh.get("purpose") == expected.get("purpose")
        and fresh.get("rootUse") in {"active", "verify-only"}
        and fresh.get("purpose") in {"policy", "suspension"}
    )


def _commit_mismatch_code(pin, fresh) -> str:
    """Name a selected policy that is not the pin.

    A higher release sequence is supersession. The same or a lower sequence
    with any other difference is a downgrade. ``root_suspended`` is returned
    by the store itself and is not rewritten here.
    """
    current = fresh.get("releaseSequence") if isinstance(fresh, Mapping) else None
    pinned = pin.get("releaseSequence") if isinstance(pin, Mapping) else None
    if (
        isinstance(current, int)
        and not isinstance(current, bool)
        and isinstance(pinned, int)
        and not isinstance(pinned, bool)
        and current > pinned
    ):
        return "policy_superseded"
    return "policy_downgrade"


def _digest(value) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _denied(code: str) -> dict:
    if code not in TECHNICAL_FAILURE_CODES or code in ASSESSMENT_OUTCOMES:
        code = "trust_configuration"
    return {"ok": False, "failureCode": code}


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _failure_code(result) -> str:
    if not isinstance(result, Mapping):
        return "trust_configuration"
    code = result.get("failureCode")
    if isinstance(code, str) and code in TECHNICAL_FAILURE_CODES and code not in ASSESSMENT_OUTCOMES:
        return code
    return "trust_configuration"


def _assessment_status(result) -> bool:
    return isinstance(result, Mapping) and (
        result.get("status") in ASSESSMENT_OUTCOMES or result.get("failureCode") in ASSESSMENT_OUTCOMES
    )


def _reader_crash() -> dict:
    return {
        "version": READER_VERSION,
        "status": "verification_failed",
        "failureCode": "reader_crash",
        "checks": None,
        "manifests": [],
        "actions": [],
        "actionsWithheld": True,
    }


def _technical(identity: dict, verified_at: str, code: str) -> dict:
    if code not in TECHNICAL_FAILURE_CODES or code in ASSESSMENT_OUTCOMES:
        code = "trust_configuration"
    built = build_provenance_record(
        sha256=identity["sha256"],
        byte_length=identity["byte_length"],
        media_type=identity["media_type"],
        verified_at=verified_at,
        failure_code=code,
    )
    if not built.get("ok"):
        built = build_provenance_record(
            sha256=identity["sha256"],
            byte_length=identity["byte_length"],
            media_type=identity["media_type"],
            verified_at=verified_at,
            failure_code="trust_configuration",
        )
    return {"status": "ready", "provenance": built["record"], "failureCode": None}


def _aborted() -> dict:
    return {"status": "aborted", "provenance": None, "failureCode": "identity_mismatch"}


def _offline_locked() -> bool:
    """The settings passed to the reader are the reader's own offline values."""
    return all(VERIFICATION_SETTINGS.get(key) is value for key, value in _OFFLINE_SETTINGS.items())


def _commit_pin_from(authorized: dict, root_use: str, purpose: str) -> dict:
    """Return the pin ``confirm_for_commit`` compares with one fresh selection.

    The bundle text is the normalized PEM passed to the reader. The record's
    hashes are the SHA-256 of those strings.
    """
    return {
        "releaseSequence": authorized["sequence"],
        "activationDigest": authorized["activation"],
        "suspensionDigest": authorized["suspension"],
        "manifestTrustPem": authorized["manifest_norm"],
        "timestampTrustPem": authorized["timestamp_norm"],
        "rootUse": root_use,
        "purpose": purpose,
    }


class UnavailableTrustStore:
    """A trust store this process cannot use.

    ``pin`` reports ``trust_configuration``. This object does not read the
    operating-system trust store, does not open a trust directory, and does
    not contact the network.
    """

    def pin(self):
        return failure("trust_configuration")

    def select(self):
        return failure("trust_configuration")

    def revalidate(self, _pinned):
        return failure("trust_configuration")


def resolve_trust_store(settings, injected=None, *, witness=None, root_control=None):
    """Return the store used for one process.

    An injected store is for tests. A complete local configuration is opened
    only when the witness and root-control services are supplied with it.
    Anything else, including a partial configuration, stays unavailable.
    This function does not fetch trust bundles.
    """
    if injected is not None:
        return injected
    if not settings.c2pa_trust_is_complete or witness is None or root_control is None:
        return UnavailableTrustStore()
    try:
        return _open_configured_trust_store(settings, witness, root_control)
    except Exception:
        return UnavailableTrustStore()


def _open_configured_trust_store(settings, witness, root_control):
    root, state, pin = (Path(value) for value in settings.c2pa_trust_path_values)
    ledger = Path(settings.ledger_file)
    for path in (root, state, pin):
        if _blocked_trust_path(path, ledger):
            raise RuntimeError("The trust configuration names the evidence ledger.")
    witness_key = bytes.fromhex(settings.c2pa_witness_mac_key.strip())
    root_key = bytes.fromhex(settings.c2pa_root_mac_key.strip())
    return TrustStore(
        root,
        state,
        pin,
        witness,
        root_control,
        witness_mac_key=witness_key,
        root_mac_key=root_key,
        caller_id=settings.c2pa_trust_caller_id.strip(),
    )


def _blocked_trust_path(path: Path, ledger: Path) -> bool:
    text = str(path)
    if path.name == "ledger.sqlite" or text == str(ledger):
        return True
    return text == "/workspace/data" or text.startswith("/workspace/data/")


def seal_with_provenance(
    *,
    ledger,
    owner_id: str,
    investigation_id: str,
    token_hash: str,
    snapshot: dict,
    expires_at: str,
    asset_directory: Path,
    asset,
    trust_store,
    reader=None,
    verified_at: str | None = None,
    client_provenance=None,
    untrusted_client_sha256: str | None = None,
    video_seal_integration: bool | None = None,
) -> dict:
    """Seal one investigation, attaching server provenance when an image exists.

    The image read and the C2PA reader run before ``Ledger.seal_assessment``.
    A credential record is sealed only with the pin from that preparation and
    ``confirm_for_commit``. A missing image keeps the previous seal, with no
    provenance record. An identity abort does not insert a snapshot.

    ``policy_superseded`` and ``root_suspended`` are prepared again once,
    outside the write transaction. A second authorization failure, and any
    other authorization failure, discards the credential result and seals a
    technical record with that failure code and ``policy`` null.

    ``video_seal_integration`` is forwarded to ``Ledger.seal_assessment``. It
    does not enable video ingest.
    """
    if not isinstance(asset, Mapping):
        return _insert_snapshot(
            ledger,
            owner_id,
            investigation_id,
            token_hash,
            snapshot,
            expires_at,
            provenance=None,
            authorize=None,
            video_seal_integration=video_seal_integration,
        )
    try:
        prepared = prepare_sealed_provenance(
            asset_directory=asset_directory,
            storage_name=asset.get("storageName"),
            sha256=asset.get("sha256"),
            byte_length=asset.get("byteLength"),
            media_type=asset.get("mediaType"),
            trust_store=trust_store,
            reader=reader,
            verified_at=verified_at,
            client_provenance=client_provenance,
            untrusted_client_sha256=untrusted_client_sha256,
        )
    except Exception:
        prepared = None
    if prepared is None:
        return _seal_technical(
            ledger,
            owner_id,
            investigation_id,
            token_hash,
            snapshot,
            expires_at,
            asset,
            "trust_configuration",
            video_seal_integration=video_seal_integration,
        )
    if prepared.get("status") == "aborted":
        return {"ok": False, "code": "identity_mismatch"}
    return _commit_prepared(
        ledger,
        owner_id,
        investigation_id,
        token_hash,
        snapshot,
        expires_at,
        asset_directory,
        asset,
        trust_store,
        reader,
        verified_at,
        client_provenance,
        untrusted_client_sha256,
        prepared,
        retries=1,
        video_seal_integration=video_seal_integration,
    )


_VIDEO_SEAL_FAILURE_CODES = frozenset({
    "video_not_ready",
    "video_identity_mismatch",
    "video_seal_busy",
})


def _commit_prepared(
    ledger,
    owner_id,
    investigation_id,
    token_hash,
    snapshot,
    expires_at,
    asset_directory,
    asset,
    trust_store,
    reader,
    verified_at,
    client_provenance,
    untrusted_client_sha256,
    prepared,
    retries: int,
    video_seal_integration: bool | None = None,
) -> dict:
    record = prepared.get("provenance") if isinstance(prepared, Mapping) else None
    policy = record.get("policy") if isinstance(record, Mapping) else None
    authorize = None
    if isinstance(policy, Mapping):
        pin = prepared.get("pin") if isinstance(prepared, Mapping) else None
        if not isinstance(pin, Mapping):
            return _seal_technical(
                ledger,
                owner_id,
                investigation_id,
                token_hash,
                snapshot,
                expires_at,
                asset,
                "trust_configuration",
                video_seal_integration=video_seal_integration,
            )
        authorize = lambda stored, pin=pin, store=trust_store: confirm_for_commit(store, pin, stored)
    try:
        outcome = _insert_snapshot(
            ledger,
            owner_id,
            investigation_id,
            token_hash,
            snapshot,
            expires_at,
            provenance=record,
            authorize=authorize,
            video_seal_integration=video_seal_integration,
        )
    except LedgerError as exc:
        if not isinstance(policy, Mapping):
            return {"ok": False, "code": "ledger_unavailable"}
        code = exc.failure_code if isinstance(exc.failure_code, str) and exc.failure_code else ""
        if not code:
            return {"ok": False, "code": "ledger_unavailable"}
        if code in _VIDEO_SEAL_FAILURE_CODES:
            return {"ok": False, "code": code}
        if code in _RETRYABLE and retries > 0:
            try:
                fresh = prepare_sealed_provenance(
                    asset_directory=asset_directory,
                    storage_name=asset.get("storageName"),
                    sha256=asset.get("sha256"),
                    byte_length=asset.get("byteLength"),
                    media_type=asset.get("mediaType"),
                    trust_store=trust_store,
                    reader=reader,
                    verified_at=verified_at,
                    client_provenance=client_provenance,
                    untrusted_client_sha256=untrusted_client_sha256,
                )
            except Exception:
                fresh = None
            if fresh is None:
                return _seal_technical(
                    ledger,
                    owner_id,
                    investigation_id,
                    token_hash,
                    snapshot,
                    expires_at,
                    asset,
                    "trust_configuration",
                    video_seal_integration=video_seal_integration,
                )
            if fresh.get("status") == "aborted":
                return {"ok": False, "code": "identity_mismatch"}
            return _commit_prepared(
                ledger,
                owner_id,
                investigation_id,
                token_hash,
                snapshot,
                expires_at,
                asset_directory,
                asset,
                trust_store,
                reader,
                verified_at,
                client_provenance,
                untrusted_client_sha256,
                fresh,
                retries=0,
                video_seal_integration=video_seal_integration,
            )
        return _seal_technical(
            ledger,
            owner_id,
            investigation_id,
            token_hash,
            snapshot,
            expires_at,
            asset,
            _authorization_code(code),
            video_seal_integration=video_seal_integration,
        )
    if not outcome.get("ok") and outcome.get("code") in _VIDEO_SEAL_FAILURE_CODES:
        return outcome
    if outcome.get("ok"):
        return outcome
    # Non-video insert failures while a credential policy is present still
    # follow the existing technical-record fallback path only when the insert
    # raised; dictionary failures are returned as-is.
    return outcome


def _seal_technical(
    ledger,
    owner_id,
    investigation_id,
    token_hash,
    snapshot,
    expires_at,
    asset,
    code: str,
    video_seal_integration: bool | None = None,
) -> dict:
    """Seal the investigation with a new technical record and no callback."""
    technical = _technical(
        {
            "sha256": asset.get("sha256"),
            "byte_length": asset.get("byteLength"),
            "media_type": asset.get("mediaType"),
        },
        _stamp(None),
        _authorization_code(code),
    )
    if technical.get("status") != "ready":
        return {"ok": False, "code": "ledger_unavailable"}
    try:
        return _insert_snapshot(
            ledger,
            owner_id,
            investigation_id,
            token_hash,
            snapshot,
            expires_at,
            provenance=technical["provenance"],
            authorize=None,
            video_seal_integration=video_seal_integration,
        )
    except LedgerError as exc:
        fail = exc.failure_code if isinstance(exc.failure_code, str) and exc.failure_code else ""
        if fail in _VIDEO_SEAL_FAILURE_CODES:
            return {"ok": False, "code": fail}
        return {"ok": False, "code": "ledger_unavailable"}


def _insert_snapshot(
    ledger,
    owner_id,
    investigation_id,
    token_hash,
    snapshot,
    expires_at,
    provenance,
    authorize,
    video_seal_integration: bool | None = None,
) -> dict:
    try:
        snapshot_id = ledger.seal_assessment(
            owner_id,
            investigation_id,
            token_hash,
            snapshot,
            expires_at,
            provenance=provenance,
            authorize=authorize,
            video_seal_integration=video_seal_integration,
        )
    except DeletionInProgress:
        return {"ok": False, "code": "deletion_in_progress"}
    except LedgerError as exc:
        fail = exc.failure_code if isinstance(exc.failure_code, str) and exc.failure_code else ""
        if fail in _VIDEO_SEAL_FAILURE_CODES:
            return {"ok": False, "code": fail}
        # Preserve prior trust-authorization retry behavior in `_commit_prepared`.
        raise
    except sqlite3.Error:
        return {"ok": False, "code": "ledger_unavailable"}
    if snapshot_id is None:
        return {"ok": False, "code": "not_found"}
    return {"ok": True, "snapshotId": snapshot_id}


def _authorization_code(code: str) -> str:
    if code in TECHNICAL_FAILURE_CODES and code not in ASSESSMENT_OUTCOMES:
        return code
    return "trust_configuration"


def _stamp(value: str | None) -> str:
    if isinstance(value, str) and _TIMESTAMP.fullmatch(value):
        return value
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
