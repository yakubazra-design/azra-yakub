"""Read a C2PA manifest store from supplied image bytes.

The reader is the official c2pa-python Reader. This module does not sign,
does not import a builder, and does not fetch a manifest, ingredient, or
certificate status. It does not open the ledger or an upload.

The native call runs in a child process. If that process is still alive
after READER_TIMEOUT_SECONDS, the parent kills it. That kill interrupts
native parser CPU. A timer around an in-process call would not.

A killed child, a child that exits without a result, a refused address
limit, a library version mismatch, and a rejected trust bundle are
technical failures. Their status is verification_failed and they carry a
failureCode. They are not credential findings and they are not assessment
outcomes.

The parent keeps its own copy of the supplied image and sends that copy to
the child. RLIMIT_AS caps only the child's virtual address space. It does
not cap the parent, and the two-second timeout is not a memory limit. The
native Reader starts only after the child has applied RLIMIT_AS. If the
platform has no such limit or refuses it, the child returns a non-trusted
result and does not call the Reader.
"""

from __future__ import annotations

import io
import json
import multiprocessing
import ssl
from collections.abc import Mapping

from c2pa import Context, Reader, Settings, sdk_version

READER_VERSION = "c2pa-reader-2"
NATIVE_LIBRARY_VERSION = "0.92.0"
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_MANIFEST_COUNT = 16
READER_TIMEOUT_SECONDS = 2.0
MAX_TRUST_ANCHOR_BYTES = 64 * 1024
TECHNICAL_FAILURE_CODES = frozenset({
    "reader_timeout",
    "reader_crash",
    "reader_unavailable",
    "memory_limit",
    "trust_configuration",
})
_CHILD_TECHNICAL_CODES = TECHNICAL_FAILURE_CODES - {"reader_timeout"}
# Virtual-memory cap for the reader child. This is not a substitute for
# the manifest-size check, and it does not bound the parent process.
CHILD_ADDRESS_SPACE_BYTES = 512 * 1024 * 1024

VERIFICATION_SETTINGS = {
    "verify.remote_manifest_fetch": False,
    "verify.ocsp_fetch": False,
    "verify.ocsp_fetch_should_override": False,
    "verify.verify_after_reading": True,
    "verify.verify_trust": True,
    "verify.verify_timestamp_trust": True,
}

_STATUSES = {
    "no_credentials",
    "not_performed",
    "credentials_malformed",
    "credentials_invalid",
    "credentials_untrusted",
    "credentials_trusted",
}
_CHECK_VALUES = {
    "signature": {"valid", "invalid", "missing", "not_checked"},
    "assetBinding": {"bound", "mismatch", "missing", "malformed", "not_checked"},
    "certificateTrust": {"trusted", "untrusted", "not_checked"},
    "certificateValidity": {"inside_at_asserted_time", "expired", "outside", "not_checked"},
    "revocation": {
        "not_revoked",
        "revoked",
        "skipped",
        "unknown",
        "inaccessible",
        "not_checked",
    },
    "timestamp": {
        "trusted",
        "absent",
        "untrusted",
        "malformed",
        "outside_validity",
        "not_checked",
    },
}
_HARD_BINDING_MATCH = {
    "assertion.dataHash.match",
    "assertion.boxesHash.match",
    "assertion.bmffHash.match",
    "assertion.collectionHash.match",
}
_HARD_BINDING_MISMATCH = {
    "assertion.dataHash.mismatch",
    "assertion.boxesHash.mismatch",
    "assertion.bmffHash.mismatch",
    "assertion.collectionHash.mismatch",
}
_HARD_BINDING_MALFORMED = {
    "assertion.dataHash.malformed",
    "assertion.boxesHash.malformed",
    "assertion.boxesHash.unknownBox",
    "assertion.bmffHash.malformed",
    "assertion.collectionHash.malformed",
    "assertion.collectionHash.invalidURI",
    "assertion.collectionHash.incorrectFileCount",
}
_TIMESTAMP_CODES = {
    "timeStamp.trusted",
    "timeStamp.validated",
    "timeStamp.untrusted",
    "timeStamp.malformed",
    "timeStamp.mismatch",
    "timeStamp.outsideValidity",
}
# Fatal revocation outcomes count in every result list. A skipped or
# not-revoked code counts only when its URL names the active manifest.
_FATAL_REVOCATION = {
    "signingCredential.ocsp.revoked",
    "signingCredential.ocsp.unknown",
    "signingCredential.ocsp.inaccessible",
}
# Codes that make a credential invalid or untrusted when the check mapper
# sees them. signingCredential.untrusted stays credentials_untrusted.
# signingCredential.invalid is an invalid credential, not an untrusted one.
_RECOGNIZED_FAILURES = {
    "claimSignature.missing",
    "claimSignature.mismatch",
    "claimSignature.outsideValidity",
    "signingCredential.expired",
    "signingCredential.invalid",
    "signingCredential.untrusted",
    "signingCredential.ocsp.revoked",
    "signingCredential.ocsp.unknown",
    "signingCredential.ocsp.inaccessible",
    "claim.hardBindings.missing",
    "assertion.dataHash.mismatch",
    "assertion.dataHash.malformed",
    "assertion.boxesHash.mismatch",
    "assertion.boxesHash.malformed",
    "assertion.boxesHash.unknownBox",
    "assertion.bmffHash.mismatch",
    "assertion.bmffHash.malformed",
    "assertion.collectionHash.mismatch",
    "assertion.collectionHash.malformed",
    "assertion.collectionHash.invalidURI",
    "assertion.collectionHash.incorrectFileCount",
    "timeStamp.outsideValidity",
    "timeStamp.malformed",
    "timeStamp.mismatch",
    "timeStamp.untrusted",
    "assertion.timestamp.malformed",
}
# A matching hard binding that also excludes extra ranges is not an
# unconditional bind, so it cannot produce credentials_trusted.
_BINDING_QUALIFIED = {
    "assertion.dataHash.additionalExclusionsPresent",
    "assertion.bmffHash.additionalExclusionsPresent",
    "assertion.boxesHash.additionalExclusionsPresent",
}
# These codes do not by themselves prove a credential invalid, and they
# do not block credentials_trusted:
# - signingCredential.ocsp.skipped: the locked settings do not fetch OCSP.
#   Skipped stays a revocation result and cannot produce credentials_trusted.
# - timeOfSigning.insideValidity: confirms the signing time sits inside the
#   certificate window. claimSignature.insideValidity remains the required
#   validity check.
# - cawg.ica.untrusted_issuer: scoped to one identity assertion. c2pa-rs
#   does not let it change the enclosing manifest's trust state.
# - cawg.identity.well-formed, cawg.ica.credential_valid, and
#   cawg.ica.time_stamp.validated: positive identity-assertion results.
# - assertion.hashedURI.match and assertion.accessible: a referenced
#   assertion matched or was reachable. They do not replace the hard binding.
# - ingredient.manifest.validated, ingredient.manifest.missing, and
#   ingredient.claimSignature.validated: ingredient bookkeeping. Missing
#   here is the library's success code for an ingredient that has no
#   manifest, not a failed active-manifest check. A second manifest or any
#   ingredient delta is still rejected before this list is consulted.
# - the CAWG X.509 success codes: identity success does not weaken the
#   C2PA credential result.
# Every other code, in any list, blocks credentials_trusted. Known hard
# failures above still become credentials_invalid or credentials_untrusted.
# Ambiguous codes such as manifest.unknownProvenance, algorithm.deprecated,
# and ingredient.unknownProvenance therefore cannot become trusted, and
# they are not automatically credentials_invalid.
_DOES_NOT_BLOCK_TRUST = {
    "claimSignature.validated",
    "claimSignature.insideValidity",
    "signingCredential.trusted",
    "signingCredential.ocsp.notRevoked",
    "signingCredential.ocsp.skipped",
    "timeStamp.trusted",
    "timeStamp.validated",
    "timeOfSigning.insideValidity",
    "assertion.dataHash.match",
    "assertion.boxesHash.match",
    "assertion.bmffHash.match",
    "assertion.collectionHash.match",
    "assertion.hashedURI.match",
    "assertion.accessible",
    "ingredient.manifest.validated",
    "ingredient.manifest.missing",
    "ingredient.claimSignature.validated",
    "cawg.ica.untrusted_issuer",
    "cawg.identity.well-formed",
    "cawg.ica.credential_valid",
    "cawg.ica.time_stamp.validated",
    "cawg.x509.credential.trusted",
    "cawg.x509.signature.validated",
}
_MANIFEST_STATUSES = {
    "credentials_malformed",
    "credentials_invalid",
    "credentials_untrusted",
    "credentials_trusted",
}
_MANIFEST_ROLES = {"active", "ingredient", "unreferenced"}
_SIGNATURE_POSITIVE = {"claimSignature.validated"}
_SIGNATURE_NEGATIVE = {"claimSignature.mismatch", "claimSignature.missing"}
_BINDING_NEGATIVE = _HARD_BINDING_MISMATCH | _HARD_BINDING_MALFORMED | {
    "claim.hardBindings.missing",
}
_C2PA_CHUNK_TAGS = {b"caBX", b"c2pa", b"JUMB"}
_WEBP_CHUNK_TAGS = {b"C2PA", b"c2pa", b"JUMB"}


class ProvenanceSettingsError(ValueError):
    """The caller asked for a verification setting this adapter does not apply."""


def native_library_version() -> str:
    """Return the c2pa-rs version linked into this process."""
    return sdk_version()


def read_image_provenance(
    data: bytes,
    *,
    manifest_trust_pem: str | None = None,
    timestamp_trust_pem: str | None = None,
    settings: Mapping | None = None,
) -> dict:
    """Return a bounded provenance result for one image.

    ``settings`` must be empty or exactly the locked verification values.
    An unknown key or any other value is rejected before the native reader
    runs. Trust material is caller-supplied PEM text. This function does
    not download it. Omitting both bundles leaves trust unconfigured. Supplying
    either bundle requires both, and each bundle is registered only for its
    own purpose.
    """
    if not isinstance(data, (bytes, bytearray)):
        return _malformed()
    blob = bytes(data)
    if not blob:
        return _malformed()
    resolved = _resolve_settings(settings)
    bundles = _trust_bundles(manifest_trust_pem, timestamp_trust_pem)
    if bundles is None:
        return _technical("trust_configuration")
    if native_library_version() != NATIVE_LIBRARY_VERSION:
        return _technical("reader_unavailable")
    if not _supported_container(blob):
        return _not_performed()
    if _manifest_exceeds_limit(blob):
        return _malformed()
    kind, outcome = run_bounded(
        _read_in_child,
        (blob, bundles[0], bundles[1], resolved),
        READER_TIMEOUT_SECONDS,
    )
    if kind == "timeout":
        return _technical("reader_timeout")
    if kind != "ok":
        return _technical("reader_crash")
    return _accept(outcome)


def run_bounded(target, args: tuple, timeout: float):
    """Run ``target`` in a child and kill that child when ``timeout`` elapses.

    Returns ``("ok", value)`` when the child finishes, ``("timeout", None)``
    when the parent kills it, ``("exception", None)`` when the child raises,
    and ``("no_result", None)`` when it exits without a result. Killing the
    child stops native code that is still running inside it.
    """
    context = multiprocessing.get_context("spawn")
    queue = context.Queue(maxsize=1)
    process = context.Process(target=_queue_call, args=(target, args, queue))
    process.start()
    process.join(timeout)
    if process.is_alive():
        process.kill()
        process.join(1)
        _close_queue(queue)
        return ("timeout", None)
    try:
        payload = queue.get(timeout=1)
    except Exception:
        return ("no_result", None)
    finally:
        _close_queue(queue)
        if process.is_alive():
            process.kill()
            process.join(1)
    if (
        not isinstance(payload, tuple)
        or len(payload) != 2
        or payload[0] not in {"child-result", "child-exception"}
    ):
        return ("no_result", None)
    if payload[0] == "child-exception":
        return ("exception", None)
    return ("ok", payload[1])


def _queue_call(target, args: tuple, queue) -> None:
    try:
        queue.put(("child-result", target(*args)))
    except Exception:
        queue.put(("child-exception", None))


def _close_queue(queue) -> None:
    try:
        queue.close()
        queue.cancel_join_thread()
    except Exception:
        return


def _resolve_settings(settings: Mapping | None) -> dict:
    if settings is None:
        return dict(VERIFICATION_SETTINGS)
    if not isinstance(settings, Mapping):
        raise ProvenanceSettingsError("verification settings must be a mapping")
    supplied = _flatten_settings(settings)
    resolved = dict(VERIFICATION_SETTINGS)
    for key, value in supplied.items():
        if key not in VERIFICATION_SETTINGS:
            raise ProvenanceSettingsError("unknown verification setting")
        if value is not VERIFICATION_SETTINGS[key]:
            raise ProvenanceSettingsError("unsupported verification setting")
        resolved[key] = value
    return resolved


def _flatten_settings(settings: Mapping) -> dict:
    flat: dict[str, object] = {}
    for key, value in settings.items():
        if not isinstance(key, str) or not key:
            raise ProvenanceSettingsError("unknown verification setting")
        if isinstance(value, Mapping):
            if "." in key:
                raise ProvenanceSettingsError("unknown verification setting")
            for child, child_value in value.items():
                if not isinstance(child, str) or not child or "." in child:
                    raise ProvenanceSettingsError("unknown verification setting")
                flat[key + "." + child] = child_value
            continue
        if key.count(".") != 1:
            raise ProvenanceSettingsError("unknown verification setting")
        flat[key] = value
    return flat


def _trust_bundles(
    manifest_trust_pem: str | None,
    timestamp_trust_pem: str | None,
) -> tuple[str, str] | None:
    """Validate the two purpose bundles without mixing them.

    ``None`` for both means the caller configured no trust. A value on
    either side requires a complete, independently valid certificate
    bundle on both sides. This function never copies one bundle into the
    other purpose and never concatenates them.
    """
    if manifest_trust_pem is None and timestamp_trust_pem is None:
        return "", ""
    manifest = _certificate_bundle(manifest_trust_pem)
    timestamp = _certificate_bundle(timestamp_trust_pem)
    if manifest is None or timestamp is None or not manifest or not timestamp:
        return None
    return manifest, timestamp


def _certificate_bundle(value: str | None) -> str | None:
    """Return one normalized certificate bundle, or None when it is unusable.

    An omitted value is an empty string. A private key, a truncated
    certificate, extra text, or a bundle over the byte ceiling is rejected.
    """
    if value is None:
        return ""
    if not isinstance(value, str) or "\x00" in value:
        return None
    if len(value.encode("utf-8")) > MAX_TRUST_ANCHOR_BYTES:
        return None
    if "PRIVATE KEY-----" in value:
        return None
    text = value.strip()
    if not text:
        return ""
    blocks = []
    rest = text
    begin = "-----BEGIN CERTIFICATE-----"
    end_mark = "-----END CERTIFICATE-----"
    while rest:
        rest = rest.lstrip()
        if not rest:
            break
        if not rest.startswith(begin):
            return None
        end = rest.find(end_mark)
        if end < 0:
            return None
        end += len(end_mark)
        block = rest[:end]
        rest = rest[end:]
        try:
            der = ssl.PEM_cert_to_DER_cert(block)
        except (ssl.SSLError, ValueError):
            return None
        if not der:
            return None
        blocks.append(block)
    if not blocks or rest.strip():
        return None
    return "\n".join(blocks) + "\n"


def _constrain_child_resources() -> bool:
    """Cap the child address space when the OS provides RLIMIT_AS.

    Returns False when the platform has no such limit or refuses it. The
    caller must not start the native Reader in that case. The cap does
    not shrink the parent's copy of the image, and a timeout does not
    replace it.
    """
    try:
        import resource
    except ImportError:
        return False
    cap = CHILD_ADDRESS_SPACE_BYTES
    try:
        _soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    except (OSError, ValueError):
        return False
    if hard != resource.RLIM_INFINITY and hard < cap:
        cap = hard
    try:
        ceiling = hard if hard != resource.RLIM_INFINITY else cap
        resource.setrlimit(resource.RLIMIT_AS, (cap, ceiling))
    except (OSError, ValueError):
        return False
    return True


def _read_in_child(data: bytes, manifest_pem: str, timestamp_pem: str, settings: dict) -> dict:
    if not _constrain_child_resources():
        return _technical("memory_limit")
    if sdk_version() != NATIVE_LIBRARY_VERSION:
        return _technical("reader_unavailable")
    verify = {
        "remote_manifest_fetch": settings["verify.remote_manifest_fetch"],
        "ocsp_fetch": settings["verify.ocsp_fetch"],
        "ocsp_fetch_should_override": settings["verify.ocsp_fetch_should_override"],
        "verify_after_reading": settings["verify.verify_after_reading"],
        "verify_trust": settings["verify.verify_trust"],
        "verify_timestamp_trust": settings["verify.verify_timestamp_trust"],
    }
    config: dict = {"verify": verify}
    if manifest_pem or timestamp_pem:
        if not manifest_pem or not timestamp_pem:
            return _technical("trust_configuration")
        config["trust"] = {
            "anchors": [
                {"trust_anchors": manifest_pem, "trust_kind": "manifest"},
                {"trust_anchors": timestamp_pem, "trust_kind": "tsa"},
            ]
        }
    try:
        native_settings = Settings.from_dict(config)
        context = Context.builder().with_settings(native_settings).build()
        reader = Reader.try_create(io.BytesIO(data), context=context)
    except Exception:
        return _malformed()
    if reader is None:
        return _absent()
    try:
        raw_json = reader.json()
    except Exception:
        return _malformed()
    finally:
        reader.close()
    return _result_from_store_json(raw_json)


class _DuplicateStoreKeys(Exception):
    """The store JSON repeated a key, so parsing would drop one of the values."""


def _object_without_duplicate_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise _DuplicateStoreKeys()
        obj[key] = value
    return obj


def _result_from_store_json(text: str) -> dict:
    """Map store JSON, rejecting duplicate keys before they collapse."""
    if not isinstance(text, str):
        return _malformed()
    try:
        payload = json.loads(text, object_pairs_hook=_object_without_duplicate_keys)
    except _DuplicateStoreKeys:
        return _structural_malformed()
    except (json.JSONDecodeError, TypeError, ValueError):
        return _malformed()
    if not isinstance(payload, dict):
        return _malformed()
    return _map_store(payload)


def _map_store(payload: dict) -> dict:
    manifests = payload.get("manifests")
    if not isinstance(manifests, dict):
        return _structural_malformed()
    if len(manifests) > MAX_MANIFEST_COUNT:
        return _structural_malformed()
    if len(manifests) == 0:
        return _absent()
    if any(not isinstance(label, str) or not label for label in manifests):
        return _structural_malformed()
    active = payload.get("active_manifest")
    if not isinstance(active, str) or active not in manifests:
        return _structural_malformed()
    if len(manifests) == 1 and not _has_manifest_ingredient(manifests):
        return _map_single(payload, active)
    return _map_multiple(payload, manifests, active)


def _has_manifest_ingredient(manifests: dict) -> bool:
    """Return True when an ingredient names a C2PA manifest label."""
    for body in manifests.values():
        if not isinstance(body, dict):
            return True
        ingredients = body.get("ingredients") or []
        if not isinstance(ingredients, list):
            return True
        for ingredient in ingredients:
            if isinstance(ingredient, dict) and "active_manifest" in ingredient:
                return True
    return False


def _map_single(payload: dict, label: str) -> dict:
    """Preserve the one-manifest mapper, including foreign-URL failures."""
    results = payload.get("validation_results")
    if not isinstance(results, dict):
        return _one_manifest(label, "credentials_malformed", _unchecked())
    if results.get("ingredientDeltas"):
        return _one_manifest(label, "credentials_malformed", _unchecked())
    active_result = results.get("activeManifest")
    if not isinstance(active_result, dict):
        return _one_manifest(label, "credentials_malformed", _unchecked())
    raw = (
        active_result.get("success"),
        active_result.get("informational"),
        active_result.get("failure"),
    )
    status, checks = _classify_raw(raw, label)
    return _one_manifest(label, status, checks)


def _map_multiple(payload: dict, manifests: dict, active: str) -> dict:
    """Validate every manifest from its snapshot and the fresh deltas."""
    if any(not isinstance(body, dict) for body in manifests.values()):
        return _structural_malformed()
    results = payload.get("validation_results")
    if not isinstance(results, dict):
        return _structural_malformed()
    active_result = results.get("activeManifest")
    if not isinstance(active_result, dict):
        return _structural_malformed()
    referenced: set[str] = set()
    snapshot = {label: _empty_groups() for label in manifests}
    for body in manifests.values():
        ingredients = body.get("ingredients", [])
        if ingredients is None:
            ingredients = []
        if not isinstance(ingredients, list):
            return _structural_malformed()
        for ingredient in ingredients:
            if not isinstance(ingredient, dict):
                return _structural_malformed()
            if "active_manifest" not in ingredient:
                continue
            target = ingredient.get("active_manifest")
            if not isinstance(target, str) or not target:
                return _structural_malformed()
            referenced.add(target)
            if target not in snapshot:
                snapshot[target] = _empty_groups()
            embedded = ingredient.get("validation_results")
            if embedded is None:
                continue
            if not isinstance(embedded, dict):
                return _structural_malformed()
            inner = embedded.get("activeManifest")
            if inner is not None:
                if not isinstance(inner, dict):
                    return _structural_malformed()
                if not _absorb_status_groups(inner, snapshot, set(snapshot)):
                    return _structural_malformed()
            nested = embedded.get("ingredientDeltas", [])
            if nested is None:
                nested = []
            if not _absorb_delta_list(nested, snapshot, set(snapshot)):
                return _structural_malformed()
    if len(snapshot) > MAX_MANIFEST_COUNT:
        return _structural_malformed()
    fresh = {label: _empty_groups() for label in snapshot}
    if not _absorb_status_groups(active_result, fresh, set(snapshot)):
        return _structural_malformed()
    deltas = results.get("ingredientDeltas", [])
    if deltas is None:
        deltas = []
    if not _absorb_delta_list(deltas, fresh, set(snapshot)):
        return _structural_malformed()
    entries = []
    for label in [active, *sorted(label for label in snapshot if label != active)]:
        if label == active:
            role = "active"
        elif label in referenced:
            role = "ingredient"
        else:
            role = "unreferenced"
        if label not in manifests:
            entries.append(_manifest_entry(label, role, "credentials_malformed", _unchecked()))
            continue
        status, checks = _combine_manifest(snapshot[label], fresh[label], label)
        entries.append(_manifest_entry(label, role, status, checks))
    aggregate = _aggregate_status(entries)
    top_checks = None
    return _finish(aggregate, top_checks, entries)


def _combine_manifest(snapshot: dict, fresh: dict, label: str) -> tuple[str, dict]:
    """Merge one manifest's snapshot with the Reader's fresh codes.

    A fresh ``signingCredential.trusted`` supersedes a snapshot
    ``signingCredential.untrusted`` for this label only. Hard failures
    from either source stay in force. Opposite signature or binding
    conclusions are a conflict, not a choice of the nicer one.
    """
    snap = _copy_groups(snapshot)
    if _groups_have(fresh, "signingCredential.trusted"):
        snap["failure"] = [
            item for item in snap["failure"]
            if item.get("code") != "signingCredential.untrusted"
        ]
    raw_snap = (snap["success"], snap["informational"], snap["failure"])
    raw_fresh = (fresh["success"], fresh["informational"], fresh["failure"])
    if _groups_conflict(raw_snap, raw_fresh):
        return "credentials_malformed", _unchecked()
    combined = (
        snap["success"] + fresh["success"],
        snap["informational"] + fresh["informational"],
        snap["failure"] + fresh["failure"],
    )
    return _classify_raw(combined, label)


def _classify_raw(raw, label: str) -> tuple[str, dict]:
    malformed_entries = _malformed_validation_entries(*raw)
    success = _success_codes(raw[0], label)
    informational = _informational_codes(raw[1], label)
    failure = _failure_codes(raw[2])
    failure |= _recognized_failures(raw[0])
    failure |= _recognized_failures(raw[1])
    qualified = _qualified_bindings(*raw)
    present = success | informational | failure
    checks = {
        "signature": _signature(success, failure),
        "assetBinding": _binding(success, failure, qualified),
        "certificateTrust": _trust(success, failure),
        "certificateValidity": _validity(success, failure),
        "revocation": _revocation(success, informational, failure),
        "timestamp": _timestamp(success, failure, present),
    }
    unrecognized = bool(failure - _RECOGNIZED_FAILURES)
    blocks_trust = _blocks_unconditional_trust(*raw) or malformed_entries
    credential_invalid = "signingCredential.invalid" in failure
    status = _status_from_checks(checks, unrecognized, blocks_trust, credential_invalid)
    return status, checks


def _empty_groups() -> dict:
    return {"success": [], "informational": [], "failure": []}


def _copy_groups(groups: dict) -> dict:
    return {name: list(groups[name]) for name in ("success", "informational", "failure")}


def _groups_have(groups: dict, code: str) -> bool:
    for name in ("success", "informational", "failure"):
        for item in groups[name]:
            if isinstance(item, dict) and item.get("code") == code:
                return True
    return False


def _absorb_status_groups(source: dict, buckets: dict, known: set[str]) -> bool:
    """Attribute a status-code object to manifest labels. False means unusable."""
    if not isinstance(source, dict):
        return False
    for name in ("success", "informational", "failure"):
        items = source.get(name)
        if items is None:
            continue
        if not isinstance(items, list):
            return False
        for item in items:
            placed = _place_item(item, name, buckets, known)
            if not placed:
                return False
    return True


def _absorb_delta_list(deltas, buckets: dict, known: set[str]) -> bool:
    """Attribute each delta to exactly one known manifest label."""
    if not isinstance(deltas, list):
        return False
    for delta in deltas:
        if not isinstance(delta, dict):
            return False
        body = delta.get("validationDeltas")
        if not isinstance(body, dict):
            return False
        touched: set[str] = set()
        local = {label: _empty_groups() for label in known}
        if not _absorb_status_groups(body, local, known):
            return False
        for label, groups in local.items():
            if any(groups[name] for name in ("success", "informational", "failure")):
                touched.add(label)
        if len(touched) != 1:
            return False
        label = next(iter(touched))
        for name in ("success", "informational", "failure"):
            buckets[label][name].extend(local[label][name])
    return True


def _place_item(item, name: str, buckets: dict, known: set[str]) -> bool:
    if not isinstance(item, dict):
        return False
    code = item.get("code")
    if not isinstance(code, str) or not code:
        return False
    label = _label_from_url(item.get("url"))
    if label is None or label not in known:
        return False
    buckets[label][name].append({"code": code, "url": item.get("url")})
    return True


def _groups_conflict(snapshot, fresh) -> bool:
    snap = _code_set(snapshot)
    fresh_codes = _code_set(fresh)
    pairs = (
        (_SIGNATURE_POSITIVE, _SIGNATURE_NEGATIVE),
        (_HARD_BINDING_MATCH, _BINDING_NEGATIVE),
    )
    for positive, negative in pairs:
        if _opposes(snap, snap, positive, negative):
            return True
        if _opposes(fresh_codes, fresh_codes, positive, negative):
            return True
        if _opposes(snap, fresh_codes, positive, negative):
            return True
    return False


def _code_set(groups) -> set[str]:
    found: set[str] = set()
    for items in groups:
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("code"), str):
                found.add(item["code"])
    return found


def _opposes(left: set[str], right: set[str], positive: set[str], negative: set[str]) -> bool:
    return bool(left & positive and right & negative) or bool(right & positive and left & negative)


def _aggregate_status(entries: list[dict]) -> str:
    statuses = [entry["status"] for entry in entries]
    if "credentials_malformed" in statuses:
        return "credentials_malformed"
    if "credentials_invalid" in statuses:
        return "credentials_invalid"
    if "credentials_untrusted" in statuses:
        return "credentials_untrusted"
    if statuses and all(item == "credentials_trusted" for item in statuses):
        return "credentials_trusted"
    return "credentials_malformed"


def _manifest_entry(label: str, role: str, status: str, checks: dict) -> dict:
    return {"label": label, "role": role, "status": status, "checks": checks}


def _one_manifest(label: str, status: str, checks: dict) -> dict:
    return _finish(status, checks, [_manifest_entry(label, "active", status, checks)])


def _finish(status: str, checks: dict | None, manifests: list[dict]) -> dict:
    if checks is None:
        body = {
            "version": READER_VERSION,
            "status": status,
            "checks": None,
            "actions": [],
            "actionsWithheld": True,
        }
    else:
        body = _with_checks(status, checks)
    body["manifests"] = manifests
    return body


def _structural_malformed() -> dict:
    """A store that cannot be reported without hiding part of it."""
    return _finish("credentials_malformed", _unchecked(), [])


def _label_from_url(url) -> str | None:
    if not isinstance(url, str) or "/c2pa/" not in url:
        return None
    label = url.split("/c2pa/", 1)[1].split("/", 1)[0]
    if not label:
        return None
    return label


def _iter_codes(items):
    """Yield code and URL pairs from well-formed validation entries.

    Entries with a missing, empty, or non-string code are not yielded, so
    they cannot become a successful check. ``_malformed_validation_entries``
    records those entries and blocks a trusted result.
    """
    if not isinstance(items, list):
        return
    for item in items:
        if not isinstance(item, dict):
            continue
        code = item.get("code")
        if isinstance(code, str) and code:
            yield code, item.get("url")


def _malformed_validation_entries(*groups) -> bool:
    """Return True when a validation list contains an unusable entry.

    A missing list is empty. A list that is present must contain only
    objects whose code is a non-empty string. Anything else is ambiguous
    and must not be ignored.
    """
    for items in groups:
        if items is None:
            continue
        if not isinstance(items, list):
            return True
        for item in items:
            if not isinstance(item, dict):
                return True
            code = item.get("code")
            if not isinstance(code, str) or not code:
                return True
    return False


def _failure_codes(items) -> set[str]:
    """Keep every failure code, including one aimed at another manifest."""
    return {code for code, _url in _iter_codes(items)}


def _recognized_failures(items) -> set[str]:
    """Pull a known failure code out of whichever list the library used."""
    return {code for code, _url in _iter_codes(items) if code in _RECOGNIZED_FAILURES}


def _success_codes(items, active_label: str) -> set[str]:
    """Count a success only when its URL names the active manifest."""
    return {code for code, url in _iter_codes(items) if _names_active(url, active_label)}


def _informational_codes(items, active_label: str) -> set[str]:
    found: set[str] = set()
    for code, url in _iter_codes(items):
        if code in _FATAL_REVOCATION or code in _RECOGNIZED_FAILURES:
            found.add(code)
        elif _names_active(url, active_label):
            found.add(code)
    return found


def _qualified_bindings(*groups) -> set[str]:
    found: set[str] = set()
    for items in groups:
        for code, _url in _iter_codes(items):
            if code in _BINDING_QUALIFIED:
                found.add(code)
    return found


def _blocks_unconditional_trust(*groups) -> bool:
    """Return True when a code must keep the result from being trusted.

    Recognized hard failures are handled by the check mapper. Every other
    code that is not on the explicit non-blocking list is ambiguous or
    weakening and blocks credentials_trusted from any result list.
    """
    for items in groups:
        for code, _url in _iter_codes(items):
            if code in _DOES_NOT_BLOCK_TRUST or code in _RECOGNIZED_FAILURES:
                continue
            return True
    return False


def _names_active(url, active_label: str) -> bool:
    if not isinstance(url, str) or "/c2pa/" not in url:
        return False
    label = url.split("/c2pa/", 1)[1].split("/", 1)[0]
    return label == active_label


def _signature(success: set[str], failure: set[str]) -> str:
    if "claimSignature.missing" in failure:
        return "missing"
    if "claimSignature.mismatch" in failure:
        return "invalid"
    if "claimSignature.validated" in success:
        return "valid"
    return "not_checked"


def _binding(success: set[str], failure: set[str], qualified: set[str]) -> str:
    if failure & _HARD_BINDING_MISMATCH:
        return "mismatch"
    if "claim.hardBindings.missing" in failure:
        return "missing"
    if failure & _HARD_BINDING_MALFORMED:
        return "malformed"
    if qualified:
        return "not_checked"
    if success & _HARD_BINDING_MATCH:
        return "bound"
    return "not_checked"


def _trust(success: set[str], failure: set[str]) -> str:
    if "signingCredential.untrusted" in failure:
        return "untrusted"
    if "signingCredential.trusted" in success:
        return "trusted"
    return "not_checked"


def _validity(success: set[str], failure: set[str]) -> str:
    """Map library validity codes without reading certificate dates.

    ``signingCredential.expired`` and ``claimSignature.outsideValidity``
    are the library's judgment at its chosen time. A trusted timestamp
    makes that time the timestamp. With no timestamp, expiry is expiry
    at validation time, not a claim about the historical signing moment.
    """
    if "signingCredential.expired" in failure:
        return "expired"
    if "claimSignature.outsideValidity" in failure:
        return "outside"
    if "claimSignature.insideValidity" in success:
        return "inside_at_asserted_time"
    return "not_checked"


def _revocation(success: set[str], informational: set[str], failure: set[str]) -> str:
    present = success | informational | failure
    if "signingCredential.ocsp.revoked" in present:
        return "revoked"
    if "signingCredential.ocsp.unknown" in present:
        return "unknown"
    if "signingCredential.ocsp.inaccessible" in present:
        return "inaccessible"
    if "signingCredential.ocsp.notRevoked" in success:
        return "not_revoked"
    if "signingCredential.ocsp.skipped" in present:
        return "skipped"
    return "not_checked"


def _timestamp(success: set[str], failure: set[str], present: set[str]) -> str:
    """Map timestamp tokens. A date elsewhere in the manifest is not a token."""
    if "timeStamp.outsideValidity" in failure:
        return "outside_validity"
    if (
        "timeStamp.malformed" in failure
        or "timeStamp.mismatch" in failure
        or "assertion.timestamp.malformed" in failure
        or "assertion.timestamp.malformed" in present
    ):
        return "malformed"
    if "timeStamp.untrusted" in failure:
        return "untrusted"
    success_pair = {"timeStamp.trusted", "timeStamp.validated"}
    if success_pair <= success and not (failure & _TIMESTAMP_CODES):
        return "trusted"
    if not (present & _TIMESTAMP_CODES):
        return "absent"
    return "not_checked"


def _status_from_checks(
    checks: dict,
    unrecognized_failure: bool = False,
    blocks_trust: bool = False,
    credential_invalid: bool = False,
) -> str:
    invalid = credential_invalid or (
        checks["signature"] in {"invalid", "missing"}
        or checks["assetBinding"] in {"mismatch", "missing", "malformed"}
        or checks["certificateValidity"] in {"outside", "expired"}
        or checks["revocation"] in {"revoked", "unknown", "inaccessible"}
        or checks["timestamp"] in {"untrusted", "malformed", "outside_validity"}
    )
    if invalid:
        return "credentials_invalid"
    demonstrated = (
        checks["signature"] == "valid"
        and checks["assetBinding"] == "bound"
        and checks["certificateValidity"] == "inside_at_asserted_time"
        and checks["timestamp"] in {"trusted", "absent"}
    )
    if not demonstrated or unrecognized_failure or blocks_trust:
        return "credentials_malformed"
    if checks["revocation"] != "not_revoked":
        if checks["certificateTrust"] == "untrusted":
            return "credentials_untrusted"
        return "credentials_malformed"
    if checks["certificateTrust"] == "trusted":
        return "credentials_trusted"
    return "credentials_untrusted"


def _manifest_exceeds_limit(data: bytes) -> bool:
    try:
        if data.startswith(b"\xff\xd8"):
            return _jpeg_manifest_exceeds(data)
        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            return _png_manifest_exceeds(data)
        if len(data) >= 12 and data.startswith(b"RIFF") and data[8:12] == b"WEBP":
            return _webp_manifest_exceeds(data)
    except Exception:
        return True
    return False


def _jpeg_manifest_exceeds(data: bytes) -> bool:
    """Return True when JPEG APP11 data exceeds the cap or cannot be counted.

    Restart markers inside a scan return to entropy-coded bytes. Stuffed
    FF00 bytes and fill bytes stay inside the scan. APP11 segments before
    and after the start of scan are counted. A broken or unfinished marker
    sequence fails closed.
    """
    position = 2
    total = 0
    steps = 0
    in_scan = False
    limit = len(data) + 2
    while position < len(data):
        steps += 1
        if steps > limit or data[position] != 0xFF:
            return True
        while position < len(data) and data[position] == 0xFF:
            position += 1
        if position >= len(data):
            return True
        marker = data[position]
        position += 1
        if marker == 0x00:
            return True
        if marker == 0xD9:
            if position != len(data):
                return True
            return total > MAX_MANIFEST_BYTES
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            if in_scan:
                nxt = _jpeg_next_marker(data, position)
                if nxt is None:
                    return True
                position = nxt
            continue
        if position + 2 > len(data):
            return True
        length = int.from_bytes(data[position:position + 2], "big")
        if length < 2 or position + length > len(data):
            return True
        if marker == 0xEB:
            total += length - 2
            if total > MAX_MANIFEST_BYTES:
                return True
        position += length
        if marker == 0xDA:
            in_scan = True
            nxt = _jpeg_next_marker(data, position)
            if nxt is None:
                return True
            position = nxt
        else:
            in_scan = False
    return True


def _jpeg_next_marker(data: bytes, position: int) -> int | None:
    """Return the offset of the next real marker after a start-of-scan header.

    Stuffed 0xFF00 bytes stay inside the entropy-coded segment. None means
    the scan ended without a marker, so the caller fails closed.
    """
    while position < len(data):
        if data[position] != 0xFF:
            position += 1
            continue
        marker_at = position
        position += 1
        while position < len(data) and data[position] == 0xFF:
            marker_at = position
            position += 1
        if position >= len(data):
            return None
        if data[position] == 0x00:
            position += 1
            continue
        return marker_at
    return None


def _png_manifest_exceeds(data: bytes) -> bool:
    """Return True when PNG C2PA chunks exceed the cap or the walk is incomplete.

    Every chunk is visited through IEND. Stopping early is not treated as a
    manifest that fits the limit.
    """
    position = 8
    total = 0
    saw_end = False
    steps = 0
    while position < len(data):
        steps += 1
        if steps > len(data) or position + 12 > len(data):
            return True
        length = int.from_bytes(data[position:position + 4], "big")
        tag = data[position + 4:position + 8]
        if position + 12 + length > len(data):
            return True
        if tag in _C2PA_CHUNK_TAGS:
            total += length
            if total > MAX_MANIFEST_BYTES:
                return True
        position += 12 + length
        if tag == b"IEND":
            saw_end = True
            break
    if not saw_end or position != len(data):
        return True
    return total > MAX_MANIFEST_BYTES


def _webp_manifest_exceeds(data: bytes) -> bool:
    """Return True when WebP C2PA chunks exceed the cap or the walk is incomplete.

    The RIFF size must match the buffer. Every chunk is visited. A walk that
    stops at a fixed chunk count is not treated as a small manifest.
    """
    if len(data) < 12:
        return True
    declared = int.from_bytes(data[4:8], "little")
    if declared < 4 or declared + 8 != len(data):
        return True
    position = 12
    total = 0
    steps = 0
    while position < len(data):
        steps += 1
        if steps > len(data) or position + 8 > len(data):
            return True
        tag = data[position:position + 4]
        length = int.from_bytes(data[position + 4:position + 8], "little")
        padded = length + (length & 1)
        if position + 8 + padded > len(data):
            return True
        if tag in _WEBP_CHUNK_TAGS:
            total += length
            if total > MAX_MANIFEST_BYTES:
                return True
        position += 8 + padded
    if position != len(data):
        return True
    return False


def _supported_container(data: bytes) -> bool:
    """Return True only for JPEG, PNG, and WebP.

    Every other container returns not_performed before the native Reader
    runs. A supported container that cannot be scanned still fails closed
    in the manifest-size walk.
    """
    if data.startswith(b"\xff\xd8"):
        return True
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return True
    if len(data) >= 12 and data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return True
    return False


def _absent() -> dict:
    return {
        "version": READER_VERSION,
        "status": "no_credentials",
        "checks": None,
        "manifests": [],
        "actions": [],
        "actionsWithheld": True,
    }


def _not_performed() -> dict:
    return {
        "version": READER_VERSION,
        "status": "not_performed",
        "checks": None,
        "actions": [],
        "actionsWithheld": True,
    }


def _technical(code: str) -> dict:
    """Return a process or configuration failure, never a credential finding."""
    if code not in TECHNICAL_FAILURE_CODES:
        code = "reader_crash"
    return {
        "version": READER_VERSION,
        "status": "verification_failed",
        "failureCode": code,
        "checks": None,
        "manifests": [],
        "actions": [],
        "actionsWithheld": True,
    }


def _technical_from_child(result: dict) -> dict:
    code = result.get("failureCode")
    if (
        code not in _CHILD_TECHNICAL_CODES
        or result.get("version") != READER_VERSION
        or result.get("checks") is not None
        or result.get("manifests") != []
        or result.get("actions") not in ([],)
        or result.get("actionsWithheld") is not True
    ):
        return _technical("reader_crash")
    return _technical(code)


def _malformed() -> dict:
    return _with_checks("credentials_malformed", _unchecked())


def _unchecked() -> dict:
    return {name: "not_checked" for name in _CHECK_VALUES}


def _with_checks(status: str, checks: dict) -> dict:
    return {
        "version": READER_VERSION,
        "status": status,
        "checks": checks,
        "actions": [],
        "actionsWithheld": True,
    }


def _clean_checks(checks) -> dict | None:
    if not isinstance(checks, dict) or set(checks) != set(_CHECK_VALUES):
        return None
    cleaned = {}
    for name, allowed in _CHECK_VALUES.items():
        value = checks.get(name)
        if value not in allowed:
            return None
        cleaned[name] = value
    return cleaned


def _clean_manifest_list(manifests) -> list[dict] | None:
    if not isinstance(manifests, list):
        return None
    cleaned = []
    labels = []
    for item in manifests:
        if not isinstance(item, dict) or set(item) != {"label", "role", "status", "checks"}:
            return None
        label = item.get("label")
        role = item.get("role")
        status = item.get("status")
        if not isinstance(label, str) or not label or label in labels:
            return None
        if role not in _MANIFEST_ROLES or status not in _MANIFEST_STATUSES:
            return None
        checks = _clean_checks(item.get("checks"))
        if checks is None:
            return None
        labels.append(label)
        cleaned.append({
            "label": label,
            "role": role,
            "status": status,
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
    return cleaned


def _accept(result) -> dict:
    if not isinstance(result, dict):
        return _technical("reader_crash")
    status = result.get("status")
    if status == "verification_failed":
        return _technical_from_child(result)
    if status not in _STATUSES or result.get("version") != READER_VERSION:
        return _technical("reader_crash")
    if result.get("actions") not in ([],):
        return _malformed()
    if result.get("actionsWithheld") is not True:
        return _malformed()
    checks = result.get("checks")
    if "manifests" not in result:
        if status in {"no_credentials", "not_performed"}:
            if checks is not None:
                return _malformed()
            if status == "no_credentials":
                return _absent()
            return _not_performed()
        cleaned = _clean_checks(checks)
        if cleaned is None:
            return _malformed()
        return _with_checks(status, cleaned)
    listed = _clean_manifest_list(result.get("manifests"))
    if listed is None:
        return _malformed()
    if status in {"no_credentials", "not_performed"}:
        if checks is not None or listed != [] or status == "not_performed":
            return _malformed()
        return _absent()
    if listed == []:
        cleaned = _clean_checks(checks)
        if status != "credentials_malformed" or cleaned != _unchecked():
            return _malformed()
        return _structural_malformed()
    if len(listed) == 1:
        cleaned = _clean_checks(checks)
        entry = listed[0]
        if cleaned is None or cleaned != entry["checks"] or status != entry["status"]:
            return _malformed()
        return _one_manifest(entry["label"], status, cleaned)
    if checks is not None or status != _aggregate_status(listed):
        return _malformed()
    return _finish(status, None, listed)
