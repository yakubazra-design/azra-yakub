"""RealityCheck AI migration backend.

Check Now calls these routes from frontend/engine.js. Source quality,
independence, and the evidence timeline are calculated from the records stored
for that investigation. A confirmed image upload is hashed on the server.
Camera and location fields are read only after a separate metadata consent,
and precise coordinates are not sent to the model.
"""

import hashlib
import hmac
import ipaddress
import logging
import sqlite3
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from secrets import token_hex, token_urlsafe

logger = logging.getLogger(__name__)

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.assetstore import AssetStore, AssetStoreError
from app.auth import (
    MIN_SECRET_LENGTH,
    burn_password_check,
    hash_password,
    new_secret,
    normalise_email,
    password_acceptable,
    session_mac,
    verify_password,
)
from app.config import Settings
from app.errors import ProviderError
from app.evidence import build_timeline, date_fields, independence, prepare_sources
from app.image_evidence import build_image_evidence
from app.images import IMAGE_CONSENT_VERSION, client_hash_status, detect_image
from app.metadata_extract import classify_metadata_consent
from app.ledger import (
    DeletionInProgress,
    Ledger,
    LedgerError,
    TestLedgerRejected,
    assessment_failure_message,
    enable_test_mode,
    production_ledger_path,
    protecting_tests,
    refuse_test_ledger,
)
from app.limits import LIMITS, MAX_BODY_BYTES, MAX_IMAGE_BYTES, MAX_VIDEO_BYTES
from app.video_detect import (
    VIDEO_CONSENT_VERSION,
    VIDEO_REMOVE_CONFIRM,
    classify_video_metadata_consent,
    detect_video_container,
)
from app.video_probe import VideoProbeError, probe_video_file, tier_a_ready
from app.video_store import VideoStore, VideoStoreError
from app.openai_client import OpenAIClient
from app.parallel_client import ParallelClient
from app.prompts import assess_prompt, extract_claims_prompt
from app.quality import classify
from app.seal_flow import resolve_trust_store, seal_with_provenance
from app.ssrf import assert_safe_to_fetch
from app.textutil import clamp_query
from app.urls import public_http_url
from app.validation import normalise_claims, validate_assessment

SESSION_COOKIE = "rc_session"
MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
ASSESSMENT_TTL_SECONDS = 600

FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"

# The page keeps its existing style attributes, Google fonts, and local blob
# previews. Scripts stay on this origin. 'unsafe-inline' is limited to style
# attributes; script-src does not allow it.
CONTENT_SECURITY_POLICY = "; ".join((
    "default-src 'self'",
    "base-uri 'none'",
    "object-src 'none'",
    "frame-src 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "script-src 'self'",
    "style-src 'self' https://fonts.googleapis.com",
    "style-src-attr 'unsafe-inline'",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' blob:",
    "connect-src 'self'",
    "worker-src 'none'",
))
REFERRER_POLICY = "strict-origin-when-cross-origin"
HSTS_VALUE = "max-age=31536000"


def security_headers(production: bool) -> list[tuple[bytes, bytes]]:
    """Headers for every response. HSTS is only added for production HTTPS."""
    headers = [
        (b"content-security-policy", CONTENT_SECURITY_POLICY.encode()),
        (b"x-frame-options", b"DENY"),
        (b"x-content-type-options", b"nosniff"),
        (b"referrer-policy", REFERRER_POLICY.encode()),
    ]
    if production:
        headers.append((b"strict-transport-security", HSTS_VALUE.encode()))
    return headers


class SecurityHeaders:
    def __init__(self, app, production: bool):
        self.app = app
        self.production = production

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                updated = list(message.get("headers") or [])
                updated.extend(security_headers(self.production))
                message = {**message, "headers": updated}
            await send(message)

        await self.app(scope, receive, send_with_headers)


class FrontendFiles(StaticFiles):
    async def get_response(self, path: str, scope):
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-cache"
        return response


class SearchRequest(BaseModel):
    queries: list[str] = Field(default_factory=list)
    sessionId: str | None = None


class FetchRequest(BaseModel):
    url: str
    sessionId: str | None = None


class ExtractClaimsRequest(BaseModel):
    input: str
    kind: str = "claim"


class AssessRequest(BaseModel):
    assessmentToken: str = ""
    primaryClaim: str = ""
    verifiablePoints: list[str] = Field(default_factory=list)
    sources: list[dict] = Field(default_factory=list)
    independence: dict = Field(default_factory=dict)
    timeline: dict = Field(default_factory=dict)
    snapshot: dict | None = None
    imageEvidence: dict | None = None


class InvestigationRequest(BaseModel):
    input: str = ""
    kind: str = "claim"


class AuthRequest(BaseModel):
    email: str = ""
    password: str = ""


class DeleteAccountRequest(BaseModel):
    password: str = ""


class GpsRevealRequest(BaseModel):
    snapshotId: str = ""


def _public_asset(record: dict) -> dict:
    return {
        "assetId": record["assetId"],
        "investigationId": record["investigationId"],
        "ownerId": record["ownerId"],
        "sha256": record["sha256"],
        "byteLength": record["byteLength"],
        "mediaType": record["mediaType"],
        "receivedAt": record["receivedAt"],
        "retention": record["retention"],
        "clientHashStatus": record["clientHashStatus"],
        "consentVersion": record["consentVersion"],
        "metadataConsentVersion": record.get("metadataConsentVersion") or "declined",
        "metadataConsentDecision": record.get("metadataConsentDecision") or "omitted",
        "metadataConsentAt": record.get("metadataConsentAt") or "",
    }


def _public_video(record: dict) -> dict:
    """Owner-safe video metadata. Never includes paths or raw probe JSON."""
    return {
        "videoAssetId": record["videoAssetId"],
        "investigationId": record["investigationId"],
        "sha256": record["sha256"],
        "byteLength": record["byteLength"],
        "mediaType": record["mediaType"],
        "receivedAt": record["receivedAt"],
        "retention": record["retention"],
        "clientHashStatus": record["clientHashStatus"],
        "consentVersion": record["consentVersion"],
        "metadataConsentVersion": record.get("metadataConsentVersion") or "declined",
        "metadataConsentDecision": record.get("metadataConsentDecision") or "omitted",
        "attachmentStatus": record.get("attachmentStatus"),
        "failureCode": record.get("failureCode"),
        "durationMs": record.get("durationMs"),
        "width": record.get("width"),
        "height": record.get("height"),
        "videoCodec": record.get("videoCodec"),
        "audioCodec": record.get("audioCodec"),
        "formatName": record.get("formatName"),
        "frameRate": record.get("frameRate"),
        "bitRate": record.get("bitRate"),
    }


def _video_ingest_disabled() -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={
            "code": "video_ingest_disabled",
            "message": "Video ingestion is not enabled on this server.",
        },
    )


def _video_error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"code": code, "message": message})


def _asset_cleanup_failed(account_deleted: bool, *, investigation: bool = False, files_may_be_removed: bool = False) -> JSONResponse:
    if files_may_be_removed:
        if investigation:
            message = "The investigation still exists. Some image files may already have been removed. The deletion can be retried safely."
        else:
            message = "The account still exists. Some image files may already have been removed. The deletion can be retried safely."
    elif investigation:
        message = "The investigation was not deleted because a stored image could not be removed. The deletion can be retried safely."
    elif account_deleted:
        message = "The account was deleted, but a stored image could not be removed."
    else:
        message = "The account was not deleted because a stored image could not be removed. The deletion can be retried safely."
    body = {
        "ok": False,
        "assetBytesDeleted": False,
        "filesMayBeRemoved": files_may_be_removed,
        "code": "asset_cleanup_failed",
        "message": message,
    }
    if investigation:
        body["deleted"] = False
    else:
        body["accountDeleted"] = account_deleted
    return JSONResponse(status_code=500, content=body)


def _retain_failed_file(store, ledger, owner_id: str, investigation_id: str, storage_name: str, digest: str, byte_length: int, reason: str) -> None:
    try:
        store.finish_intent(storage_name)
    except AssetStoreError:
        if not store.remove(storage_name):
            raise
        return
    if store.remove(storage_name):
        return
    store.note_pending(storage_name, owner_id, investigation_id)
    ledger.record_asset_cleanup(owner_id, investigation_id, storage_name, digest, byte_length, reason)


def _names_for_account(app, ledger, owner_id: str) -> list[str]:
    names = set(ledger.asset_storage_names(owner_id))
    names.update(row["storage_name"] for row in ledger.cleanup_records(owner_id))
    store = app.state.assets
    if store is not None:
        names.update(name for name, owner, _investigation in store.pending_entries() if owner == owner_id)
        names.update(name for name, owner, _investigation in store.intent_entries() if owner == owner_id)
    return sorted(names)


def _names_for_investigation(app, ledger, owner_id: str, investigation_id: str, asset) -> list[str]:
    names = set()
    if asset is not None:
        names.add(asset["storageName"])
    names.update(row["storage_name"] for row in ledger.cleanup_records(owner_id, investigation_id))
    store = app.state.assets
    if store is not None:
        names.update(
            name
            for name, owner, investigation in store.pending_entries()
            if owner == owner_id and investigation == investigation_id
        )
        names.update(
            name
            for name, owner, investigation in store.intent_entries()
            if owner == owner_id and investigation == investigation_id
        )
    return sorted(names)


def _remove_named_files(store, names: list[str]) -> tuple[bool, bool, bool]:
    """Return removed, failed, and whether a listed file was already missing."""
    if not names:
        return False, False, False
    if store is None:
        return False, True, False
    removed = False
    failed = False
    missing = False
    for name in names:
        report = store.remove_report(name)
        if report == "removed":
            removed = True
            try:
                store.finish_intent(name)
            except (AssetStoreError, VideoStoreError):
                failed = True
        elif report == "missing":
            missing = True
            try:
                store.finish_intent(name)
            except (AssetStoreError, VideoStoreError):
                failed = True
        elif report == "failed":
            failed = True
    return removed, failed, missing


def _merge_removal(left: tuple[bool, bool, bool], right: tuple[bool, bool, bool]) -> tuple[bool, bool, bool]:
    return left[0] or right[0], left[1] or right[1], left[2] or right[2]


def _video_names_for_account(app, ledger, owner_id: str) -> list[str]:
    names = set(ledger.video_storage_names(owner_id))
    names.update(row["storage_name"] for row in ledger.video_cleanup_records(owner_id))
    return sorted(names)


def _video_names_for_investigation(ledger, owner_id: str, investigation_id: str, video) -> list[str]:
    names = set()
    if video is not None:
        names.add(video["storageName"])
    names.update(row["storage_name"] for row in ledger.video_cleanup_records(owner_id, investigation_id))
    return sorted(names)


def _remove_account_files(app, ledger, owner_id: str) -> tuple[bool, bool, bool]:
    try:
        names = _names_for_account(app, ledger, owner_id)
        video_names = _video_names_for_account(app, ledger, owner_id)
    except (LedgerError, sqlite3.Error, AssetStoreError, VideoStoreError):
        return False, True, False
    image_result = _remove_named_files(app.state.assets, names)
    video_result = _remove_named_files(app.state.videos, video_names)
    return _merge_removal(image_result, video_result)


def _remove_investigation_files(app, ledger, owner_id: str, investigation_id: str, asset) -> tuple[bool, bool, bool]:
    try:
        names = _names_for_investigation(app, ledger, owner_id, investigation_id, asset)
        video = ledger.video_asset(owner_id, investigation_id)
        video_names = _video_names_for_investigation(ledger, owner_id, investigation_id, video)
    except (LedgerError, sqlite3.Error, AssetStoreError, VideoStoreError):
        return False, True, False
    image_result = _remove_named_files(app.state.assets, names)
    video_result = _remove_named_files(app.state.videos, video_names)
    return _merge_removal(image_result, video_result)


def _deletion_in_progress() -> JSONResponse:
    return JSONResponse(
        status_code=409,
        content={
            "code": "deletion_in_progress",
            "message": "An assessment cannot be sealed while deletion is in progress.",
        },
    )


async def _untrusted_seal_input(request: Request):
    """Read a client hash or provenance value so it can be discarded.

    The seal snapshot is built from the ledger. These values are not copied
    into that snapshot and are not sent to the assessment model.
    """
    client_hash = request.headers.get("x-client-sha256")
    content_type = request.headers.get("content-type", "")
    if "application/json" not in content_type.lower():
        return None, client_hash
    try:
        payload = await request.json()
    except Exception:
        return {"rejected": True}, client_hash
    if isinstance(payload, dict) and "provenance" in payload:
        return payload.get("provenance"), client_hash
    if payload is not None:
        return payload, client_hash
    return None, client_hash


def _unavailable() -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"code": "ledger_unavailable", "message": "The evidence ledger is unavailable."},
    )


def _nostore(response):
    """Keep a reveal response, including an error, out of caches."""
    headers = {
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
        "Referrer-Policy": "no-referrer",
    }
    if isinstance(response, JSONResponse):
        response.headers.update(headers)
        return response
    return JSONResponse(content=response, headers=headers)


def _missing() -> JSONResponse:
    return JSONResponse(
        status_code=404,
        content={"code": "not_found", "message": "That investigation was not found."},
    )


def _is_token(value: str) -> bool:
    return len(value) == 32 and all(char in "0123456789abcdef" for char in value)


def _session_cookie_name(settings: Settings) -> str:
    if settings.cookie_secure:
        return "__Host-rc_session"
    return SESSION_COOKIE


class StartupError(RuntimeError):
    """Production configuration cannot serve requests."""


def _single_forwarded_ip(value: str | None) -> str | None:
    """Return one forwarded address, or None when the header is not a single IP."""
    if value is None:
        return None
    text = value.strip()
    if not text or "," in text or any(char.isspace() for char in text):
        return None
    try:
        return ipaddress.ip_address(text).compressed
    except ValueError:
        return None


def client_address(peer: str | None, forwarded_for: str | None, trusted_proxies: frozenset[str]) -> str:
    """Return the visitor address used for login and registration limits.

    X-Forwarded-For is read only when the TCP peer is one of the configured
    proxy addresses and the header contains exactly one IP. A list, the
    Forwarded header, and any header from another peer are ignored.
    """
    if peer is None or not str(peer).strip():
        return "unknown"
    peer_text = str(peer).strip()
    try:
        peer_ip = ipaddress.ip_address(peer_text).compressed
    except ValueError:
        return peer_text
    if peer_ip not in trusted_proxies:
        return peer_ip
    forwarded = _single_forwarded_ip(forwarded_for)
    if forwarded is None:
        return peer_ip
    return forwarded


def _auth_secret(settings: Settings) -> str | None:
    secret = settings.auth_secret.strip()
    if settings.production:
        if not settings.cookie_secure or len(secret) < MIN_SECRET_LENGTH:
            return None
        return secret
    if secret and len(secret) < MIN_SECRET_LENGTH:
        return None
    if settings.cookie_secure and not secret:
        return None
    if not secret:
        return new_secret()
    return secret


def _production_gate(settings: Settings) -> None:
    """Stop process startup when production settings are not safe.

    Local development is unchanged. Production never reaches the ephemeral
    secret used when AUTH_SECRET is unset on a local HTTP process.
    """
    if not settings.production:
        return
    if not settings.cookie_secure:
        raise StartupError("COOKIE_SECURE must be true in production.")
    if len(settings.auth_secret.strip()) < MIN_SECRET_LENGTH:
        raise StartupError("AUTH_SECRET must be at least 32 characters in production.")
    if production_ledger_path(settings.ledger_path, FRONTEND_DIR) is None:
        raise StartupError("LEDGER_PATH is not a usable database file.")
    proxies, proxies_valid = settings.trusted_proxy_addresses
    if not proxies_valid:
        raise StartupError("TRUSTED_PROXIES must contain only IP addresses.")
    if not proxies:
        raise StartupError("TRUSTED_PROXIES must list the reverse proxy address in production.")


def _trust_gate(settings: Settings) -> None:
    """Reject a trust setting that is not a local path.

    An empty configuration stays unavailable at seal time. It does not select
    operating-system trust and it does not fetch a bundle.
    """
    if settings.c2pa_trust_remote:
        raise StartupError("C2PA trust configuration must be a local path.")
    if not settings.production:
        return
    for path in settings.c2pa_trust_path_values:
        if path and not Path(path).is_absolute():
            raise StartupError("C2PA trust configuration must use absolute local paths.")


def _unauthenticated() -> JSONResponse:
    return JSONResponse(
        status_code=401,
        content={"code": "unauthenticated", "message": "Sign in to continue."},
    )


def _invalid_credentials() -> JSONResponse:
    return JSONResponse(
        status_code=401,
        content={"code": "invalid_credentials", "message": "The email or password is incorrect."},
    )


def _csrf_failed() -> JSONResponse:
    return JSONResponse(
        status_code=403,
        content={"code": "csrf_failed", "message": "The request could not be verified."},
    )


class RequestSizeLimit:
    """Reject an oversized body before the route reads it.

    JSON routes stay at 64 KiB. The image upload route may receive the
    separate image limit. No other path inherits that limit. One ASGI
    message larger than the limit is not copied into the accumulated body.
    The server may already have allocated that message. The reverse proxy
    is what stops it from being accepted onto this host.
    """

    def __init__(
        self,
        app,
        max_bytes: int = MAX_BODY_BYTES,
        image_bytes: int = MAX_IMAGE_BYTES,
        video_bytes: int = MAX_VIDEO_BYTES,
    ):
        self.app = app
        self.max_bytes = max_bytes
        self.image_bytes = image_bytes
        self.video_bytes = video_bytes

    def _limit(self, scope) -> int:
        path = scope.get("path") or ""
        method = scope.get("method")
        if method == "POST" and path.endswith("/asset"):
            return self.image_bytes
        if method == "POST" and path.endswith("/video"):
            return self.video_bytes
        return self.max_bytes

    def _is_video_upload(self, scope) -> bool:
        path = scope.get("path") or ""
        return scope.get("method") == "POST" and path.endswith("/video")

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        allowed = self._limit(scope)
        length = _content_length(scope, allowed)
        if length is not None and length > allowed:
            await _reply_too_large(send)
            return
        # Video uploads stream to disk in the route. Do not buffer the body.
        if self._is_video_upload(scope):
            total = 0
            closed = False

            async def limited_receive():
                nonlocal total, closed
                if closed:
                    return {"type": "http.disconnect"}
                message = await receive()
                if message["type"] != "http.request":
                    return message
                piece = message.get("body", b"") or b""
                if len(piece) > allowed or total > allowed - len(piece):
                    closed = True
                    scope["rc_video_too_large"] = True
                    return {"type": "http.request", "body": b"", "more_body": False}
                total += len(piece)
                return message

            await self.app(scope, limited_receive, send)
            return

        chunks = []
        total = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                chunks = []
                break
            piece = message.get("body", b"") or b""
            # The ASGI server may already have allocated this message. Do not
            # copy an oversized message into the accumulated body. A reverse
            # proxy should reject anything larger than the image limit before
            # it reaches this process; this check cannot undo that allocation.
            if len(piece) > allowed or total > allowed - len(piece):
                await _reply_too_large(send)
                return
            total += len(piece)
            chunks.append(piece)
            if not message.get("more_body", False):
                break
        payload = b"".join(chunks)
        sent = False

        async def replay():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": payload, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


def _content_length(scope, allowed: int) -> int | None:
    for name, value in scope.get("headers", []):
        if name.lower() == b"content-length":
            try:
                return int(value.decode())
            except ValueError:
                return allowed + 1
    return None


async def _reply_too_large(send) -> None:
    body = b'{"code":"request_too_large","message":"The request is too large."}'
    await send({
        "type": "http.response.start",
        "status": 413,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ],
    })
    await send({"type": "http.response.body", "body": body})


def _auth_unavailable() -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"code": "auth_unavailable", "message": "Authentication is unavailable."},
    )


def _session_cookie(response: JSONResponse, token: str, settings: Settings) -> JSONResponse:
    secure = bool(settings.cookie_secure)
    response.set_cookie(
        _session_cookie_name(settings),
        token,
        max_age=max(int(settings.session_ttl_seconds), 0),
        httponly=True,
        secure=secure,
        samesite="strict" if secure else "lax",
        path="/",
    )
    return response


def _clear_session_cookie(response: JSONResponse, settings: Settings) -> JSONResponse:
    secure = bool(settings.cookie_secure)
    response.delete_cookie(
        _session_cookie_name(settings),
        path="/",
        secure=secure,
        httponly=True,
        samesite="strict" if secure else "lax",
    )
    return response


def _require_explicit_test_ledger(settings: Settings) -> None:
    """Refuse the development ledger before a test application opens one.

    An empty path is not explicit: ``Settings`` would otherwise use
    ``data/ledger.sqlite``. The comparison covers the absolute path and the
    symlink-resolved path. This function does not connect to a database.
    """
    explicit = settings.ledger_path.strip()
    if not explicit:
        raise TestLedgerRejected(
            "A test application must receive an explicit ledger path. "
            "The development ledger is not used."
        )
    refuse_test_ledger(Path(explicit))


def create_app(
    settings: Settings | None = None,
    parallel_transport=None,
    openai_transport=None,
    retry_wait: float = 0.0,
    fetch_guard=None,
    limits: dict | None = None,
    testing: bool = False,
    trust_store=None,
    c2pa_reader=None,
    trust_witness=None,
    trust_root_control=None,
) -> FastAPI:
    if testing:
        enable_test_mode()
    supplied = settings
    if protecting_tests() and supplied is None:
        raise TestLedgerRejected(
            "A test application must receive an explicit ledger path. "
            "The development ledger is not used."
        )
    settings = supplied or Settings()
    proxies, proxies_valid = settings.trusted_proxy_addresses
    if not settings.production and not proxies_valid:
        raise StartupError("TRUSTED_PROXIES must contain only IP addresses.")
    _production_gate(settings)
    _trust_gate(settings)
    if protecting_tests():
        _require_explicit_test_ledger(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        app.state.parallel.close()
        app.state.openai.close()

    app = FastAPI(title="RealityCheck AI", version="migration-0.1.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.auth_secret = _auth_secret(settings)
    app.state.auth_ready = app.state.auth_secret is not None
    app.state.trusted_proxies = proxies
    app.state.limits = dict(LIMITS)
    if limits:
        app.state.limits.update(limits)
    try:
        app.state.ledger = Ledger(settings.ledger_file)
        app.state.assets = AssetStore.for_ledger(settings.ledger_file)
        app.state.videos = VideoStore.for_ledger(settings.ledger_file)
    except (LedgerError, AssetStoreError, VideoStoreError) as exc:
        if settings.production:
            raise StartupError("The evidence ledger is unavailable.") from exc
        app.state.ledger = None
        app.state.assets = None
        app.state.videos = None
    app.state.parallel = ParallelClient(
        settings.parallel_api_key,
        settings.parallel_api_base,
        transport=parallel_transport,
        retry_wait=retry_wait,
    )
    app.state.fetch_guard = fetch_guard or assert_safe_to_fetch
    app.state.openai = OpenAIClient(
        settings.openai_api_key,
        settings.openai_api_base,
        transport=openai_transport,
        retry_wait=retry_wait,
    )
    app.state.trust_store = resolve_trust_store(
        settings,
        trust_store,
        witness=trust_witness,
        root_control=trust_root_control,
    )
    app.state.c2pa_reader = c2pa_reader

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_methods=["GET", "POST", "DELETE"],
            allow_headers=["Content-Type", "X-CSRF-Token"],
        )

    @app.exception_handler(ProviderError)
    async def provider_error(_request: Request, exc: ProviderError):
        return JSONResponse(status_code=exc.status_code, content={"code": exc.code, "message": exc.message})

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_request: Request, _exc: RequestValidationError):
        return JSONResponse(
            status_code=400,
            content={"code": "invalid_request", "message": "The request could not be read."},
        )

    def _ledger_healthy() -> bool:
        ledger = app.state.ledger
        if ledger is None:
            return False
        try:
            return ledger.check_health() is True
        except Exception:
            return False

    @app.get("/api/health")
    def health():
        healthy = _ledger_healthy()
        body = {
            "status": "ok" if healthy else "unhealthy",
            "openaiConfigured": settings.openai_configured,
            "parallelConfigured": settings.parallel_configured,
            "authReady": app.state.auth_ready,
            "videoIngestEnabled": bool(settings.video_ingest_enabled),
            "videoIngestAvailable": bool(
                settings.video_ingest_enabled and tier_a_ready(settings.ffprobe_path)[0]
            ),
        }
        if healthy:
            return body
        return JSONResponse(status_code=503, content=body)

    def _client_ip(request: Request) -> str:
        peer = request.client.host if request.client is not None else None
        return client_address(peer, request.headers.get("x-forwarded-for"), app.state.trusted_proxies)

    def _rate_limited(retry_after: int) -> JSONResponse:
        response = JSONResponse(
            status_code=429,
            content={"code": "rate_limited", "message": "Too many requests. Try again later."},
        )
        response.headers["Retry-After"] = str(max(int(retry_after), 1))
        return response

    def enforce_limit(bucket: str, subject: str):
        ledger = app.state.ledger
        if ledger is None:
            return _unavailable()
        limit, window = app.state.limits[bucket]
        try:
            allowed, retry_after = ledger.hit_rate_limit(bucket, subject, limit, window)
        except (LedgerError, sqlite3.Error):
            return _unavailable()
        if not allowed:
            return _rate_limited(retry_after)
        return None

    def require_ledger() -> Ledger | JSONResponse:
        ledger = app.state.ledger
        if ledger is None:
            return _unavailable()
        return ledger

    def current_session(request: Request):
        ledger = require_ledger()
        if isinstance(ledger, JSONResponse):
            return None, ledger
        if not app.state.auth_ready:
            return None, _auth_unavailable()
        token = request.cookies.get(_session_cookie_name(settings), "")
        if not token:
            return None, _unauthenticated()
        try:
            session = ledger.get_session(session_mac(app.state.auth_secret, token))
        except (LedgerError, sqlite3.Error):
            return None, _unavailable()
        if session is None:
            return None, _unauthenticated()
        if request.method in MUTATING:
            supplied = request.headers.get("x-csrf-token", "")
            expected = session["csrf_token"]
            if not supplied or not hmac.compare_digest(supplied, expected):
                return None, _csrf_failed()
        return session, None

    def require_case(request: Request, investigation_id: str):
        session, error = current_session(request)
        if error is not None:
            return error, None
        if not _is_token(investigation_id):
            return _missing(), None
        ledger = app.state.ledger
        try:
            case = ledger.get_investigation(session["user_id"], investigation_id)
        except (LedgerError, sqlite3.Error):
            return _unavailable(), None
        if case is None:
            return _missing(), None
        return case, ledger

    def issue_session(user_id: str):
        token = token_urlsafe(32)
        csrf_token = token_urlsafe(32)
        expires = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=int(settings.session_ttl_seconds))
        try:
            app.state.ledger.create_session(
                user_id,
                session_mac(app.state.auth_secret, token),
                csrf_token,
                expires.isoformat(),
            )
        except (LedgerError, sqlite3.Error):
            return _unavailable()
        return token, csrf_token

    @app.post("/api/auth/register")
    def register(body: AuthRequest, request: Request):
        ledger = require_ledger()
        if isinstance(ledger, JSONResponse):
            return ledger
        if not app.state.auth_ready:
            return _auth_unavailable()
        email = normalise_email(body.email)
        if email is None or not password_acceptable(body.password):
            return JSONResponse(
                status_code=400,
                content={"code": "invalid_account", "message": "Use an email address and a password of at least 12 characters."},
            )
        blocked = enforce_limit("register", _client_ip(request))
        if blocked is not None:
            return blocked
        try:
            existing = ledger.get_account_by_email(email)
            if existing is None:
                created = ledger.create_account(email, hash_password(body.password))
                if created is None:
                    existing = ledger.get_account_by_email(email)
            else:
                verify_password(existing["password_hash"], body.password)
        except (LedgerError, sqlite3.Error):
            return _unavailable()
        return {"ok": True}

    @app.post("/api/auth/login")
    def login(body: AuthRequest, request: Request):
        ledger = require_ledger()
        if isinstance(ledger, JSONResponse):
            return ledger
        if not app.state.auth_ready:
            return _auth_unavailable()
        blocked = enforce_limit("login", _client_ip(request))
        if blocked is not None:
            return blocked
        email = normalise_email(body.email)
        password = body.password if isinstance(body.password, str) else ""
        account = None
        try:
            if email is not None:
                account = ledger.get_account_by_email(email)
        except (LedgerError, sqlite3.Error):
            return _unavailable()
        if account is None:
            burn_password_check(password)
            return _invalid_credentials()
        if not verify_password(account["password_hash"], password):
            return _invalid_credentials()
        issued = issue_session(account["id"])
        if isinstance(issued, JSONResponse):
            return issued
        token, csrf_token = issued
        return _session_cookie(
            JSONResponse({"email": account["email"], "csrfToken": csrf_token}),
            token,
            settings,
        )

    @app.get("/api/auth/session")
    def read_session(request: Request):
        session, error = current_session(request)
        if error is not None:
            return error
        return {"email": session["email"], "csrfToken": session["csrf_token"]}

    @app.post("/api/auth/logout")
    def logout(request: Request):
        ledger = require_ledger()
        if isinstance(ledger, JSONResponse):
            return ledger
        if not app.state.auth_ready:
            return _auth_unavailable()
        token = request.cookies.get(_session_cookie_name(settings), "")
        session = None
        if token:
            try:
                session = ledger.get_session(session_mac(app.state.auth_secret, token))
            except (LedgerError, sqlite3.Error):
                return _unavailable()
        if session is None:
            return _unauthenticated()
        supplied = request.headers.get("x-csrf-token", "")
        if not supplied or not hmac.compare_digest(supplied, session["csrf_token"]):
            return _csrf_failed()
        try:
            ledger.revoke_session(session_mac(app.state.auth_secret, token))
        except (LedgerError, sqlite3.Error):
            return _unavailable()
        return _clear_session_cookie(JSONResponse({"ok": True}), settings)

    @app.delete("/api/auth/account")
    def delete_account(body: DeleteAccountRequest, request: Request):
        session, error = current_session(request)
        if error is not None:
            return error
        ledger = app.state.ledger
        try:
            status = ledger.prepare_account_deletion(session["user_id"], body.password)
        except (LedgerError, sqlite3.Error):
            return _unavailable()
        removed_files = False
        files_may_be_removed = False
        if status == "ok":
            removed_files, failed, missing = _remove_account_files(app, ledger, session["user_id"])
            files_may_be_removed = removed_files or missing
            if failed:
                return _asset_cleanup_failed(False, files_may_be_removed=files_may_be_removed)
        try:
            result = ledger.erase_account(session["user_id"], body.password)
        except (LedgerError, sqlite3.Error):
            if files_may_be_removed:
                return _asset_cleanup_failed(False, files_may_be_removed=True)
            return _unavailable()
        if result == "ok":
            return _clear_session_cookie(JSONResponse({"ok": True}), settings)
        if files_may_be_removed:
            return _asset_cleanup_failed(False, files_may_be_removed=True)
        if result == "missing":
            return _clear_session_cookie(_unauthenticated(), settings)
        if result == "legacy":
            return JSONResponse(
                status_code=403,
                content={"code": "account_not_erasable", "message": "This account cannot be deleted."},
            )
        return JSONResponse(
            status_code=403,
            content={"code": "invalid_password", "message": "The password is not correct."},
        )

    @app.post("/api/investigations")
    def open_investigation(body: InvestigationRequest, request: Request):
        session, error = current_session(request)
        if error is not None:
            return error
        ledger = app.state.ledger
        text = body.input.strip()
        if not text:
            return JSONResponse(
                status_code=400,
                content={"code": "empty_input", "message": "A claim or page address is required."},
            )
        blocked = enforce_limit("investigation", session["user_id"])
        if blocked is not None:
            return blocked
        kind = "url" if body.kind == "url" else "claim"
        try:
            investigation_id = ledger.create_investigation(session["user_id"], kind, text)
        except (LedgerError, sqlite3.Error):
            return _unavailable()
        if investigation_id is None:
            return _unavailable()
        return {"investigationId": investigation_id, "kind": kind}

    @app.post("/api/investigations/{investigation_id}/search")
    def search(investigation_id: str, body: SearchRequest, request: Request):
        case, ledger = require_case(request, investigation_id)
        if ledger is None:
            return case
        if not any(isinstance(query, str) and clamp_query(query) for query in body.queries):
            return JSONResponse(
                status_code=400,
                content={"code": "empty_query", "message": "A search query is required."},
            )
        blocked = enforce_limit("search", case["owner_id"])
        if blocked is not None:
            return blocked
        found = app.state.parallel.search(body.queries, body.sessionId)
        prepared = prepare_sources(found["sources"])
        try:
            stored = ledger.replace_sources(case["owner_id"], investigation_id, prepared)
        except (LedgerError, sqlite3.Error):
            return _unavailable()
        if stored is None:
            return _missing()
        for source in stored:
            source.pop("position", None)
        found["sources"] = stored
        found["investigationId"] = investigation_id
        _best_effort_graph(
            ledger,
            case["owner_id"],
            investigation_id,
            "investigation_skeleton",
            investigation_id,
        )
        return found

    @app.post("/api/investigations/{investigation_id}/fetch")
    def fetch(investigation_id: str, request: Request):
        case, ledger = require_case(request, investigation_id)
        if ledger is None:
            return case
        if case["kind"] != "url":
            return JSONResponse(
                status_code=400,
                content={"code": "bad_url", "message": "A web page address is required."},
            )
        try:
            url = public_http_url(case["input_text"])
        except ValueError as exc:
            return JSONResponse(
                status_code=400,
                content={"code": "bad_url", "message": str(exc)},
            )
        blocked = enforce_limit("fetch", case["owner_id"])
        if blocked is not None:
            return blocked
        try:
            app.state.fetch_guard(url)
        except ValueError as exc:
            return JSONResponse(
                status_code=400,
                content={"code": "bad_url", "message": str(exc)},
            )
        page = app.state.parallel.fetch(url, None)
        record = {
            "url": page.get("url") or url,
            "title": page.get("title"),
            "snippet": str(page.get("text") or "")[:2000],
            "publishedAt": page.get("publishedAt"),
        }
        published, certainty, date_type = date_fields(record)
        try:
            page_id = ledger.save_page(case["owner_id"], investigation_id, {
                "requested_url": url,
                "final_url": record["url"],
                "title": page.get("title"),
                "body_text": page.get("text") or "",
                "published_at": published,
                "date_certainty": certainty,
                "date_type": date_type,
                "provider": "Parallel Search",
            })
        except (LedgerError, sqlite3.Error):
            return _unavailable()
        if page_id is None:
            return _missing()
        page["url"] = record["url"]
        page["publishedAt"] = published
        page["dateCertainty"] = certainty
        page["dateType"] = date_type
        page["quality"] = classify(record["url"])
        page["id"] = page_id
        return page

    @app.get("/api/investigations/{investigation_id}/evidence")
    def evidence(investigation_id: str, request: Request):
        case, ledger = require_case(request, investigation_id)
        if ledger is None:
            return case
        blocked = enforce_limit("evidence", case["owner_id"])
        if blocked is not None:
            return blocked
        try:
            sources = ledger.list_sources(case["owner_id"], investigation_id)
        except (LedgerError, sqlite3.Error):
            return _unavailable()
        if sources is None:
            return _missing()
        return {
            "investigationId": investigation_id,
            "sources": sources,
            "independence": independence(sources),
            "timeline": build_timeline(sources),
        }

    @app.post("/api/investigations/{investigation_id}/extract-claims")
    def extract_claims(investigation_id: str, request: Request):
        case, ledger = require_case(request, investigation_id)
        if ledger is None:
            return case
        if case["kind"] == "url":
            try:
                page = ledger.get_page(case["owner_id"], investigation_id)
            except (LedgerError, sqlite3.Error):
                return _unavailable()
            if page is None:
                return JSONResponse(
                    status_code=400,
                    content={"code": "page_missing", "message": "The submitted page has not been read."},
                )
            material = page["body_text"]
            kind = "url"
        else:
            material = case["input_text"]
            kind = "claim"
        blocked = enforce_limit("extract", case["owner_id"])
        if blocked is not None:
            return blocked
        prompt = extract_claims_prompt(material, kind)
        raw = app.state.openai.complete_json(
            prompt,
            settings.openai_model_default,
            "Claim analysis is unavailable in this view.",
        )
        normalised = normalise_claims(raw, material)
        try:
            saved = ledger.save_claims(
                case["owner_id"],
                investigation_id,
                str(normalised.get("primaryClaim") or ""),
                normalised.get("verifiablePoints") if isinstance(normalised.get("verifiablePoints"), list) else [],
            )
        except (LedgerError, sqlite3.Error, TypeError):
            return _unavailable()
        if not saved:
            return _missing()
        _best_effort_graph(
            ledger,
            case["owner_id"],
            investigation_id,
            "investigation_skeleton",
            investigation_id,
        )
        return normalised

    def _best_effort_graph(ledger: Ledger, owner_id: str, investigation_id: str, scope_type: str, scope_id: str) -> None:
        """Separate from Phase A persistence. Never raises into the HTTP success path."""
        try:
            ledger.materialize_graph_scope(owner_id, investigation_id, scope_type, scope_id)
        except (LedgerError, sqlite3.Error, ValueError, TypeError) as exc:
            code = getattr(exc, "failure_code", None) or "graph_persist_failed"
            if not isinstance(code, str) or not code:
                code = "graph_persist_failed"
            # Safe catalog codes only — never log secrets, prompts, or provider bodies.
            logger.warning(
                "graph_materialization_failed investigation_id=%s scope_type=%s scope_id=%s error_code=%s",
                investigation_id,
                scope_type,
                scope_id,
                code,
            )

    def _claim_context(case: dict, ledger: Ledger):
        sources = ledger.list_sources(case["owner_id"], investigation_id := case["id"])
        claims = ledger.get_claims(case["owner_id"], investigation_id)
        if sources is None:
            return None
        if claims is None:
            primary = case["input_text"]
            points = [case["input_text"]] if case["kind"] == "claim" else []
        else:
            primary = claims["primaryClaim"]
            points = claims["verifiablePoints"]
        return {
            "primaryClaim": primary,
            "verifiablePoints": points,
            "sources": sources,
            "independence": independence(sources),
            "timeline": build_timeline(sources),
        }

    def _token_invalid() -> JSONResponse:
        return JSONResponse(
            status_code=403,
            content={"code": "assessment_token_invalid", "message": "The assessment token is not valid."},
        )

    def _token_expired() -> JSONResponse:
        return JSONResponse(
            status_code=403,
            content={"code": "assessment_token_expired", "message": "The assessment token has expired."},
        )

    def _token_used() -> JSONResponse:
        return JSONResponse(
            status_code=403,
            content={"code": "assessment_token_used", "message": "The assessment token has already been used."},
        )

    @app.post("/api/investigations/{investigation_id}/seal")
    async def seal_investigation(investigation_id: str, request: Request):
        case, ledger = require_case(request, investigation_id)
        if ledger is None:
            return case
        blocked = enforce_limit("seal", case["owner_id"])
        if blocked is not None:
            return blocked
        try:
            snapshot = _claim_context(case, ledger)
        except (LedgerError, sqlite3.Error):
            return _unavailable()
        if snapshot is None:
            return _missing()
        try:
            asset = ledger.image_asset(case["owner_id"], investigation_id)
        except (LedgerError, sqlite3.Error):
            return _unavailable()
        token = token_urlsafe(32)
        expires = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=ASSESSMENT_TTL_SECONDS)
        client_provenance, client_hash = await _untrusted_seal_input(request)
        try:
            outcome = seal_with_provenance(
                ledger=ledger,
                owner_id=case["owner_id"],
                investigation_id=investigation_id,
                token_hash=session_mac(app.state.auth_secret, token),
                snapshot=snapshot,
                expires_at=expires.isoformat(),
                asset_directory=Path(ledger.path).parent / "assets",
                asset=asset,
                trust_store=app.state.trust_store,
                reader=app.state.c2pa_reader,
                client_provenance=client_provenance,
                untrusted_client_sha256=client_hash,
                video_seal_integration=bool(settings.video_seal_integration),
            )
        except DeletionInProgress:
            return _deletion_in_progress()
        except (LedgerError, sqlite3.Error):
            return _unavailable()
        if outcome["ok"]:
            # Skeleton then snapshot: each scope owns its checkpoint transaction.
            _best_effort_graph(
                ledger,
                case["owner_id"],
                investigation_id,
                "investigation_skeleton",
                investigation_id,
            )
            if isinstance(outcome.get("snapshotId"), str):
                _best_effort_graph(
                    ledger,
                    case["owner_id"],
                    investigation_id,
                    "snapshot",
                    outcome["snapshotId"],
                )
            return {"assessmentToken": token, "expiresAt": expires.isoformat()}
        if outcome["code"] == "identity_mismatch":
            return JSONResponse(
                status_code=409,
                content={
                    "code": "identity_mismatch",
                    "message": "The stored image changed before the assessment could be sealed.",
                },
            )
        if outcome["code"] == "video_not_ready":
            return JSONResponse(
                status_code=409,
                content={
                    "code": "video_not_ready",
                    "message": "The attached video is not ready to seal.",
                },
            )
        if outcome["code"] == "video_identity_mismatch":
            return JSONResponse(
                status_code=409,
                content={
                    "code": "video_identity_mismatch",
                    "message": "The stored video could not be verified before sealing.",
                },
            )
        if outcome["code"] == "video_seal_busy":
            return JSONResponse(
                status_code=409,
                content={
                    "code": "video_seal_busy",
                    "message": "The video could not be sealed while another upload is in progress.",
                },
            )
        if outcome["code"] == "deletion_in_progress":
            return _deletion_in_progress()
        if outcome["code"] == "not_found":
            return _missing()
        return _unavailable()

    @app.post("/api/investigations/{investigation_id}/assess")
    def assess(investigation_id: str, body: AssessRequest, request: Request):
        case, ledger = require_case(request, investigation_id)
        if ledger is None:
            return case
        blocked = enforce_limit("assess", case["owner_id"])
        if blocked is not None:
            return blocked
        token = body.assessmentToken.strip()
        if not token:
            return _token_invalid()
        try:
            snapshot, status = ledger.consume_assessment(
                case["owner_id"],
                investigation_id,
                session_mac(app.state.auth_secret, token),
            )
        except (LedgerError, sqlite3.Error):
            return _unavailable()
        if status == "expired":
            return _token_expired()
        if status == "used":
            return _token_used()
        if status != "ok" or snapshot is None:
            return _token_invalid()
        snapshot_id = snapshot.get("snapshotId") if isinstance(snapshot.get("snapshotId"), str) else ""
        if not snapshot_id:
            return _unavailable()
        # Recovery: if a completed result already exists for this snapshot,
        # return it without another provider call (token was already one-shot).
        try:
            existing = ledger.get_assessment_by_snapshot(
                case["owner_id"], investigation_id, snapshot_id
            )
        except (LedgerError, sqlite3.Error):
            existing = None
        if existing is not None and existing.get("status") == "completed":
            return _public_assessment_response(existing)

        ctx = {
            "primaryClaim": snapshot.get("primaryClaim") or "",
            "verifiablePoints": snapshot.get("verifiablePoints") or [],
            "sources": snapshot.get("sources") or [],
            "independence": snapshot.get("independence") or {},
            "timeline": snapshot.get("timeline") or {},
            "sealedImage": isinstance(snapshot.get("sealedAsset"), dict),
        }
        prompt = assess_prompt(ctx)
        try:
            raw = app.state.openai.complete_json(
                prompt,
                settings.openai_model_complex,
                "Assessment is unavailable in this view.",
            )
        except ProviderError as exc:
            try:
                ledger.save_failed_assessment(
                    case["owner_id"],
                    investigation_id,
                    snapshot_id,
                    failure_code=exc.code,
                )
            except Exception:
                pass
            raise
        result = validate_assessment(raw, snapshot)
        model_assessment = result.pop("modelAssessment", result.get("assessment"))
        # The consume step already compared the stored bytes with the sealed
        # hash. This check time is part of the response only.
        checked_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        result["imageEvidence"] = build_image_evidence(
            snapshot.get("sealedAsset"),
            result.get("assessment") or "",
            availability="retained",
            checked_at=checked_at,
            embedded=snapshot.get("embeddedMetadata"),
            snapshot_id=snapshot_id,
            provenance=snapshot.get("provenance") if isinstance(snapshot, dict) and "provenance" in snapshot else None,
        )
        try:
            saved = ledger.save_completed_assessment(
                case["owner_id"],
                investigation_id,
                snapshot_id,
                model_assessment=model_assessment,
                facing_assessment=result.get("assessment") or "UNRESOLVED",
                why=result.get("why") or {},
                uncertainty=result.get("uncertainty") or [],
                original_material=result.get("originalMaterial") or {},
                findings=result.get("findings") or [],
                image_evidence=result.get("imageEvidence"),
            )
        except LedgerError as exc:
            if getattr(exc, "failure_code", None) == "persist_failed":
                return JSONResponse(
                    status_code=503,
                    content={
                        "code": "assessment_persist_failed",
                        "message": assessment_failure_message("persist_failed"),
                    },
                )
            return _unavailable()
        except sqlite3.Error:
            return JSONResponse(
                status_code=503,
                content={
                    "code": "assessment_persist_failed",
                    "message": assessment_failure_message("persist_failed"),
                },
            )
        result["assessmentResultId"] = saved.get("assessmentResultId")
        result["snapshotId"] = snapshot_id
        result["assessedAt"] = saved.get("assessedAt") or checked_at
        result.pop("modelAssessment", None)
        # Best-effort graph materialization AFTER Phase A commit. Failures do not
        # change this successful assessment response or re-call the provider.
        if saved.get("assessmentResultId"):
            _best_effort_graph(
                ledger,
                case["owner_id"],
                investigation_id,
                "assessment_result",
                saved["assessmentResultId"],
            )
        return result

    def _public_assessment_response(saved: dict) -> dict | JSONResponse:
        """Shape a stored completed assessment like the live assess response."""
        if saved.get("status") != "completed":
            return _missing()
        body = {
            "assessment": saved.get("assessment"),
            "findings": saved.get("findings") or [],
            "originalMaterial": saved.get("originalMaterial") or {},
            "why": saved.get("why") or {},
            "uncertainty": saved.get("uncertainty") or [],
            "assessmentResultId": saved.get("assessmentResultId"),
            "snapshotId": saved.get("snapshotId"),
            "assessedAt": saved.get("assessedAt"),
        }
        if saved.get("imageEvidence") is not None:
            body["imageEvidence"] = saved["imageEvidence"]
        return body

    @app.get("/api/investigations/{investigation_id}/assessments")
    def list_investigation_assessments(investigation_id: str, request: Request):
        case, ledger = require_case(request, investigation_id)
        if ledger is None:
            return case
        try:
            rows = ledger.list_assessments(case["owner_id"], investigation_id)
        except (LedgerError, sqlite3.Error):
            return _unavailable()
        if rows is None:
            return _missing()
        # History may include failed attempts; they are never shaped as completed outcomes.
        return {"assessments": rows}

    @app.get("/api/investigations/{investigation_id}/assessments/latest")
    def latest_investigation_assessment(investigation_id: str, request: Request):
        case, ledger = require_case(request, investigation_id)
        if ledger is None:
            return case
        try:
            saved = ledger.get_latest_completed_assessment(case["owner_id"], investigation_id)
        except (LedgerError, sqlite3.Error):
            return _unavailable()
        if saved is None:
            return _missing()
        return _public_assessment_response(saved)

    @app.get("/api/investigations/{investigation_id}/assessments/{snapshot_id}")
    def assessment_by_snapshot(investigation_id: str, snapshot_id: str, request: Request):
        case, ledger = require_case(request, investigation_id)
        if ledger is None:
            return case
        if not _is_token(snapshot_id):
            return _missing()
        try:
            saved = ledger.get_assessment_by_snapshot(
                case["owner_id"], investigation_id, snapshot_id.strip().lower()
            )
        except (LedgerError, sqlite3.Error):
            return _unavailable()
        if saved is None:
            return _missing()
        if saved.get("status") == "completed":
            return _public_assessment_response(saved)
        # Failed attempt for this snapshot — not a completed outcome.
        return {
            "assessmentResultId": saved.get("assessmentResultId"),
            "snapshotId": saved.get("snapshotId"),
            "status": "failed",
            "failureCode": saved.get("failureCode"),
            "failureMessage": saved.get("failureMessage"),
            "assessedAt": saved.get("assessedAt"),
        }

    @app.get("/api/investigations/{investigation_id}/graph")
    def investigation_graph(investigation_id: str, request: Request):
        """Owner-scoped read-only graph. Never materializes or calls providers."""
        case, ledger = require_case(request, investigation_id)
        if ledger is None:
            return case
        include = str(request.query_params.get("include") or "").strip().lower()
        include_replaced = include == "replaced"
        try:
            graph = ledger.get_investigation_graph(
                case["owner_id"],
                investigation_id,
                include_replaced=include_replaced,
            )
        except (LedgerError, sqlite3.Error):
            return _unavailable()
        if graph is None:
            return _missing()
        return graph

    @app.post("/api/investigations/{investigation_id}/image-metadata/gps")
    def reveal_gps(investigation_id: str, body: GpsRevealRequest, request: Request):
        case, ledger = require_case(request, investigation_id)
        if ledger is None:
            return _nostore(case)
        blocked = enforce_limit("gps_reveal", case["owner_id"])
        if blocked is not None:
            return _nostore(blocked)
        snapshot_id = body.snapshotId.strip().lower()
        if not _is_token(snapshot_id):
            return _nostore(_missing())
        try:
            revealed = ledger.reveal_gps(case["owner_id"], investigation_id, snapshot_id)
        except (LedgerError, sqlite3.Error):
            return _nostore(_unavailable())
        if revealed is None:
            return _nostore(_missing())
        return _nostore(revealed)

    @app.post("/api/investigations/{investigation_id}/asset")
    async def upload_asset(investigation_id: str, request: Request):
        case, ledger = require_case(request, investigation_id)
        if ledger is None:
            return case
        blocked = enforce_limit("asset", case["owner_id"])
        if blocked is not None:
            return blocked
        store = app.state.assets
        if store is None:
            return _unavailable()
        data = await request.body()
        media_type = detect_image(data)
        if media_type is None:
            return JSONResponse(
                status_code=400,
                content={"code": "invalid_image", "message": "The file is not a supported image."},
            )
        if request.headers.get("x-image-consent", "").strip() != IMAGE_CONSENT_VERSION:
            return JSONResponse(
                status_code=400,
                content={
                    "code": "consent_required",
                    "message": "Confirm the image disclosure before uploading the file.",
                },
            )
        metadata_consent = classify_metadata_consent(request.headers.get("x-image-metadata-consent"))
        if metadata_consent is None:
            return JSONResponse(
                status_code=400,
                content={
                    "code": "metadata_consent_invalid",
                    "message": "The metadata consent value is not valid.",
                },
            )
        metadata_version, metadata_decision = metadata_consent
        digest = hashlib.sha256(data).hexdigest()
        supplied = request.headers.get("x-client-sha256", "")
        status = client_hash_status(supplied, digest)
        asset_id = token_hex(16)
        try:
            storage_name = store.write(
                asset_id,
                data,
                owner_id=case["owner_id"],
                investigation_id=investigation_id,
            )
        except AssetStoreError:
            return _unavailable()
        try:
            outcome, previous = ledger.save_image_asset(
                case["owner_id"],
                investigation_id,
                asset_id,
                digest,
                len(data),
                media_type,
                status,
                storage_name,
                IMAGE_CONSENT_VERSION,
                metadata_version,
                metadata_decision,
            )
        except (LedgerError, sqlite3.Error):
            _retain_failed_file(store, ledger, case["owner_id"], investigation_id, storage_name, digest, len(data), "uncommitted")
            return _unavailable()
        if outcome != "saved":
            _retain_failed_file(store, ledger, case["owner_id"], investigation_id, storage_name, digest, len(data), outcome)
            if outcome == "sealed":
                return JSONResponse(
                    status_code=409,
                    content={
                        "code": "asset_after_seal",
                        "message": "An image cannot be added after the assessment snapshot is sealed.",
                    },
                )
            if outcome == "deleting":
                return JSONResponse(
                    status_code=409,
                    content={
                        "code": "deletion_in_progress",
                        "message": "An image cannot be saved while deletion is in progress.",
                    },
                )
            return _missing()
        record = ledger.image_asset(case["owner_id"], investigation_id)
        if record is None:
            return _unavailable()
        try:
            store.finish_intent(storage_name)
        except AssetStoreError:
            return _unavailable()
        body = _public_asset(record)
        if previous and previous != storage_name:
            if store.remove(previous):
                try:
                    ledger.finish_asset_cleanup(previous)
                except (LedgerError, sqlite3.Error):
                    body["cleanupRecorded"] = True
            else:
                body["previousFileRemoved"] = False
        _best_effort_graph(
            ledger,
            case["owner_id"],
            investigation_id,
            "investigation_skeleton",
            investigation_id,
        )
        return body

    @app.delete("/api/investigations/{investigation_id}")
    def delete_investigation(investigation_id: str, request: Request):
        case, ledger = require_case(request, investigation_id)
        if ledger is None:
            return case
        try:
            ready = ledger.prepare_investigation_deletion(case["owner_id"], investigation_id)
        except (LedgerError, sqlite3.Error):
            return _unavailable()
        if not ready:
            return _missing()
        try:
            asset = ledger.image_asset(case["owner_id"], investigation_id)
        except (LedgerError, sqlite3.Error):
            return _unavailable()
        removed, failed, missing = _remove_investigation_files(app, ledger, case["owner_id"], investigation_id, asset)
        files_may_be_removed = removed or missing
        if failed:
            return _asset_cleanup_failed(False, investigation=True, files_may_be_removed=files_may_be_removed)
        try:
            deleted = ledger.delete_investigation(case["owner_id"], investigation_id)
        except (LedgerError, sqlite3.Error):
            return _asset_cleanup_failed(False, investigation=True, files_may_be_removed=files_may_be_removed)
        if not deleted:
            return _missing()
        return {"deleted": True}

    @app.post("/api/investigations/{investigation_id}/video")
    async def upload_video(investigation_id: str, request: Request):
        if not settings.video_ingest_enabled:
            return _video_ingest_disabled()
        ready, tier_code = tier_a_ready(settings.ffprobe_path)
        if not ready:
            return _video_error(503, tier_code, "Video analysis is unavailable on this server.")
        if request.scope.get("rc_video_too_large"):
            return _video_error(413, "request_too_large", "The request is too large.")
        case, ledger = require_case(request, investigation_id)
        if ledger is None:
            return case
        blocked = enforce_limit("video_asset", case["owner_id"])
        if blocked is not None:
            return blocked
        store = app.state.videos
        if store is None:
            return _unavailable()
        if request.headers.get("x-video-consent", "").strip() != VIDEO_CONSENT_VERSION:
            return _video_error(400, "consent_required", "Confirm the video disclosure before uploading the file.")
        metadata_consent = classify_video_metadata_consent(request.headers.get("x-video-metadata-consent"))
        if metadata_consent is None:
            return _video_error(400, "metadata_consent_invalid", "The metadata consent value is not valid.")
        metadata_version, metadata_decision = metadata_consent

        try:
            lock_handle = store.try_acquire_upload_lock(case["owner_id"])
        except VideoStoreError:
            return _unavailable()
        if lock_handle is None:
            return _video_error(409, "video_upload_in_progress", "A video upload is already in progress for this account.")
        partial = None
        storage_name = None
        digest = None
        byte_length = 0
        try:
            upload_id = token_hex(16)
            try:
                partial = store.open_partial(upload_id)
            except VideoStoreError:
                return _unavailable()
            hasher = hashlib.sha256()
            prefix = bytearray()
            PREFIX_NEED = 64 * 1024
            try:
                async for chunk in request.stream():
                    if not chunk:
                        continue
                    if byte_length > MAX_VIDEO_BYTES - len(chunk):
                        raise VideoProbeError("request_too_large")
                    store.append_partial(partial, chunk)
                    hasher.update(chunk)
                    byte_length += len(chunk)
                    if len(prefix) < PREFIX_NEED:
                        remain = PREFIX_NEED - len(prefix)
                        prefix.extend(chunk[:remain])
            except VideoStoreError:
                if partial is not None:
                    store.unlink_partial(partial)
                return _unavailable()
            except VideoProbeError as exc:
                if partial is not None:
                    store.unlink_partial(partial)
                if exc.code == "request_too_large":
                    return _video_error(413, "request_too_large", "The request is too large.")
                return _video_error(400, exc.code, exc.message)

            if request.scope.get("rc_video_too_large"):
                store.unlink_partial(partial)
                return _video_error(413, "request_too_large", "The request is too large.")

            if byte_length <= 0:
                store.unlink_partial(partial)
                return _video_error(400, "invalid_video", "The file is not a supported video.")
            media_type = detect_video_container(bytes(prefix))
            if media_type is None:
                store.unlink_partial(partial)
                return _video_error(400, "invalid_video", "The file is not a supported video.")
            try:
                store.fsync_partial(partial)
            except VideoStoreError:
                store.unlink_partial(partial)
                return _unavailable()

            try:
                probe = probe_video_file(
                    partial,
                    scratch_parent=store.scratch_dir(),
                    ffprobe_path=settings.ffprobe_path,
                )
            except VideoProbeError as exc:
                store.unlink_partial(partial)
                status = 503 if exc.code in {
                    "video_isolation_insufficient",
                    "video_toolchain_unavailable",
                    "video_probe_timeout",
                } else 422
                if exc.code in {"invalid_video", "encrypted_media", "no_video_stream", "codec_not_allowed",
                                "hevc_not_allowed", "av1_not_allowed", "duration_out_of_range",
                                "dimensions_out_of_range", "pixels_out_of_range", "frame_rate_out_of_range",
                                "bitrate_out_of_range", "audio_streams_exceeded", "container_not_allowed",
                                "mov_without_ftyp"}:
                    status = 400
                return _video_error(status, exc.code, exc.message)

            digest = hasher.hexdigest()
            supplied = request.headers.get("x-client-sha256", "")
            hash_status = client_hash_status(supplied, digest)
            asset_id = token_hex(16)
            try:
                storage_name = store.promote_partial(
                    partial,
                    asset_id,
                    owner_id=case["owner_id"],
                    investigation_id=investigation_id,
                    digest=digest,
                    byte_length=byte_length,
                )
            except VideoStoreError:
                store.unlink_partial(partial)
                return _unavailable()
            partial = None
            import json as _json
            try:
                outcome, previous = ledger.save_video_asset(
                    case["owner_id"],
                    investigation_id,
                    asset_id,
                    digest,
                    byte_length,
                    media_type,
                    hash_status,
                    storage_name,
                    VIDEO_CONSENT_VERSION,
                    metadata_version,
                    metadata_decision,
                    attachment_status="ready",
                    duration_ms=probe["duration_ms"],
                    width=probe["width"],
                    height=probe["height"],
                    video_codec=probe["video_codec"],
                    audio_codec=probe["audio_codec"],
                    format_name=probe["format_name"],
                    frame_rate=probe["frame_rate"],
                    bit_rate=probe["bit_rate"],
                    probe_summary_json=_json.dumps(probe["probe_summary"]),
                )
            except (LedgerError, sqlite3.Error):
                try:
                    ledger.record_video_cleanup(
                        case["owner_id"], investigation_id, storage_name, digest, byte_length, "uncommitted"
                    )
                except Exception:
                    pass
                store.remove(storage_name)
                return _unavailable()
            if outcome != "saved":
                try:
                    ledger.record_video_cleanup(
                        case["owner_id"], investigation_id, storage_name, digest, byte_length, outcome
                    )
                except Exception:
                    pass
                store.remove(storage_name)
                if outcome == "sealed":
                    return _video_error(409, "video_after_seal", "A video cannot be added after the assessment snapshot is sealed.")
                if outcome == "deleting":
                    return _video_error(409, "deletion_in_progress", "A video cannot be saved while deletion is in progress.")
                return _missing()
            try:
                store.finish_intent(storage_name)
            except VideoStoreError:
                return _unavailable()
            if previous and previous != storage_name:
                if store.remove(previous):
                    try:
                        ledger.finish_video_cleanup(previous)
                    except Exception:
                        pass
            record = ledger.video_asset(case["owner_id"], investigation_id)
            if record is None:
                return _unavailable()
            return _public_video(record)
        finally:
            store.release_upload_lock(lock_handle)

    @app.get("/api/investigations/{investigation_id}/video")
    def get_video(investigation_id: str, request: Request):
        if not settings.video_ingest_enabled:
            return _video_ingest_disabled()
        case, ledger = require_case(request, investigation_id)
        if ledger is None:
            return case
        try:
            record = ledger.video_asset(case["owner_id"], investigation_id)
        except (LedgerError, sqlite3.Error):
            return _unavailable()
        if record is None:
            return _video_error(404, "video_not_found", "That video was not found.")
        return _public_video(record)

    @app.delete("/api/investigations/{investigation_id}/video")
    def delete_video(investigation_id: str, request: Request):
        """Remove the video attachment.

        Order: durable cleanup row → unlink bytes → delete asset row → finish
        cleanup. Never reports success while bytes remain. When unlink fails,
        the asset row is kept so DELETE can be retried; the cleanup row also
        remains for startup reconcile recovery without requiring the asset row.
        """
        if not settings.video_ingest_enabled:
            return _video_ingest_disabled()
        case, ledger = require_case(request, investigation_id)
        if ledger is None:
            return case
        if request.headers.get("x-video-remove-confirm", "").strip() != VIDEO_REMOVE_CONFIRM:
            return _video_error(
                400,
                "removal_confirmation_required",
                "Confirm that this investigation may continue without the attached video.",
            )
        store = app.state.videos
        if store is None:
            return _unavailable()
        try:
            prior = ledger.prepare_video_removal(case["owner_id"], investigation_id)
        except (LedgerError, sqlite3.Error):
            return _unavailable()
        if prior is not None and prior.get("__sealed__"):
            return _video_error(409, "video_after_seal", "A sealed video cannot be removed.")
        if prior is None:
            # Retry path: asset row already gone but cleanup still pending.
            try:
                pending = ledger.pending_video_cleanup_for_investigation(
                    case["owner_id"], investigation_id
                )
            except (LedgerError, sqlite3.Error):
                return _unavailable()
            if pending is None:
                return _video_error(404, "video_not_found", "That video was not found.")
            storage_name = pending["storage_name"]
            report = store.remove_report(storage_name)
            if report == "failed":
                return JSONResponse(
                    status_code=500,
                    content={
                        "ok": False,
                        "code": "video_cleanup_failed",
                        "message": "The video attachment could not be removed. The deletion can be retried safely.",
                        "assetBytesDeleted": False,
                    },
                )
            try:
                ledger.finish_video_cleanup(storage_name)
            except (LedgerError, sqlite3.Error):
                return _unavailable()
            return {"ok": True, "removed": True}

        storage_name = prior.get("storageName")
        digest = prior.get("sha256") or ""
        byte_length = int(prior.get("byteLength") or 0)
        try:
            ledger.record_video_cleanup(
                case["owner_id"], investigation_id, storage_name, digest, byte_length, "user_removed"
            )
        except (LedgerError, sqlite3.Error):
            return _unavailable()
        report = store.remove_report(storage_name)
        if report == "failed":
            # Asset row intentionally retained for retry; cleanup row is durable.
            return JSONResponse(
                status_code=500,
                content={
                    "ok": False,
                    "code": "video_cleanup_failed",
                    "message": "The video attachment could not be removed. The deletion can be retried safely.",
                    "assetBytesDeleted": False,
                },
            )
        try:
            removed = ledger.delete_video_asset_row(case["owner_id"], investigation_id)
        except (LedgerError, sqlite3.Error):
            return _unavailable()
        if removed is not None and removed.get("__sealed__"):
            return _video_error(409, "video_after_seal", "A sealed video cannot be removed.")
        try:
            ledger.finish_video_cleanup(storage_name)
        except (LedgerError, sqlite3.Error):
            return _unavailable()
        return {"ok": True, "removed": True}

    if FRONTEND_DIR.is_dir():
        app.mount("/", FrontendFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")

    app.add_middleware(RequestSizeLimit, max_bytes=MAX_BODY_BYTES)
    app.add_middleware(SecurityHeaders, production=settings.production)
    return app


class DeferredApplication:
    """ASGI entry point that builds the server application on first use.

    Importing this module, including ``from app.main import app``, does not
    open a ledger. Uvicorn starts the server by calling this object, and that
    call uses the normal production startup checks.
    """

    def __init__(self) -> None:
        self._application = None
        self._lock = threading.Lock()

    def _load(self):
        if self._application is None:
            with self._lock:
                if self._application is None:
                    self._application = create_app()
        return self._application

    async def __call__(self, scope, receive, send):
        application = self._load()
        await application(scope, receive, send)


app = DeferredApplication()
