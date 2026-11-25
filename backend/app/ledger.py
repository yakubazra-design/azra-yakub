"""SQLite evidence ledger.

Accounts and sessions live beside the evidence rows. Password hashes and
session token hashes are credentials; a stored source still does not prove
the source is authentic. Existing investigation rows are kept when account
columns are added.
"""

import hashlib
import json
import logging
import os
import sqlite3
import stat
import sys
import time
from collections.abc import Mapping
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from secrets import token_hex

logger = logging.getLogger(__name__)

from app.auth import verify_password
from app.evidence_graph import (
    GRAPH_NOTE,
    GraphBuilder,
    canonical_assessment,
    canonical_claim,
    canonical_finding,
    canonical_image,
    canonical_investigation,
    canonical_live_source,
    canonical_observation,
    canonical_page,
    canonical_provenance,
    canonical_publication,
    canonical_site,
    canonical_snap_source,
    canonical_snapshot,
    canonical_url,
    delete_graph_for_investigation,
    delete_graph_for_owner,
    finding_support_certainty,
    props_claim,
    props_source,
    published_at_certainty,
    website_key,
)
from app.metadata_extract import (
    METADATA_CONSENT_VERSION,
    extract_embedded_metadata,
    precise_gps_points,
    seal_metadata,
)
from app.provenance import reject_client_provenance, validate_provenance_record
from app.urls import stored_source_url

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schema.sql"
_ASSET_COLUMNS = """
    id, investigation_id, owner_id, sha256, byte_length, media_type,
    received_at, retention, client_hash_status, storage_name,
    consent_version, metadata_consent_version, metadata_consent_decision,
    metadata_consent_at
"""
PROJECT_ROOT = Path(__file__).resolve().parents[2]
BUSY_TIMEOUT_MS = 5000


class LedgerError(Exception):
    """The ledger file could not be opened or updated.

    ``failure_code`` is set when a commit-time trust check refuses a
    credential record. The message stays generic. The code is not a
    credential status and it is not an assessment outcome.
    """

    def __init__(self, message="The evidence ledger is unavailable.", failure_code=None):
        super().__init__(message)
        self.failure_code = failure_code


class DeletionInProgress(LedgerError):
    """Deletion has started, so a new snapshot must not reference its image."""


class TestLedgerRejected(RuntimeError):
    """A test tried to open the development ledger or a file inside data/."""


_test_mode = False


def enable_test_mode() -> None:
    """Turn on ledger protection for this process.

    The test package calls this when it is loaded. It is not an environment
    variable. The development server does not call it, so a normal startup
    still opens the configured ledger.
    """
    global _test_mode
    _test_mode = True


def test_mode_enabled() -> bool:
    return _test_mode


def invoked_by_test() -> bool:
    """True when a frame belongs to the automated test tree.

    This is a second check. Test mode itself is enabled explicitly by the
    test package or by ``create_app(..., testing=True)``.
    """
    frame = sys._getframe()
    while frame is not None:
        filename = frame.f_code.co_filename.replace("\\", "/")
        if "/backend/tests/" in filename:
            return True
        frame = frame.f_back
    return False


def protecting_tests() -> bool:
    """True when this process must not fall back to the development ledger."""
    return _test_mode or invoked_by_test()


def _absolute(path: Path) -> Path:
    if path.is_absolute():
        return path
    return Path.cwd() / path


def _identities(path: Path) -> set[Path]:
    """Absolute path and symlink-resolved path, without opening a database."""
    absolute = _absolute(Path(path))
    found = {absolute.absolute()}
    try:
        found.add(absolute.resolve(strict=False).absolute())
    except (OSError, RuntimeError):
        pass
    try:
        found.add(Path(os.path.realpath(absolute)).absolute())
    except OSError:
        pass
    return found


def matches_live_ledger(path: Path) -> bool:
    """True when path is the development ledger, including through a symlink."""
    live = PROJECT_ROOT / "data" / "ledger.sqlite"
    return bool(_identities(path) & _identities(live))


def inside_project_data(path: Path) -> bool:
    """True when path is the data directory or a file inside it."""
    data = PROJECT_ROOT / "data"
    roots = _identities(data)
    for candidate in _identities(path):
        for root in roots:
            if candidate == root or root in candidate.parents:
                return True
    return False


def refuse_test_ledger(path: Path) -> None:
    """Reject the live ledger and any other file under data/.

    This does not create, open, migrate, or delete a database.
    """
    if matches_live_ledger(path):
        raise TestLedgerRejected(
            "Tests cannot open the live ledger at data/ledger.sqlite. "
            "Pass an isolated database outside the data directory."
        )
    if inside_project_data(path):
        raise TestLedgerRejected(
            "Test databases must be created outside the data directory."
        )


def production_ledger_path(raw: str, frontend_dir: Path) -> Path | None:
    """Return an absolute ledger path production may open, or None.

    The path must be set, absolute, and a regular file location outside the
    public frontend directory. A symlink is rejected. This does not create or
    replace the file.
    """
    text = str(raw or "").strip()
    if not text:
        return None
    path = Path(text)
    if not path.is_absolute():
        return None
    try:
        if path.is_symlink() or path.parent.is_symlink():
            return None
        resolved = path.resolve()
        frontend = frontend_dir.resolve()
    except OSError:
        return None
    if resolved == frontend or frontend in resolved.parents:
        return None
    if resolved.exists() and not resolved.is_file():
        return None
    parent = resolved.parent
    if parent.exists() and not parent.is_dir():
        return None
    return resolved


def _chmod_private(path: Path, mode: int) -> None:
    if path.is_symlink():
        raise LedgerError("The evidence ledger is unavailable.")
    try:
        os.chmod(path, mode)
    except OSError as exc:
        raise LedgerError("The evidence ledger is unavailable.") from exc


def _protect_directory(directory: Path) -> None:
    if directory.is_symlink():
        raise LedgerError("The evidence ledger is unavailable.")
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise LedgerError("The evidence ledger is unavailable.") from exc
    _chmod_private(directory, 0o700)


def _protect_files(path: Path) -> None:
    """Restrict the database and any WAL or SHM file already beside it."""
    for candidate in (path, Path(str(path) + "-wal"), Path(str(path) + "-shm")):
        if candidate.is_symlink():
            raise LedgerError("The evidence ledger is unavailable.")
        if candidate.exists():
            _chmod_private(candidate, 0o600)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class Ledger:
    def __init__(self, path: Path):
        self.path = path
        if protecting_tests():
            refuse_test_ledger(Path(path))
        try:
            if path.is_symlink():
                raise LedgerError("The evidence ledger is unavailable.")
            _protect_directory(path.parent)
            from app.backup import BackupError, recover_restore
            try:
                recover_restore(path)
            except BackupError as exc:
                raise LedgerError("The evidence ledger is unavailable.") from exc
            conn = self._connect()
            try:
                conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
                _migrate(conn)
                referenced = _referenced_storage_names(conn)
            finally:
                conn.close()
            _protect_files(path)
            from app.assetstore import reconcile_assets
            reconcile_assets(path.parent / "assets", referenced)
            try:
                self._reconcile_video_assets()
            except (OSError, sqlite3.Error, LedgerError):
                # Video reconcile must not prevent ledger open for image-only use.
                pass
        except LedgerError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise LedgerError("The evidence ledger is unavailable.") from exc

    def _reconcile_video_assets(self) -> None:
        """Apply V1.2.2E video reconcile without auto-deleting attachment rows."""
        from app.video_store import VideoStore, purge_video_quarantine, reconcile_video_assets

        conn = self._connect()
        try:
            referenced = _referenced_video_storage_names(conn)
            verify_rows = _video_verify_rows(conn)

            def _mark_missing(storage_name: str) -> None:
                conn.execute(
                    """
                    UPDATE video_assets
                    SET attachment_status = 'missing', failure_code = 'video_bytes_missing'
                    WHERE storage_name = ? AND attachment_status = 'ready'
                    """,
                    (storage_name,),
                )

            def _mark_integrity(storage_name: str) -> None:
                conn.execute(
                    """
                    UPDATE video_assets
                    SET attachment_status = 'integrity_failed', failure_code = 'integrity_mismatch'
                    WHERE storage_name = ?
                      AND attachment_status IN ('ready', 'missing')
                    """,
                    (storage_name,),
                )

            video_root = self.path.parent / "assets" / "video"
            reconcile_video_assets(
                video_root,
                referenced,
                mark_missing=_mark_missing,
                mark_integrity_failed=_mark_integrity,
                verify_rows=verify_rows,
            )
            # Retry durable cleanups left from prior failed unlinks.
            try:
                cleanup_rows = conn.execute(
                    "SELECT storage_name FROM video_asset_cleanup"
                ).fetchall()
            except sqlite3.Error:
                cleanup_rows = []
            if cleanup_rows:
                store = VideoStore(video_root)
                for row in cleanup_rows:
                    name = row["storage_name"]
                    report = store.remove_report(name)
                    if report in {"removed", "missing"}:
                        conn.execute(
                            "DELETE FROM video_asset_cleanup WHERE storage_name = ?",
                            (name,),
                        )
            purge_video_quarantine(video_root)
        finally:
            conn.close()

    def _connect(self) -> sqlite3.Connection:
        if self.path.is_symlink() or self.path.parent.is_symlink():
            raise LedgerError("The evidence ledger is unavailable.")
        conn = sqlite3.connect(self.path, timeout=BUSY_TIMEOUT_MS / 1000, isolation_level=None)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
            mode = conn.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if str(mode).lower() != "wal":
                raise sqlite3.OperationalError("The evidence ledger is unavailable.")
            _protect_directory(self.path.parent)
            _protect_files(self.path)
        except Exception:
            conn.close()
            raise
        return conn

    @contextmanager
    def _transaction(self):
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def hit_rate_limit(self, bucket: str, subject: str, limit: int, window_seconds: int, now: int | None = None) -> tuple[bool, int]:
        """Count one request. Return whether it is allowed and the retry delay.

        The insert and the conditional update run in one immediate transaction,
        so two overlapping requests cannot both pass a full window.
        """
        current = int(time.time()) if now is None else int(now)
        window_start = current - (current % window_seconds)
        retry_after = max(window_start + window_seconds - current, 1)
        with self._transaction() as conn:
            conn.execute("DELETE FROM rate_limits WHERE window_start < ?", (current - 2 * 60 * 60,))
            row = conn.execute(
                """
                SELECT count FROM rate_limits
                WHERE bucket = ? AND subject = ? AND window_start = ?
                """,
                (bucket, subject, window_start),
            ).fetchone()
            if row is None:
                conn.execute(
                    """
                    INSERT INTO rate_limits (bucket, subject, window_start, count)
                    VALUES (?, ?, ?, 1)
                    """,
                    (bucket, subject, window_start),
                )
                return True, 0
            if int(row["count"]) >= limit:
                return False, retry_after
            updated = conn.execute(
                """
                UPDATE rate_limits
                SET count = count + 1
                WHERE bucket = ? AND subject = ? AND window_start = ? AND count < ?
                """,
                (bucket, subject, window_start, limit),
            )
            if updated.rowcount != 1:
                return False, retry_after
        return True, 0

    def create_account(self, email: str, password_hash: str) -> str | None:
        user_id = token_hex(16)
        try:
            with self._transaction() as conn:
                conn.execute(
                    """
                    INSERT INTO users (id, created_at, email, password_hash)
                    VALUES (?, ?, ?, ?)
                    """,
                    (user_id, _now(), email, password_hash),
                )
        except sqlite3.IntegrityError:
            return None
        return user_id

    def get_account_by_email(self, email: str) -> dict | None:
        conn = self._connect()
        try:
            row = conn.execute(
                """
                SELECT id, email, password_hash
                FROM users
                WHERE email = ?
                """,
                (email,),
            ).fetchone()
        finally:
            conn.close()
        if row is None or not row["password_hash"]:
            return None
        return {"id": row["id"], "email": row["email"], "password_hash": row["password_hash"]}

    def create_session(self, user_id: str, token_hash: str, csrf_token: str, expires_at: str) -> None:
        with self._transaction() as conn:
            conn.execute(
                """
                INSERT INTO sessions (
                    id, user_id, token_hash, csrf_token, created_at, expires_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, NULL)
                """,
                (token_hex(16), user_id, token_hash, csrf_token, _now(), expires_at),
            )

    def get_session(self, token_hash: str) -> dict | None:
        conn = self._connect()
        try:
            row = conn.execute(
                """
                SELECT sessions.user_id, sessions.csrf_token, sessions.expires_at,
                       sessions.revoked_at, users.email
                FROM sessions
                JOIN users ON users.id = sessions.user_id
                WHERE sessions.token_hash = ?
                """,
                (token_hash,),
            ).fetchone()
        finally:
            conn.close()
        if row is None or row["revoked_at"] or not row["email"]:
            return None
        try:
            expires = datetime.fromisoformat(row["expires_at"])
        except ValueError:
            return None
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) >= expires:
            return None
        return {
            "user_id": row["user_id"],
            "email": row["email"],
            "csrf_token": row["csrf_token"],
        }

    def revoke_session(self, token_hash: str) -> None:
        with self._transaction() as conn:
            conn.execute(
                """
                UPDATE sessions
                SET revoked_at = ?
                WHERE token_hash = ? AND revoked_at IS NULL
                """,
                (_now(), token_hash),
            )

    def create_owner(self) -> str:
        owner_id = token_hex(16)
        with self._transaction() as conn:
            conn.execute(
                "INSERT INTO users (id, created_at) VALUES (?, ?)",
                (owner_id, _now()),
            )
        return owner_id

    def owner_exists(self, owner_id: str) -> bool:
        conn = self._connect()
        try:
            row = conn.execute("SELECT 1 FROM users WHERE id = ?", (owner_id,)).fetchone()
        finally:
            conn.close()
        return row is not None

    def create_investigation(self, owner_id: str, kind: str, input_text: str) -> str | None:
        if not self.owner_exists(owner_id):
            return None
        investigation_id = token_hex(16)
        with self._transaction() as conn:
            conn.execute(
                """
                INSERT INTO investigations (id, owner_id, kind, input_text, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (investigation_id, owner_id, kind, input_text, _now()),
            )
        return investigation_id

    def get_investigation(self, owner_id: str, investigation_id: str) -> dict | None:
        conn = self._connect()
        try:
            row = conn.execute(
                """
                SELECT id, owner_id, kind, input_text, created_at
                FROM investigations
                WHERE id = ? AND owner_id = ?
                """,
                (investigation_id, owner_id),
            ).fetchone()
        finally:
            conn.close()
        return dict(row) if row else None

    def save_page(self, owner_id: str, investigation_id: str, page: dict) -> str | None:
        if self.get_investigation(owner_id, investigation_id) is None:
            return None
        page_id = token_hex(16)
        with self._transaction() as conn:
            conn.execute("DELETE FROM page_fetches WHERE investigation_id = ?", (investigation_id,))
            conn.execute(
                """
                INSERT INTO page_fetches (
                    id, investigation_id, requested_url, final_url, title, body_text,
                    published_at, date_certainty, date_type, provider, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    page_id,
                    investigation_id,
                    page.get("requested_url") or "",
                    page.get("final_url") or "",
                    page.get("title"),
                    page.get("body_text") or "",
                    page.get("published_at"),
                    page.get("date_certainty"),
                    page.get("date_type"),
                    page.get("provider"),
                    _now(),
                ),
            )
        return page_id

    def get_page(self, owner_id: str, investigation_id: str) -> dict | None:
        if self.get_investigation(owner_id, investigation_id) is None:
            return None
        conn = self._connect()
        try:
            row = conn.execute(
                """
                SELECT id, investigation_id, requested_url, final_url, title, body_text,
                       published_at, date_certainty, date_type, provider
                FROM page_fetches
                WHERE investigation_id = ?
                """,
                (investigation_id,),
            ).fetchone()
        finally:
            conn.close()
        return dict(row) if row else None

    def save_claims(self, owner_id: str, investigation_id: str, primary_claim: str, points: list) -> bool:
        if self.get_investigation(owner_id, investigation_id) is None:
            return False
        with self._transaction() as conn:
            conn.execute("DELETE FROM claim_analyses WHERE investigation_id = ?", (investigation_id,))
            conn.execute(
                """
                INSERT INTO claim_analyses (investigation_id, primary_claim, verifiable_points, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (investigation_id, primary_claim, json.dumps(points), _now()),
            )
        return True

    def get_claims(self, owner_id: str, investigation_id: str) -> dict | None:
        if self.get_investigation(owner_id, investigation_id) is None:
            return None
        conn = self._connect()
        try:
            row = conn.execute(
                """
                SELECT primary_claim, verifiable_points
                FROM claim_analyses
                WHERE investigation_id = ?
                """,
                (investigation_id,),
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        try:
            points = json.loads(row["verifiable_points"])
        except ValueError:
            points = []
        if not isinstance(points, list):
            points = []
        return {"primaryClaim": row["primary_claim"], "verifiablePoints": points}

    def replace_sources(self, owner_id: str, investigation_id: str, sources: list[dict]) -> list[dict] | None:
        if self.get_investigation(owner_id, investigation_id) is None:
            return None
        stored = []
        with self._transaction() as conn:
            conn.execute("DELETE FROM evidence_sources WHERE investigation_id = ?", (investigation_id,))
            for position, source in enumerate(sources):
                source_id = token_hex(16)
                source = dict(source)
                source["url"] = stored_source_url(source.get("url")) or ""
                quality = source.get("quality") or {}
                conn.execute(
                    """
                    INSERT INTO evidence_sources (
                        id, investigation_id, position, url, title, snippet, published_at,
                        date_certainty, date_type, provider, quality_tier, quality_reason, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        source_id,
                        investigation_id,
                        position,
                        source.get("url") or "",
                        source.get("title"),
                        source.get("snippet") or "",
                        source.get("publishedAt"),
                        source.get("dateCertainty"),
                        source.get("dateType"),
                        source.get("provider"),
                        quality.get("tier") or "UNKNOWN",
                        quality.get("reason") or "",
                        _now(),
                    ),
                )
                stored.append(_source_dict(source_id, position, source))
        return stored

    def _prepare_seal_metadata(self, owner_id: str, investigation_id: str):
        """Read and parse outside the seal write transaction.

        ``None`` means there is no asset to describe. A pending deletion or
        a retiring row is also ``None`` here; the seal transaction rejects
        those states. A hash mismatch raises before any metadata is kept.
        """
        conn = self._connect()
        try:
            owned = conn.execute(
                "SELECT id FROM investigations WHERE id = ? AND owner_id = ?",
                (investigation_id, owner_id),
            ).fetchone()
            if owned is None or _deletion_pending(conn, owner_id, investigation_id):
                return None
            row = conn.execute(
                f"""
                SELECT {_ASSET_COLUMNS}
                FROM image_assets
                WHERE investigation_id = ? AND owner_id = ?
                """,
                (investigation_id, owner_id),
            ).fetchone()
        finally:
            conn.close()
        if row is None or row["retention"] == "retiring":
            return None
        current = {key: row[key] for key in row.keys()}
        accepted = (
            current["metadata_consent_version"] == METADATA_CONSENT_VERSION
            and current["metadata_consent_decision"] == "accepted"
        )
        verified = None
        if accepted:
            verified = _read_matching_asset(
                self.path.parent / "assets" / current["storage_name"],
                current["sha256"],
                int(current["byte_length"]),
            )
            try:
                parsed = extract_embedded_metadata(verified, current["media_type"])
            except Exception:
                parsed = {"status": "extraction_failed", "fields": {}}
        else:
            parsed = {"status": "not_performed", "fields": {}}
        return current, parsed, verified

    def seal_assessment(
        self,
        owner_id: str,
        investigation_id: str,
        token_hash: str,
        snapshot: dict,
        expires_at: str,
        provenance: dict | None = None,
        authorize=None,
        *,
        video_seal_integration: bool | None = None,
    ) -> str | None:
        """Seal one snapshot.

        ``provenance`` is the server-built record. A provenance value inside
        ``snapshot`` is discarded, including one that would otherwise
        validate. The record is checked against the sealed image in this
        same transaction and is omitted when the investigation has no image
        and no record was supplied.

        When ``video_seal_integration`` is true (the Settings default), a
        ``video_assets`` row for this investigation must be ``ready`` and the
        on-disk bytes must match the recorded SHA-256 and size after a full
        recalculation; the verified identity is stored as ``sealedVideo``.
        An investigation with no video row seals normally. Client-supplied
        ``sealedVideo`` / ``videoEvidence`` keys are discarded. When the
        flag is false, video attachment state is ignored for sealing.

        ``authorize`` is not a trust-store import. A validated record with a
        policy must supply it. The callback runs once after validation and
        immediately before the snapshot INSERT, and that call is the
        authorization point for the credential record. A missing callback, a
        denial, or an exception rolls this transaction back, so no snapshot
        row remains. A technical record whose policy is null, and a snapshot
        with no provenance, do not require a callback.

        The trust witness and this SQLite transaction are not one atomic
        commit. A suspension that arrives after ``authorize`` returns and
        before SQLite commits cannot be coordinated with the witness.
        Nothing after a successful authorization runs except the INSERT
        and the commit. This transaction does not run the C2PA reader.
        """
        snapshot_id = token_hex(16)
        prepared = self._prepare_seal_metadata(owner_id, investigation_id)
        if video_seal_integration is None:
            from app.config import Settings

            video_seal_integration = bool(Settings().video_seal_integration)
        video_lock = None
        video_store = None
        try:
            with self._transaction() as conn:
                owned = conn.execute(
                    "SELECT id FROM investigations WHERE id = ? AND owner_id = ?",
                    (investigation_id, owner_id),
                ).fetchone()
                if owned is None:
                    return None
                if _deletion_pending(conn, owner_id, investigation_id):
                    raise DeletionInProgress("The evidence ledger is unavailable.")
                asset = conn.execute(
                    f"""
                    SELECT {_ASSET_COLUMNS}
                    FROM image_assets
                    WHERE investigation_id = ? AND owner_id = ?
                    """,
                    (investigation_id, owner_id),
                ).fetchone()
                body = dict(snapshot)
                client_provenance = body.pop("provenance", None)
                reject_client_provenance(client_provenance)
                for client_key in (
                    "sealedAsset",
                    "imageEvidence",
                    "currentFile",
                    "embeddedMetadata",
                    "snapshotId",
                    "sealedVideo",
                    "videoEvidence",
                ):
                    body.pop(client_key, None)
                if asset is not None and asset["retention"] == "retiring":
                    raise DeletionInProgress("The evidence ledger is unavailable.")
                if asset is not None:
                    if prepared is None or not _same_sealed_asset(prepared[0], asset):
                        raise LedgerError("The evidence ledger is unavailable.")
                    verified = prepared[2]
                    current_bytes = _read_asset_buffer(
                        self.path.parent / "assets" / asset["storage_name"],
                        int(asset["byte_length"]),
                    )
                    if not _buffer_matches(current_bytes, asset["sha256"], int(asset["byte_length"])):
                        raise LedgerError("The evidence ledger is unavailable.")
                    if verified is not None and current_bytes != verified:
                        raise LedgerError("The evidence ledger is unavailable.")
                    record = _asset_record(asset)
                    body["sealedAsset"] = {
                        "assetId": record["assetId"],
                        "ownerId": record["ownerId"],
                        "sha256": record["sha256"],
                        "byteLength": record["byteLength"],
                        "mediaType": record["mediaType"],
                        "receivedAt": record["receivedAt"],
                        "retention": record["retention"],
                        "clientHashStatus": record["clientHashStatus"],
                        "consentVersion": record["consentVersion"],
                    }
                    _previous, parsed, _verified = prepared
                    body["embeddedMetadata"] = seal_metadata(
                        parsed,
                        record["consentVersion"],
                        record["metadataConsentVersion"],
                        record["metadataConsentDecision"],
                        record["metadataConsentAt"],
                    )
                elif prepared is not None:
                    raise LedgerError("The evidence ledger is unavailable.")
                if provenance is not None:
                    sealed = body.get("sealedAsset")
                    if not isinstance(sealed, dict):
                        raise LedgerError("The evidence ledger is unavailable.")
                    checked = validate_provenance_record(provenance, {
                        "sha256": sealed.get("sha256"),
                        "byteLength": sealed.get("byteLength"),
                        "mediaType": sealed.get("mediaType"),
                    })
                    if not checked.get("ok"):
                        raise LedgerError("The evidence ledger is unavailable.")
                    body["provenance"] = checked["record"]
                if video_seal_integration:
                    video_row = conn.execute(
                        """
                        SELECT * FROM video_assets
                        WHERE investigation_id = ? AND owner_id = ?
                        """,
                        (investigation_id, owner_id),
                    ).fetchone()
                    if video_row is not None:
                        from app.video_store import VideoStore, VideoStoreError

                        if video_row["retention"] == "retiring":
                            raise DeletionInProgress("The evidence ledger is unavailable.")
                        if video_row["attachment_status"] != "ready":
                            raise LedgerError(
                                "The evidence ledger is unavailable.",
                                failure_code="video_not_ready",
                            )
                        try:
                            video_store = VideoStore.for_ledger(self.path)
                            video_lock = video_store.try_acquire_upload_lock(owner_id)
                        except VideoStoreError as exc:
                            raise LedgerError(
                                "The evidence ledger is unavailable.",
                                failure_code="video_identity_mismatch",
                            ) from exc
                        if video_lock is None:
                            raise LedgerError(
                                "The evidence ledger is unavailable.",
                                failure_code="video_seal_busy",
                            )
                        storage_name = video_row["storage_name"]
                        digest = str(video_row["sha256"]).strip().lower()
                        byte_length = int(video_row["byte_length"])
                        try:
                            path = video_store.path_for(storage_name)
                        except VideoStoreError as exc:
                            raise LedgerError(
                                "The evidence ledger is unavailable.",
                                failure_code="video_identity_mismatch",
                            ) from exc
                        if not video_store.verify_path(path, digest, byte_length):
                            raise LedgerError(
                                "The evidence ledger is unavailable.",
                                failure_code="video_identity_mismatch",
                            )
                        sealed_at = _now()
                        body["sealedVideo"] = _sealed_video_identity(
                            video_row,
                            verified_sha256=digest,
                            verified_byte_length=byte_length,
                            sealed_at=sealed_at,
                        )
                body["snapshotId"] = snapshot_id
                _authorize_commit(authorize, body.get("provenance"))
                conn.execute(
                    """
                    INSERT INTO assessment_snapshots (
                        id, investigation_id, owner_id, token_hash, snapshot_json,
                        created_at, expires_at, consumed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
                    """,
                    (
                        snapshot_id,
                        investigation_id,
                        owner_id,
                        token_hash,
                        json.dumps(body),
                        _now(),
                        expires_at,
                    ),
                )
        finally:
            if video_store is not None and video_lock is not None:
                video_store.release_upload_lock(video_lock)
        return snapshot_id

    def consume_assessment(self, owner_id: str, investigation_id: str, token_hash: str) -> tuple[dict | None, str]:
        """Mark one matching token used and return its snapshot.

        The update commits before the caller talks to the model. A second
        caller, including one racing the first, cannot consume the same row.
        """
        with self._transaction() as conn:
            row = conn.execute(
                """
                SELECT id, owner_id, investigation_id, snapshot_json, expires_at, consumed_at
                FROM assessment_snapshots
                WHERE token_hash = ?
                """,
                (token_hash,),
            ).fetchone()
            if row is None or row["owner_id"] != owner_id or row["investigation_id"] != investigation_id:
                return None, "invalid"
            if row["consumed_at"]:
                return None, "used"
            if _is_past(row["expires_at"]):
                return None, "expired"
            updated = conn.execute(
                """
                UPDATE assessment_snapshots
                SET consumed_at = ?
                WHERE token_hash = ?
                  AND owner_id = ?
                  AND investigation_id = ?
                  AND consumed_at IS NULL
                  AND expires_at > ?
                """,
                (_now(), token_hash, owner_id, investigation_id, _now()),
            )
            if updated.rowcount != 1:
                current = conn.execute(
                    "SELECT consumed_at FROM assessment_snapshots WHERE token_hash = ?",
                    (token_hash,),
                ).fetchone()
                if current is not None and current["consumed_at"]:
                    return None, "used"
                return None, "expired"
            try:
                snapshot = json.loads(row["snapshot_json"])
            except ValueError as exc:
                raise LedgerError("The evidence ledger is unavailable.") from exc
            if not isinstance(snapshot, dict):
                raise LedgerError("The evidence ledger is unavailable.")
            snapshot["snapshotId"] = row["id"]
            sealed = snapshot.get("sealedAsset")
            if isinstance(sealed, dict):
                if _deletion_pending(conn, owner_id, investigation_id):
                    raise LedgerError("The evidence ledger is unavailable.")
                asset = conn.execute(
                    """
                    SELECT storage_name, sha256, byte_length, retention
                    FROM image_assets
                    WHERE investigation_id = ? AND owner_id = ?
                    """,
                    (investigation_id, owner_id),
                ).fetchone()
                if (
                    asset is None
                    or asset["retention"] == "retiring"
                    or asset["sha256"] != sealed.get("sha256")
                    or not _asset_file_matches(
                        self.path.parent / "assets" / asset["storage_name"],
                        asset["sha256"],
                        int(asset["byte_length"]),
                    )
                ):
                    raise LedgerError("The evidence ledger is unavailable.")
        return snapshot, "ok"

    def reveal_gps(self, owner_id: str, investigation_id: str, snapshot_id: str) -> dict | None:
        """Return precise coordinates for one owned snapshot, or None.

        A missing row, a pending deletion, and a snapshot without a stored
        coordinate all look the same to the caller.
        """
        with self._transaction() as conn:
            if _deletion_pending(conn, owner_id, investigation_id):
                return None
            row = conn.execute(
                """
                SELECT snapshot_json FROM assessment_snapshots
                WHERE id = ? AND owner_id = ? AND investigation_id = ?
                """,
                (snapshot_id, owner_id, investigation_id),
            ).fetchone()
        if row is None:
            return None
        try:
            snapshot = json.loads(row["snapshot_json"])
        except ValueError:
            return None
        if not isinstance(snapshot, dict):
            return None
        points = precise_gps_points(snapshot.get("embeddedMetadata"))
        if not points:
            return None
        return {"snapshotId": snapshot_id, "gps": points}

    def list_sources(self, owner_id: str, investigation_id: str) -> list[dict] | None:
        if self.get_investigation(owner_id, investigation_id) is None:
            return None
        conn = self._connect()
        try:
            rows = conn.execute(
                """
                SELECT id, position, url, title, snippet, published_at, date_certainty,
                       date_type, provider, quality_tier, quality_reason
                FROM evidence_sources
                WHERE investigation_id = ?
                ORDER BY position
                """,
                (investigation_id,),
            ).fetchall()
        finally:
            conn.close()
        return [
            {
                "id": row["id"],
                "url": stored_source_url(row["url"]) or "",
                "title": row["title"],
                "snippet": row["snippet"],
                "publishedAt": row["published_at"],
                "dateCertainty": row["date_certainty"],
                "dateType": row["date_type"],
                "provider": row["provider"],
                "quality": {"tier": row["quality_tier"], "reason": row["quality_reason"]},
            }
            for row in rows
        ]

    def save_completed_assessment(
        self,
        owner_id: str,
        investigation_id: str,
        snapshot_id: str,
        *,
        model_assessment: str,
        facing_assessment: str,
        why: dict,
        uncertainty: list,
        original_material: dict,
        findings: list[dict],
        image_evidence: dict | None = None,
        supersession_reason: str = "reassessment",
    ) -> dict:
        """Insert one completed assessment and its findings.

        Raises ``LedgerError`` with ``failure_code='persist_failed'`` when the
        write cannot complete. On UNIQUE(snapshot_id) conflict, returns the
        existing completed row without modifying it.
        """
        if model_assessment not in OFFICIAL_ASSESSMENT_OUTCOMES:
            raise LedgerError("The evidence ledger is unavailable.")
        if facing_assessment not in OFFICIAL_ASSESSMENT_OUTCOMES:
            raise LedgerError("The evidence ledger is unavailable.")
        if supersession_reason not in ("reassessment", "correction"):
            raise LedgerError("The evidence ledger is unavailable.")
        result_id = token_hex(16)
        created_at = _now()
        try:
            with self._transaction() as conn:
                existing = conn.execute(
                    """
                    SELECT id, status FROM assessment_results
                    WHERE snapshot_id = ?
                    """,
                    (snapshot_id,),
                ).fetchone()
                if existing is not None:
                    if existing["status"] != "completed":
                        raise LedgerError("The evidence ledger is unavailable.")
                    return self._assessment_payload(conn, existing["id"], include_model=False)

                prior = conn.execute(
                    """
                    SELECT id FROM assessment_results
                    WHERE investigation_id = ? AND owner_id = ? AND status = 'completed'
                    ORDER BY created_at DESC, id DESC
                    LIMIT 1
                    """,
                    (investigation_id, owner_id),
                ).fetchone()

                conn.execute(
                    """
                    INSERT INTO assessment_results (
                        id, investigation_id, owner_id, snapshot_id, status,
                        model_assessment, facing_assessment, failure_code, failure_message,
                        why_json, uncertainty_json, original_material_json, image_evidence_json,
                        created_at
                    ) VALUES (?, ?, ?, ?, 'completed', ?, ?, NULL, NULL, ?, ?, ?, ?, ?)
                    """,
                    (
                        result_id,
                        investigation_id,
                        owner_id,
                        snapshot_id,
                        model_assessment,
                        facing_assessment,
                        json.dumps(why),
                        json.dumps(uncertainty),
                        json.dumps(original_material),
                        json.dumps(image_evidence) if image_evidence is not None else None,
                        created_at,
                    ),
                )
                for position, finding in enumerate(findings or []):
                    if not isinstance(finding, dict):
                        continue
                    indexes = finding.get("sources") if isinstance(finding.get("sources"), list) else []
                    clean_indexes = [int(i) for i in indexes if isinstance(i, int)]
                    conn.execute(
                        """
                        INSERT INTO findings (
                            id, assessment_result_id, position, finding_type, evidence_status,
                            alignment_reason, text, source_indexes_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            token_hex(16),
                            result_id,
                            position,
                            str(finding.get("type") or "caution"),
                            str(finding.get("evidenceStatus") or "not_established"),
                            finding.get("alignmentReason") if isinstance(finding.get("alignmentReason"), str) else None,
                            str(finding.get("text") or ""),
                            json.dumps(clean_indexes),
                        ),
                    )
                if prior is not None and prior["id"] != result_id:
                    conn.execute(
                        """
                        INSERT INTO assessment_supersessions (
                            id, owner_id, investigation_id, prior_result_id, successor_result_id,
                            reason, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            token_hex(16),
                            owner_id,
                            investigation_id,
                            prior["id"],
                            result_id,
                            supersession_reason,
                            created_at,
                        ),
                    )
                return self._assessment_payload(conn, result_id, include_model=False)
        except LedgerError:
            raise
        except sqlite3.IntegrityError as exc:
            # Concurrent insert for the same snapshot: return the winner.
            try:
                with self._transaction() as conn:
                    existing = conn.execute(
                        """
                        SELECT id, status FROM assessment_results
                        WHERE snapshot_id = ? AND owner_id = ? AND investigation_id = ?
                        """,
                        (snapshot_id, owner_id, investigation_id),
                    ).fetchone()
                    if existing is not None and existing["status"] == "completed":
                        return self._assessment_payload(conn, existing["id"], include_model=False)
            except (LedgerError, sqlite3.Error):
                pass
            raise LedgerError(
                "The evidence ledger is unavailable.",
                failure_code="persist_failed",
            ) from exc
        except sqlite3.Error as exc:
            raise LedgerError(
                "The evidence ledger is unavailable.",
                failure_code="persist_failed",
            ) from exc

    def save_failed_assessment(
        self,
        owner_id: str,
        investigation_id: str,
        snapshot_id: str,
        failure_code: str,
    ) -> dict | None:
        """Insert a failed attempt with no official outcomes or findings."""
        code = failure_code if failure_code in ASSESSMENT_FAILURE_CATALOG else "unknown"
        message = assessment_failure_message(code)
        result_id = token_hex(16)
        created_at = _now()
        try:
            with self._transaction() as conn:
                existing = conn.execute(
                    "SELECT id, status FROM assessment_results WHERE snapshot_id = ?",
                    (snapshot_id,),
                ).fetchone()
                if existing is not None:
                    return self._assessment_payload(conn, existing["id"], include_model=False)
                conn.execute(
                    """
                    INSERT INTO assessment_results (
                        id, investigation_id, owner_id, snapshot_id, status,
                        model_assessment, facing_assessment, failure_code, failure_message,
                        why_json, uncertainty_json, original_material_json, image_evidence_json,
                        created_at
                    ) VALUES (?, ?, ?, ?, 'failed', NULL, NULL, ?, ?, NULL, NULL, NULL, NULL, ?)
                    """,
                    (result_id, investigation_id, owner_id, snapshot_id, code, message, created_at),
                )
                return self._assessment_payload(conn, result_id, include_model=False)
        except sqlite3.IntegrityError:
            try:
                with self._transaction() as conn:
                    existing = conn.execute(
                        """
                        SELECT id FROM assessment_results
                        WHERE snapshot_id = ? AND owner_id = ? AND investigation_id = ?
                        """,
                        (snapshot_id, owner_id, investigation_id),
                    ).fetchone()
                    if existing is not None:
                        return self._assessment_payload(conn, existing["id"], include_model=False)
            except (LedgerError, sqlite3.Error):
                return None
            return None
        except (LedgerError, sqlite3.Error):
            return None

    def get_assessment_by_snapshot(
        self, owner_id: str, investigation_id: str, snapshot_id: str
    ) -> dict | None:
        with self._transaction() as conn:
            row = conn.execute(
                """
                SELECT id FROM assessment_results
                WHERE snapshot_id = ? AND owner_id = ? AND investigation_id = ?
                """,
                (snapshot_id, owner_id, investigation_id),
            ).fetchone()
            if row is None:
                return None
            return self._assessment_payload(conn, row["id"], include_model=False)

    def get_latest_completed_assessment(self, owner_id: str, investigation_id: str) -> dict | None:
        with self._transaction() as conn:
            row = conn.execute(
                """
                SELECT id FROM assessment_results
                WHERE owner_id = ? AND investigation_id = ? AND status = 'completed'
                ORDER BY created_at DESC, id DESC
                LIMIT 1
                """,
                (owner_id, investigation_id),
            ).fetchone()
            if row is None:
                return None
            return self._assessment_payload(conn, row["id"], include_model=False)

    def list_assessments(self, owner_id: str, investigation_id: str) -> list[dict] | None:
        if self.get_investigation(owner_id, investigation_id) is None:
            return None
        with self._transaction() as conn:
            rows = conn.execute(
                """
                SELECT id FROM assessment_results
                WHERE owner_id = ? AND investigation_id = ?
                ORDER BY created_at DESC, id DESC
                """,
                (owner_id, investigation_id),
            ).fetchall()
            return [self._assessment_payload(conn, row["id"], include_model=False) for row in rows]

    def _assessment_payload(self, conn: sqlite3.Connection, result_id: str, *, include_model: bool) -> dict:
        row = conn.execute(
            """
            SELECT id, investigation_id, owner_id, snapshot_id, status,
                   model_assessment, facing_assessment, failure_code, failure_message,
                   why_json, uncertainty_json, original_material_json, image_evidence_json,
                   created_at
            FROM assessment_results
            WHERE id = ?
            """,
            (result_id,),
        ).fetchone()
        if row is None:
            raise LedgerError("The evidence ledger is unavailable.")
        findings = []
        if row["status"] == "completed":
            for finding in conn.execute(
                """
                SELECT position, finding_type, evidence_status, alignment_reason, text, source_indexes_json
                FROM findings
                WHERE assessment_result_id = ?
                ORDER BY position
                """,
                (result_id,),
            ):
                try:
                    indexes = json.loads(finding["source_indexes_json"])
                except ValueError:
                    indexes = []
                if not isinstance(indexes, list):
                    indexes = []
                item = {
                    "type": finding["finding_type"],
                    "text": finding["text"],
                    "sources": [i for i in indexes if isinstance(i, int)],
                    "evidenceStatus": finding["evidence_status"],
                }
                if finding["alignment_reason"]:
                    item["alignmentReason"] = finding["alignment_reason"]
                findings.append(item)
        payload = {
            "assessmentResultId": row["id"],
            "investigationId": row["investigation_id"],
            "snapshotId": row["snapshot_id"],
            "status": row["status"],
            "assessedAt": row["created_at"],
            "assessment": row["facing_assessment"],
            "findings": findings,
        }
        if row["status"] == "completed":
            try:
                payload["why"] = json.loads(row["why_json"] or "{}")
            except ValueError:
                payload["why"] = {}
            try:
                payload["uncertainty"] = json.loads(row["uncertainty_json"] or "[]")
            except ValueError:
                payload["uncertainty"] = []
            try:
                payload["originalMaterial"] = json.loads(row["original_material_json"] or "{}")
            except ValueError:
                payload["originalMaterial"] = {}
            if row["image_evidence_json"]:
                try:
                    payload["imageEvidence"] = json.loads(row["image_evidence_json"])
                except ValueError:
                    pass
        else:
            payload["failureCode"] = row["failure_code"]
            payload["failureMessage"] = row["failure_message"]
        if include_model and row["model_assessment"]:
            payload["modelAssessment"] = row["model_assessment"]
        return payload

    def materialize_investigation_graph(self, owner_id: str, investigation_id: str) -> dict:
        """Idempotent internal graph build from stored rows only. No providers."""
        if self.get_investigation(owner_id, investigation_id) is None:
            raise LedgerError("The evidence ledger is unavailable.")
        results = {
            "investigation_skeleton": self.materialize_graph_scope(
                owner_id, investigation_id, "investigation_skeleton", investigation_id
            ),
        }
        with self._transaction() as conn:
            snaps = conn.execute(
                """
                SELECT id FROM assessment_snapshots
                WHERE investigation_id = ? AND owner_id = ?
                """,
                (investigation_id, owner_id),
            ).fetchall()
            assessments = conn.execute(
                """
                SELECT id FROM assessment_results
                WHERE investigation_id = ? AND owner_id = ? AND status = 'completed'
                """,
                (investigation_id, owner_id),
            ).fetchall()
        for snap in snaps:
            results[f"snapshot:{snap['id']}"] = self.materialize_graph_scope(
                owner_id, investigation_id, "snapshot", snap["id"]
            )
        for row in assessments:
            results[f"assessment_result:{row['id']}"] = self.materialize_graph_scope(
                owner_id, investigation_id, "assessment_result", row["id"]
            )
        return {"scopes": results}

    def materialize_graph_scope(
        self,
        owner_id: str,
        investigation_id: str,
        scope_type: str,
        scope_id: str,
    ) -> dict:
        """Materialize one graph scope in its own transaction. Best-effort caller wraps errors.

        Pending checkpoints are committed in a separate transaction so an
        interrupted build is recoverable as status ``pending`` (or ``failed``).
        Assessment scopes ensure their snapshot scope via a separate call first.
        """
        if scope_type not in ("investigation_skeleton", "snapshot", "assessment_result"):
            raise LedgerError(
                "The evidence ledger is unavailable.",
                failure_code="graph_persist_failed",
            )
        if self.get_investigation(owner_id, investigation_id) is None:
            raise LedgerError("The evidence ledger is unavailable.")
        # Immutable scopes that already completed are no-ops (idempotent).
        if scope_type in ("snapshot", "assessment_result"):
            prior = self._graph_checkpoint_status(owner_id, investigation_id, scope_type, scope_id)
            if prior == "complete":
                return {
                    "scopeType": scope_type,
                    "scopeId": scope_id,
                    "status": "complete",
                }
        # Snapshot nodes must have a matching snapshot checkpoint before assessment edges.
        if scope_type == "assessment_result":
            snapshot_id = self._snapshot_id_for_assessment(owner_id, investigation_id, scope_id)
            if snapshot_id:
                self.materialize_graph_scope(
                    owner_id, investigation_id, "snapshot", snapshot_id
                )
        # Durable pending so crashes leave a recoverable incomplete state (L2).
        self._set_graph_checkpoint(
            owner_id, investigation_id, scope_type, scope_id, "pending", None
        )
        try:
            with self._transaction() as conn:
                owned = conn.execute(
                    "SELECT id FROM investigations WHERE id = ? AND owner_id = ?",
                    (investigation_id, owner_id),
                ).fetchone()
                if owned is None:
                    raise LedgerError("The evidence ledger is unavailable.")
                builder = GraphBuilder(conn, owner_id, investigation_id, now=_now())
                if scope_type == "investigation_skeleton":
                    self._materialize_skeleton(conn, builder, owner_id, investigation_id)
                elif scope_type == "snapshot":
                    self._materialize_snapshot(conn, builder, owner_id, investigation_id, scope_id)
                else:
                    self._materialize_assessment_result(
                        conn, builder, owner_id, investigation_id, scope_id
                    )
                builder.set_checkpoint(scope_type, scope_id, "complete", None)
                return {"scopeType": scope_type, "scopeId": scope_id, "status": "complete"}
        except LedgerError as exc:
            self._mark_graph_checkpoint_failed(owner_id, investigation_id, scope_type, scope_id)
            code = getattr(exc, "failure_code", None) or "graph_persist_failed"
            logger.warning(
                "graph_scope_failed investigation_id=%s scope_type=%s scope_id=%s error_code=%s",
                investigation_id,
                scope_type,
                scope_id,
                code if isinstance(code, str) else "graph_persist_failed",
            )
            raise
        except (ValueError, sqlite3.Error, TypeError, json.JSONDecodeError) as exc:
            self._mark_graph_checkpoint_failed(owner_id, investigation_id, scope_type, scope_id)
            logger.warning(
                "graph_scope_failed investigation_id=%s scope_type=%s scope_id=%s error_code=%s",
                investigation_id,
                scope_type,
                scope_id,
                "graph_persist_failed",
            )
            raise LedgerError(
                "The evidence ledger is unavailable.",
                failure_code="graph_persist_failed",
            ) from exc

    def _graph_checkpoint_status(
        self, owner_id: str, investigation_id: str, scope_type: str, scope_id: str
    ) -> str | None:
        conn = self._connect()
        try:
            row = conn.execute(
                """
                SELECT status FROM evidence_graph_checkpoints
                WHERE investigation_id = ? AND owner_id = ?
                  AND scope_type = ? AND scope_id = ?
                """,
                (investigation_id, owner_id, scope_type, scope_id),
            ).fetchone()
            return row["status"] if row is not None else None
        finally:
            conn.close()

    def _snapshot_id_for_assessment(
        self, owner_id: str, investigation_id: str, result_id: str
    ) -> str | None:
        conn = self._connect()
        try:
            row = conn.execute(
                """
                SELECT snapshot_id FROM assessment_results
                WHERE id = ? AND investigation_id = ? AND owner_id = ? AND status = 'completed'
                """,
                (result_id, investigation_id, owner_id),
            ).fetchone()
            if row is None:
                return None
            sid = row["snapshot_id"]
            return sid if isinstance(sid, str) and sid else None
        finally:
            conn.close()

    def _set_graph_checkpoint(
        self,
        owner_id: str,
        investigation_id: str,
        scope_type: str,
        scope_id: str,
        status: str,
        error_code: str | None,
    ) -> None:
        with self._transaction() as conn:
            builder = GraphBuilder(conn, owner_id, investigation_id, now=_now())
            builder.set_checkpoint(scope_type, scope_id, status, error_code)

    def _mark_graph_checkpoint_failed(
        self, owner_id: str, investigation_id: str, scope_type: str, scope_id: str
    ) -> None:
        try:
            self._set_graph_checkpoint(
                owner_id,
                investigation_id,
                scope_type,
                scope_id,
                "failed",
                "graph_persist_failed",
            )
        except (LedgerError, sqlite3.Error):
            pass

    def _materialize_skeleton(
        self, conn: sqlite3.Connection, builder: GraphBuilder, owner_id: str, investigation_id: str
    ) -> None:
        inv = conn.execute(
            "SELECT id, kind, input_text, created_at FROM investigations WHERE id = ? AND owner_id = ?",
            (investigation_id, owner_id),
        ).fetchone()
        if inv is None:
            raise LedgerError("The evidence ledger is unavailable.")
        inv_node = builder.upsert_node(
            "investigation",
            canonical_investigation(investigation_id),
            {"kind": inv["kind"], "createdAt": inv["created_at"]},
            source_table="investigations",
            source_row_id=investigation_id,
        )
        claim_row = conn.execute(
            "SELECT primary_claim FROM claim_analyses WHERE investigation_id = ?",
            (investigation_id,),
        ).fetchone()
        claim_text = (claim_row["primary_claim"] if claim_row else None) or inv["input_text"] or ""
        claim_node = builder.upsert_node(
            "claim",
            canonical_claim(),
            props_claim(claim_text),
            source_table="claim_analyses" if claim_row else "investigations",
            source_row_id=investigation_id,
        )
        builder.ensure_active_edge(
            src_node_id=inv_node,
            dst_node_id=claim_node,
            rel_type="CONTAINS",
            certainty="CONFIRMED",
            method="system_structural",
            evidence={"rule": "investigation_contains_claim"},
        )
        for source in conn.execute(
            """
            SELECT id, position, url, title, snippet, published_at, date_certainty, date_type,
                   quality_tier
            FROM evidence_sources WHERE investigation_id = ? ORDER BY position
            """,
            (investigation_id,),
        ):
            src_props = props_source(
                {
                    "url": source["url"],
                    "title": source["title"],
                    "publishedAt": source["published_at"],
                    "dateCertainty": source["date_certainty"],
                    "dateType": source["date_type"],
                    "quality_tier": source["quality_tier"],
                },
                sealed=False,
            )
            live_node = builder.upsert_node(
                "evidence_source",
                canonical_live_source(source["id"]),
                src_props,
                source_table="evidence_sources",
                source_row_id=source["id"],
            )
            builder.ensure_active_edge(
                src_node_id=inv_node,
                dst_node_id=live_node,
                rel_type="CONTAINS",
                certainty="CONFIRMED",
                method="system_structural",
                evidence={"rule": "investigation_contains_live_source", "sourceId": source["id"]},
            )
            url = source["url"] or ""
            if url:
                url_node = builder.upsert_node(
                    "url",
                    canonical_url(url),
                    {"url": url},
                )
                builder.ensure_active_edge(
                    src_node_id=live_node,
                    dst_node_id=url_node,
                    rel_type="REFERENCES",
                    certainty="CONFIRMED",
                    method="system_structural",
                    evidence={"rule": "live_source_url"},
                )
                site = canonical_site(url)
                if site != "site:":
                    site_node = builder.upsert_node("website", site, {"host": website_key(url)})
                    builder.ensure_active_edge(
                        src_node_id=url_node,
                        dst_node_id=site_node,
                        rel_type="REFERENCES",
                        certainty="CONFIRMED",
                        method="system_structural",
                        evidence={"rule": "url_website"},
                    )
                if source["published_at"] or source["date_certainty"]:
                    pub_key = canonical_publication(
                        canonical_live_source(source["id"]),
                        "claimed_publication",
                        source["published_at"],
                        source["date_certainty"],
                    )
                    pub_node = builder.upsert_node(
                        "publication_event",
                        pub_key,
                        {
                            "date_role": "claimed_publication",
                            "published_at": source["published_at"],
                            "date_certainty": source["date_certainty"],
                            "date_type": source["date_type"],
                            "attribution": "source_row",
                            "limitations": ["not_verified_as_original_publication"],
                        },
                    )
                    builder.ensure_active_edge(
                        src_node_id=live_node,
                        dst_node_id=pub_node,
                        rel_type="PUBLISHED_AT",
                        certainty=published_at_certainty(source["date_certainty"]),
                        method="system_structural",
                        evidence={"rule": "recorded_publication_field"},
                        allow_replace=True,
                    )
        page = conn.execute(
            "SELECT id, final_url, title, created_at FROM page_fetches WHERE investigation_id = ?",
            (investigation_id,),
        ).fetchone()
        if page is not None:
            page_node = builder.upsert_node(
                "page",
                canonical_page(page["id"]),
                {"url": page["final_url"], "title": page["title"]},
                source_table="page_fetches",
                source_row_id=page["id"],
            )
            builder.ensure_active_edge(
                src_node_id=inv_node,
                dst_node_id=page_node,
                rel_type="CONTAINS",
                certainty="CONFIRMED",
                method="system_structural",
                evidence={"rule": "investigation_contains_page"},
            )
            builder.ensure_active_edge(
                src_node_id=claim_node,
                dst_node_id=page_node,
                rel_type="DERIVED_FROM",
                certainty="CONFIRMED",
                method="system_structural",
                evidence={"rule": "claim_from_page"},
            )
            obs_key = canonical_observation(
                "investigation_capture", canonical_page(page["id"]), page["created_at"]
            )
            obs_node = builder.upsert_node(
                "observation_event",
                obs_key,
                {
                    "observation_kind": "investigation_capture",
                    "observed_at": page["created_at"],
                    "clock": "server",
                    "limitations": [],
                },
            )
            builder.ensure_active_edge(
                src_node_id=page_node,
                dst_node_id=obs_node,
                rel_type="OBSERVED_AT",
                certainty="CONFIRMED",
                method="system_clock",
                evidence={"rule": "page_fetch_created_at"},
            )
        asset = conn.execute(
            """
            SELECT id, sha256, received_at, media_type FROM image_assets
            WHERE investigation_id = ? AND owner_id = ?
            """,
            (investigation_id, owner_id),
        ).fetchone()
        if asset is not None:
            image_node = builder.upsert_node(
                "image",
                canonical_image(asset["sha256"]),
                {"sha256": asset["sha256"], "mediaType": asset["media_type"]},
                source_table="image_assets",
                source_row_id=asset["id"],
            )
            builder.ensure_active_edge(
                src_node_id=inv_node,
                dst_node_id=image_node,
                rel_type="CONTAINS",
                certainty="CONFIRMED",
                method="system_structural",
                evidence={"rule": "investigation_contains_image"},
            )
            obs_key = canonical_observation(
                "server_received", canonical_image(asset["sha256"]), asset["received_at"]
            )
            obs_node = builder.upsert_node(
                "observation_event",
                obs_key,
                {
                    "observation_kind": "server_received",
                    "observed_at": asset["received_at"],
                    "clock": "server",
                    "limitations": [],
                },
            )
            builder.ensure_active_edge(
                src_node_id=image_node,
                dst_node_id=obs_node,
                rel_type="OBSERVED_AT",
                certainty="CONFIRMED",
                method="system_clock",
                evidence={"rule": "image_received_at"},
            )

    def _materialize_snapshot(
        self,
        conn: sqlite3.Connection,
        builder: GraphBuilder,
        owner_id: str,
        investigation_id: str,
        snapshot_id: str,
    ) -> None:
        row = conn.execute(
            """
            SELECT id, snapshot_json, created_at FROM assessment_snapshots
            WHERE id = ? AND investigation_id = ? AND owner_id = ?
            """,
            (snapshot_id, investigation_id, owner_id),
        ).fetchone()
        if row is None:
            raise LedgerError("The evidence ledger is unavailable.")
        # Immutable once complete: skip rebuild if already complete.
        done = conn.execute(
            """
            SELECT status FROM evidence_graph_checkpoints
            WHERE investigation_id = ? AND scope_type = 'snapshot' AND scope_id = ?
            """,
            (investigation_id, snapshot_id),
        ).fetchone()
        # pending was just set by caller; still build. If previously complete, short-circuit
        # only when snapshot node already exists (idempotent rematerialize).
        existing_snap = conn.execute(
            """
            SELECT id FROM evidence_nodes
            WHERE investigation_id = ? AND node_type = 'snapshot' AND canonical_key = ?
            """,
            (investigation_id, canonical_snapshot(snapshot_id)),
        ).fetchone()
        if existing_snap is not None and done is not None and done["status"] == "complete":
            return
        try:
            body = json.loads(row["snapshot_json"] or "{}")
        except ValueError as exc:
            raise LedgerError("The evidence ledger is unavailable.") from exc
        inv_node = builder.upsert_node(
            "investigation",
            canonical_investigation(investigation_id),
            {},
            source_table="investigations",
            source_row_id=investigation_id,
        )
        snap_node = builder.upsert_node(
            "snapshot",
            canonical_snapshot(snapshot_id),
            {"createdAt": row["created_at"]},
            source_table="assessment_snapshots",
            source_row_id=snapshot_id,
            snapshot_id=snapshot_id,
        )
        builder.ensure_active_edge(
            src_node_id=inv_node,
            dst_node_id=snap_node,
            rel_type="CONTAINS",
            certainty="CONFIRMED",
            method="system_structural",
            evidence={"rule": "investigation_contains_snapshot"},
            snapshot_id=snapshot_id,
        )
        obs_key = canonical_observation(
            "investigation_capture", canonical_snapshot(snapshot_id), row["created_at"]
        )
        obs_node = builder.upsert_node(
            "observation_event",
            obs_key,
            {
                "observation_kind": "investigation_capture",
                "observed_at": row["created_at"],
                "clock": "server",
                "limitations": [],
            },
            snapshot_id=snapshot_id,
        )
        builder.ensure_active_edge(
            src_node_id=snap_node,
            dst_node_id=obs_node,
            rel_type="OBSERVED_AT",
            certainty="CONFIRMED",
            method="system_clock",
            evidence={"rule": "snapshot_created_at"},
            snapshot_id=snapshot_id,
        )
        sources = body.get("sources") if isinstance(body.get("sources"), list) else []
        for index, source in enumerate(sources):
            if not isinstance(source, dict):
                continue
            key = canonical_snap_source(snapshot_id, index)
            src_node = builder.upsert_node(
                "evidence_source",
                key,
                props_source(source, sealed=True),
                snapshot_id=snapshot_id,
            )
            builder.ensure_active_edge(
                src_node_id=snap_node,
                dst_node_id=src_node,
                rel_type="CONTAINS",
                certainty="CONFIRMED",
                method="system_structural",
                evidence={"rule": "snapshot_contains_source", "index": index},
                snapshot_id=snapshot_id,
            )
            url = source.get("url") or ""
            if url:
                url_node = builder.upsert_node("url", canonical_url(url), {"url": url}, snapshot_id=snapshot_id)
                builder.ensure_active_edge(
                    src_node_id=src_node,
                    dst_node_id=url_node,
                    rel_type="REFERENCES",
                    certainty="CONFIRMED",
                    method="system_structural",
                    evidence={"rule": "sealed_source_url", "index": index},
                    snapshot_id=snapshot_id,
                )
            published = source.get("publishedAt")
            certainty = source.get("dateCertainty")
            if published or certainty:
                pub_node = builder.upsert_node(
                    "publication_event",
                    canonical_publication(key, "claimed_publication", published, certainty),
                    {
                        "date_role": "claimed_publication",
                        "published_at": published,
                        "date_certainty": certainty,
                        "date_type": source.get("dateType"),
                        "attribution": "sealed_source",
                        "limitations": ["not_verified_as_original_publication"],
                    },
                    snapshot_id=snapshot_id,
                )
                builder.ensure_active_edge(
                    src_node_id=src_node,
                    dst_node_id=pub_node,
                    rel_type="PUBLISHED_AT",
                    certainty=published_at_certainty(certainty if isinstance(certainty, str) else None),
                    method="system_structural",
                    evidence={"rule": "sealed_publication_field", "index": index},
                    snapshot_id=snapshot_id,
                )
        if isinstance(body.get("provenance"), dict) or body.get("provenance"):
            prov_node = builder.upsert_node(
                "provenance_record",
                canonical_provenance(snapshot_id),
                {"present": True},
                snapshot_id=snapshot_id,
            )
            builder.ensure_active_edge(
                src_node_id=snap_node,
                dst_node_id=prov_node,
                rel_type="CONTAINS",
                certainty="CONFIRMED",
                method="system_structural",
                evidence={"rule": "snapshot_provenance"},
                snapshot_id=snapshot_id,
            )
        sealed_asset = body.get("sealedAsset") if isinstance(body.get("sealedAsset"), dict) else None
        if sealed_asset and sealed_asset.get("sha256"):
            image_node = builder.upsert_node(
                "image",
                canonical_image(str(sealed_asset["sha256"])),
                {"sha256": sealed_asset["sha256"], "sealed": True},
                snapshot_id=snapshot_id,
            )
            builder.ensure_active_edge(
                src_node_id=snap_node,
                dst_node_id=image_node,
                rel_type="CONTAINS",
                certainty="CONFIRMED",
                method="system_structural",
                evidence={"rule": "snapshot_sealed_image"},
                snapshot_id=snapshot_id,
            )

    def _materialize_assessment_result(
        self,
        conn: sqlite3.Connection,
        builder: GraphBuilder,
        owner_id: str,
        investigation_id: str,
        result_id: str,
    ) -> None:
        row = conn.execute(
            """
            SELECT id, snapshot_id, status, facing_assessment, created_at
            FROM assessment_results
            WHERE id = ? AND investigation_id = ? AND owner_id = ?
            """,
            (result_id, investigation_id, owner_id),
        ).fetchone()
        if row is None or row["status"] != "completed":
            raise LedgerError("The evidence ledger is unavailable.")
        existing = conn.execute(
            """
            SELECT id FROM evidence_nodes
            WHERE investigation_id = ? AND node_type = 'assessment_result' AND canonical_key = ?
            """,
            (investigation_id, canonical_assessment(result_id)),
        ).fetchone()
        done = conn.execute(
            """
            SELECT status FROM evidence_graph_checkpoints
            WHERE investigation_id = ? AND scope_type = 'assessment_result' AND scope_id = ?
            """,
            (investigation_id, result_id),
        ).fetchone()
        if existing is not None and done is not None and done["status"] == "complete":
            return
        # Snapshot scope must already be materialized in its own checkpointed
        # transaction (see materialize_graph_scope). Only upsert references here.
        claim_node = builder.upsert_node("claim", canonical_claim(), props_claim(""))
        snap_node = builder.upsert_node(
            "snapshot",
            canonical_snapshot(row["snapshot_id"]),
            {},
            snapshot_id=row["snapshot_id"],
        )
        assess_node = builder.upsert_node(
            "assessment_result",
            canonical_assessment(result_id),
            {
                "status": "completed",
                "assessment": row["facing_assessment"],
                "assessedAt": row["created_at"],
            },
            source_table="assessment_results",
            source_row_id=result_id,
            snapshot_id=row["snapshot_id"],
            assessment_result_id=result_id,
        )
        builder.ensure_active_edge(
            src_node_id=assess_node,
            dst_node_id=snap_node,
            rel_type="DERIVED_FROM",
            certainty="CONFIRMED",
            method="system_structural",
            evidence={"rule": "assessment_from_snapshot"},
            snapshot_id=row["snapshot_id"],
            assessment_result_id=result_id,
        )
        for finding in conn.execute(
            """
            SELECT position, finding_type, evidence_status, alignment_reason, text, source_indexes_json
            FROM findings WHERE assessment_result_id = ? ORDER BY position
            """,
            (result_id,),
        ):
            f_node = builder.upsert_node(
                "finding",
                canonical_finding(result_id, int(finding["position"])),
                {
                    "type": finding["finding_type"],
                    "text": finding["text"],
                    "evidenceStatus": finding["evidence_status"],
                    "alignmentReason": finding["alignment_reason"],
                },
                source_table="findings",
                snapshot_id=row["snapshot_id"],
                assessment_result_id=result_id,
            )
            builder.ensure_active_edge(
                src_node_id=assess_node,
                dst_node_id=f_node,
                rel_type="CONTAINS",
                certainty="CONFIRMED",
                method="system_structural",
                evidence={"rule": "assessment_contains_finding", "position": finding["position"]},
                snapshot_id=row["snapshot_id"],
                assessment_result_id=result_id,
            )
            try:
                indexes = json.loads(finding["source_indexes_json"] or "[]")
            except ValueError:
                indexes = []
            if not isinstance(indexes, list):
                indexes = []
            for index in indexes:
                if not isinstance(index, int):
                    continue
                src_node = builder.upsert_node(
                    "evidence_source",
                    canonical_snap_source(row["snapshot_id"], index),
                    {"index": index, "sealed": True},
                    snapshot_id=row["snapshot_id"],
                )
                builder.ensure_active_edge(
                    src_node_id=f_node,
                    dst_node_id=src_node,
                    rel_type="REFERENCES",
                    certainty="CONFIRMED",
                    method="system_structural",
                    evidence={"rule": "finding_source_index", "index": index},
                    snapshot_id=row["snapshot_id"],
                    assessment_result_id=result_id,
                )
            ftype = finding["finding_type"] or ""
            certainty, method = finding_support_certainty(
                finding["evidence_status"], finding["alignment_reason"]
            )
            if ftype == "support":
                builder.ensure_active_edge(
                    src_node_id=f_node,
                    dst_node_id=claim_node,
                    rel_type="SUPPORTS",
                    certainty=certainty,
                    method=method,
                    evidence={
                        "rule": "finding_supports_claim",
                        "evidenceStatus": finding["evidence_status"],
                        "alignmentReason": finding["alignment_reason"],
                    },
                    snapshot_id=row["snapshot_id"],
                    assessment_result_id=result_id,
                )
            elif ftype == "contradict":
                builder.ensure_active_edge(
                    src_node_id=f_node,
                    dst_node_id=claim_node,
                    rel_type="CONTRADICTS",
                    certainty=certainty,
                    method=method,
                    evidence={
                        "rule": "finding_contradicts_claim",
                        "evidenceStatus": finding["evidence_status"],
                        "alignmentReason": finding["alignment_reason"],
                    },
                    snapshot_id=row["snapshot_id"],
                    assessment_result_id=result_id,
                )
        # Supersession edges from Phase A table.
        for link in conn.execute(
            """
            SELECT prior_result_id, successor_result_id, reason
            FROM assessment_supersessions
            WHERE investigation_id = ? AND owner_id = ?
              AND (prior_result_id = ? OR successor_result_id = ?)
            """,
            (investigation_id, owner_id, result_id, result_id),
        ):
            prior_node = builder.upsert_node(
                "assessment_result",
                canonical_assessment(link["prior_result_id"]),
                {},
                assessment_result_id=link["prior_result_id"],
            )
            succ_node = builder.upsert_node(
                "assessment_result",
                canonical_assessment(link["successor_result_id"]),
                {},
                assessment_result_id=link["successor_result_id"],
            )
            builder.ensure_active_edge(
                src_node_id=succ_node,
                dst_node_id=prior_node,
                rel_type="SUPERSEDES",
                certainty="CONFIRMED",
                method="system_supersession",
                evidence={"rule": "assessment_supersession", "reason": link["reason"]},
                assessment_result_id=link["successor_result_id"],
            )

    def get_investigation_graph(
        self, owner_id: str, investigation_id: str, *, include_replaced: bool = False
    ) -> dict | None:
        """Read-only graph projection. Performs no writes."""
        if self.get_investigation(owner_id, investigation_id) is None:
            return None
        conn = self._connect()
        try:
            stored = {
                (row["scope_type"], row["scope_id"]): row["status"]
                for row in conn.execute(
                    """
                    SELECT scope_type, scope_id, status FROM evidence_graph_checkpoints
                    WHERE investigation_id = ? AND owner_id = ?
                    """,
                    (investigation_id, owner_id),
                )
            }
            expected = [("investigation_skeleton", investigation_id)]
            for row in conn.execute(
                """
                SELECT id FROM assessment_snapshots
                WHERE investigation_id = ? AND owner_id = ?
                ORDER BY id
                """,
                (investigation_id, owner_id),
            ):
                expected.append(("snapshot", row["id"]))
            for row in conn.execute(
                """
                SELECT id FROM assessment_results
                WHERE investigation_id = ? AND owner_id = ? AND status = 'completed'
                ORDER BY id
                """,
                (investigation_id, owner_id),
            ):
                expected.append(("assessment_result", row["id"]))
            # Report every expected scope; missing rows surface as status "missing".
            checkpoints = []
            for scope_type, scope_id in expected:
                status = stored.get((scope_type, scope_id))
                checkpoints.append(
                    {
                        "scopeType": scope_type,
                        "scopeId": scope_id,
                        "status": status if status is not None else "missing",
                    }
                )
            # Also surface unexpected leftover checkpoints (should be rare).
            expected_keys = set(expected)
            for (scope_type, scope_id), status in sorted(stored.items()):
                if (scope_type, scope_id) not in expected_keys:
                    checkpoints.append(
                        {
                            "scopeType": scope_type,
                            "scopeId": scope_id,
                            "status": status,
                        }
                    )
            complete = bool(expected) and all(
                stored.get(key) == "complete" for key in expected
            )
            nodes = []
            for row in conn.execute(
                """
                SELECT id, node_type, canonical_key, props_json
                FROM evidence_nodes
                WHERE investigation_id = ? AND owner_id = ?
                ORDER BY node_type, canonical_key
                """,
                (investigation_id, owner_id),
            ):
                try:
                    props = json.loads(row["props_json"] or "{}")
                except ValueError:
                    props = {}
                nodes.append(
                    {
                        "id": row["id"],
                        "type": row["node_type"],
                        "canonicalKey": row["canonical_key"],
                        "props": props,
                    }
                )
            if include_replaced:
                edge_rows = conn.execute(
                    """
                    SELECT id, src_node_id, dst_node_id, rel_type, certainty, method,
                           snapshot_id, assessment_result_id, replaces_edge_id, created_at
                    FROM evidence_edges
                    WHERE investigation_id = ? AND owner_id = ?
                    ORDER BY created_at, id
                    """,
                    (investigation_id, owner_id),
                ).fetchall()
            else:
                edge_rows = conn.execute(
                    """
                    SELECT e.id, e.src_node_id, e.dst_node_id, e.rel_type, e.certainty, e.method,
                           e.snapshot_id, e.assessment_result_id, e.replaces_edge_id, e.created_at
                    FROM evidence_edges e
                    JOIN evidence_edge_active a ON a.edge_id = e.id
                    WHERE e.investigation_id = ? AND e.owner_id = ?
                    ORDER BY e.created_at, e.id
                    """,
                    (investigation_id, owner_id),
                ).fetchall()
            edges = [
                {
                    "id": row["id"],
                    "source": row["src_node_id"],
                    "target": row["dst_node_id"],
                    "relType": row["rel_type"],
                    "certainty": row["certainty"],
                    "method": row["method"],
                    "snapshotId": row["snapshot_id"],
                    "assessmentResultId": row["assessment_result_id"],
                    "replacesEdgeId": row["replaces_edge_id"],
                    "createdAt": row["created_at"],
                }
                for row in edge_rows
            ]
            return {
                "investigationId": investigation_id,
                "note": GRAPH_NOTE,
                "graphStatus": {"complete": complete, "checkpoints": checkpoints},
                "nodes": nodes,
                "edges": edges,
                "derived": {"earliestIndependentObservation": None},
            }
        finally:
            conn.close()

    def check_health(self) -> bool:
        """Open the ledger, query its tables, and run the SQLite integrity check.

        False means the file could not be used. The reason is not included.
        """
        try:
            conn = self._connect()
        except (LedgerError, OSError, sqlite3.Error):
            return False
        try:
            for table in (
                "users",
                "investigations",
                "page_fetches",
                "evidence_sources",
                "claim_analyses",
                "sessions",
                "assessment_snapshots",
                "assessment_results",
                "findings",
                "assessment_supersessions",
                "evidence_nodes",
                "evidence_edges",
                "evidence_edge_active",
                "evidence_graph_checkpoints",
                "image_assets",
                "asset_cleanup",
                "pending_deletions",
            ):
                conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
            try:
                rows = conn.execute("PRAGMA integrity_check").fetchall()
            except sqlite3.Error:
                return False
            if len(rows) != 1 or str(rows[0][0]).lower() != "ok":
                return False
            return self._asset_files_consistent(conn)
        except (OSError, sqlite3.Error):
            return False
        finally:
            conn.close()

    def account_password_status(self, user_id: str, password: str) -> str:
        """Check an account password without deleting anything.

        Returns the same ``ok``, ``rejected``, ``missing``, and ``legacy``
        values as erasure. A wrong password leaves every row in place.
        """
        try:
            with self._transaction() as conn:
                row = conn.execute(
                    "SELECT email, password_hash FROM users WHERE id = ?",
                    (user_id,),
                ).fetchone()
        except sqlite3.Error as exc:
            raise LedgerError("The evidence ledger is unavailable.") from exc
        if row is None:
            return "missing"
        if not row["email"] or not row["password_hash"]:
            return "legacy"
        if not verify_password(row["password_hash"], password if isinstance(password, str) else ""):
            return "rejected"
        return "ok"

    def image_asset(self, owner_id: str, investigation_id: str) -> dict | None:
        with self._transaction() as conn:
            row = conn.execute(
                f"""
                SELECT {_ASSET_COLUMNS}
                FROM image_assets
                WHERE investigation_id = ? AND owner_id = ?
                """,
                (investigation_id, owner_id),
            ).fetchone()
        if row is None:
            return None
        return _asset_record(row)

    def asset_storage_names(self, owner_id: str) -> list[str]:
        with self._transaction() as conn:
            rows = conn.execute(
                """
                SELECT storage_name FROM image_assets
                WHERE owner_id = ?
                   OR investigation_id IN (SELECT id FROM investigations WHERE owner_id = ?)
                """,
                (owner_id, owner_id),
            ).fetchall()
        return [row["storage_name"] for row in rows]

    def video_storage_names(self, owner_id: str) -> list[str]:
        with self._transaction() as conn:
            rows = conn.execute(
                """
                SELECT storage_name FROM video_assets
                WHERE owner_id = ?
                   OR investigation_id IN (SELECT id FROM investigations WHERE owner_id = ?)
                """,
                (owner_id, owner_id),
            ).fetchall()
        return [row["storage_name"] for row in rows]

    def video_cleanup_records(self, owner_id: str, investigation_id: str | None = None) -> list[dict]:
        with self._transaction() as conn:
            if investigation_id is None:
                rows = conn.execute(
                    """
                    SELECT storage_name, owner_id, investigation_id, sha256, byte_length
                    FROM video_asset_cleanup
                    WHERE owner_id = ?
                    """,
                    (owner_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT storage_name, owner_id, investigation_id, sha256, byte_length
                    FROM video_asset_cleanup
                    WHERE owner_id = ? AND investigation_id = ?
                    """,
                    (owner_id, investigation_id),
                ).fetchall()
        return [dict(row) for row in rows]

    def cleanup_records(self, owner_id: str, investigation_id: str | None = None) -> list[dict]:
        with self._transaction() as conn:
            if investigation_id is None:
                rows = conn.execute(
                    """
                    SELECT storage_name, owner_id, investigation_id, sha256, byte_length
                    FROM asset_cleanup
                    WHERE owner_id = ?
                    """,
                    (owner_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT storage_name, owner_id, investigation_id, sha256, byte_length
                    FROM asset_cleanup
                    WHERE owner_id = ? AND investigation_id = ?
                    """,
                    (owner_id, investigation_id),
                ).fetchall()
        return [dict(row) for row in rows]

    def record_asset_cleanup(
        self,
        owner_id: str,
        investigation_id: str,
        storage_name: str,
        digest: str,
        byte_length: int,
        reason: str,
    ) -> None:
        with self._transaction() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO asset_cleanup (
                    storage_name, owner_id, investigation_id, sha256, byte_length, reason, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (storage_name, owner_id, investigation_id, digest, byte_length, reason, _now()),
            )

    def finish_asset_cleanup(self, storage_name: str) -> None:
        with self._transaction() as conn:
            conn.execute("DELETE FROM asset_cleanup WHERE storage_name = ?", (storage_name,))

    def save_image_asset(
        self,
        owner_id: str,
        investigation_id: str,
        asset_id: str,
        digest: str,
        byte_length: int,
        media_type: str,
        client_hash_status: str,
        storage_name: str,
        consent_version: str,
        metadata_consent_version: str = "declined",
        metadata_consent_decision: str = "omitted",
    ) -> tuple[str, str | None]:
        """Store one asset for an investigation that has not been sealed.

        Returns ``saved`` and the previous storage name, ``sealed`` when a
        snapshot already exists, or ``missing`` when the investigation is not
        owned by this account. The file itself is written by the caller.
        """
        try:
            with self._transaction() as conn:
                owned = conn.execute(
                    "SELECT id FROM investigations WHERE id = ? AND owner_id = ?",
                    (investigation_id, owner_id),
                ).fetchone()
                if owned is None:
                    return "missing", None
                if _deletion_pending(conn, owner_id, investigation_id):
                    return "deleting", None
                previous = conn.execute(
                    """
                    SELECT storage_name, sha256, byte_length, retention
                    FROM image_assets WHERE investigation_id = ?
                    """,
                    (investigation_id,),
                ).fetchone()
                if previous is not None and previous["retention"] == "retiring":
                    return "deleting", None
                sealed = conn.execute(
                    """
                    SELECT id FROM assessment_snapshots
                    WHERE investigation_id = ? AND owner_id = ?
                    """,
                    (investigation_id, owner_id),
                ).fetchone()
                if sealed is not None:
                    return "sealed", None
                previous_name = previous["storage_name"] if previous else None
                if previous is not None and previous_name != storage_name:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO asset_cleanup (
                            storage_name, owner_id, investigation_id, sha256, byte_length,
                            reason, created_at
                        ) VALUES (?, ?, ?, ?, ?, 'replaced', ?)
                        """,
                        (
                            previous_name,
                            owner_id,
                            investigation_id,
                            previous["sha256"],
                            previous["byte_length"],
                            _now(),
                        ),
                    )
                conn.execute(
                    "DELETE FROM image_assets WHERE investigation_id = ?",
                    (investigation_id,),
                )
                received_at = _now()
                conn.execute(
                    """
                    INSERT INTO image_assets (
                        id, investigation_id, owner_id, sha256, byte_length, media_type,
                        received_at, retention, client_hash_status, storage_name,
                        consent_version, metadata_consent_version,
                        metadata_consent_decision, metadata_consent_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'retained', ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        asset_id,
                        investigation_id,
                        owner_id,
                        digest,
                        byte_length,
                        media_type,
                        received_at,
                        client_hash_status,
                        storage_name,
                        consent_version,
                        metadata_consent_version,
                        metadata_consent_decision,
                        received_at,
                    ),
                )
        except sqlite3.Error as exc:
            raise LedgerError("The evidence ledger is unavailable.") from exc
        return "saved", previous_name

    def video_asset(self, owner_id: str, investigation_id: str) -> dict | None:
        conn = self._connect()
        try:
            row = conn.execute(
                """
                SELECT * FROM video_assets
                WHERE investigation_id = ? AND owner_id = ?
                """,
                (investigation_id, owner_id),
            ).fetchone()
            return _video_record(row) if row else None
        except sqlite3.Error as exc:
            raise LedgerError("The evidence ledger is unavailable.") from exc
        finally:
            conn.close()

    def delete_video_asset_row(self, owner_id: str, investigation_id: str) -> dict | None:
        """Remove the video row after physical unlink succeeded.

        Returns the prior public record (including storageName) or None.
        Callers must record cleanup and unlink before invoking this.
        """
        try:
            with self._transaction() as conn:
                row = conn.execute(
                    """
                    SELECT * FROM video_assets
                    WHERE investigation_id = ? AND owner_id = ?
                    """,
                    (investigation_id, owner_id),
                ).fetchone()
                if row is None:
                    return None
                sealed = conn.execute(
                    """
                    SELECT id FROM assessment_snapshots
                    WHERE investigation_id = ? AND owner_id = ?
                    """,
                    (investigation_id, owner_id),
                ).fetchone()
                if sealed is not None:
                    return {"__sealed__": True}
                record = _video_record(row)
                conn.execute(
                    "DELETE FROM video_assets WHERE investigation_id = ? AND owner_id = ?",
                    (investigation_id, owner_id),
                )
                return record
        except sqlite3.Error as exc:
            raise LedgerError("The evidence ledger is unavailable.") from exc

    def prepare_video_removal(self, owner_id: str, investigation_id: str) -> dict | None:
        """Inspect a video for user removal without deleting the row yet.

        Returns ``None`` when absent, ``{"__sealed__": True}`` when sealed,
        or the public record (with storageName) when removal may proceed.
        """
        try:
            with self._transaction() as conn:
                row = conn.execute(
                    """
                    SELECT * FROM video_assets
                    WHERE investigation_id = ? AND owner_id = ?
                    """,
                    (investigation_id, owner_id),
                ).fetchone()
                if row is None:
                    return None
                sealed = conn.execute(
                    """
                    SELECT id FROM assessment_snapshots
                    WHERE investigation_id = ? AND owner_id = ?
                    """,
                    (investigation_id, owner_id),
                ).fetchone()
                if sealed is not None:
                    return {"__sealed__": True}
                return _video_record(row)
        except sqlite3.Error as exc:
            raise LedgerError("The evidence ledger is unavailable.") from exc

    def pending_video_cleanup_for_investigation(
        self, owner_id: str, investigation_id: str
    ) -> dict | None:
        """Return one durable cleanup row for retry when the asset row is gone."""
        with self._transaction() as conn:
            row = conn.execute(
                """
                SELECT storage_name, owner_id, investigation_id, sha256, byte_length, reason
                FROM video_asset_cleanup
                WHERE owner_id = ? AND investigation_id = ?
                ORDER BY created_at ASC
                LIMIT 1
                """,
                (owner_id, investigation_id),
            ).fetchone()
        return dict(row) if row else None

    def save_video_asset(
        self,
        owner_id: str,
        investigation_id: str,
        asset_id: str,
        digest: str,
        byte_length: int,
        media_type: str,
        client_hash_status: str,
        storage_name: str,
        consent_version: str,
        metadata_consent_version: str,
        metadata_consent_decision: str,
        *,
        attachment_status: str = "ready",
        failure_code: str | None = None,
        duration_ms: int | None = None,
        width: int | None = None,
        height: int | None = None,
        video_codec: str | None = None,
        audio_codec: str | None = None,
        format_name: str | None = None,
        frame_rate: str | None = None,
        bit_rate: int | None = None,
        probe_summary_json: str | None = None,
        probed_at: str | None = None,
    ) -> tuple[str, str | None]:
        """Persist one video attachment row after durable promote.

        Returns ``saved`` and previous storage name, or ``sealed`` / ``missing`` /
        ``deleting`` like image assets. Does not write file bytes.
        """
        try:
            with self._transaction() as conn:
                owned = conn.execute(
                    "SELECT id FROM investigations WHERE id = ? AND owner_id = ?",
                    (investigation_id, owner_id),
                ).fetchone()
                if owned is None:
                    return "missing", None
                if _deletion_pending(conn, owner_id, investigation_id):
                    return "deleting", None
                previous = conn.execute(
                    """
                    SELECT storage_name, sha256, byte_length, retention, attachment_status
                    FROM video_assets WHERE investigation_id = ?
                    """,
                    (investigation_id,),
                ).fetchone()
                if previous is not None and previous["retention"] == "retiring":
                    return "deleting", None
                sealed = conn.execute(
                    """
                    SELECT id FROM assessment_snapshots
                    WHERE investigation_id = ? AND owner_id = ?
                    """,
                    (investigation_id, owner_id),
                ).fetchone()
                if sealed is not None:
                    return "sealed", None
                previous_name = previous["storage_name"] if previous else None
                if previous is not None and previous_name != storage_name:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO video_asset_cleanup (
                            storage_name, owner_id, investigation_id, sha256, byte_length,
                            reason, created_at
                        ) VALUES (?, ?, ?, ?, ?, 'replaced', ?)
                        """,
                        (
                            previous_name,
                            owner_id,
                            investigation_id,
                            previous["sha256"],
                            previous["byte_length"],
                            _now(),
                        ),
                    )
                conn.execute(
                    "DELETE FROM video_assets WHERE investigation_id = ?",
                    (investigation_id,),
                )
                received_at = _now()
                probed = probed_at or received_at
                conn.execute(
                    """
                    INSERT INTO video_assets (
                        id, investigation_id, owner_id, sha256, byte_length, media_type,
                        received_at, retention, client_hash_status, storage_name,
                        consent_version, metadata_consent_version, metadata_consent_decision,
                        metadata_consent_at, attachment_status, failure_code,
                        duration_ms, width, height, video_codec, audio_codec, format_name,
                        frame_rate, bit_rate, probe_summary_json, probed_at
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, 'retained', ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    (
                        asset_id,
                        investigation_id,
                        owner_id,
                        digest,
                        byte_length,
                        media_type,
                        received_at,
                        client_hash_status,
                        storage_name,
                        consent_version,
                        metadata_consent_version,
                        metadata_consent_decision,
                        received_at,
                        attachment_status,
                        failure_code,
                        duration_ms,
                        width,
                        height,
                        video_codec,
                        audio_codec,
                        format_name,
                        frame_rate,
                        bit_rate,
                        probe_summary_json,
                        probed,
                    ),
                )
        except sqlite3.Error as exc:
            raise LedgerError("The evidence ledger is unavailable.") from exc
        return "saved", previous_name

    def record_video_cleanup(
        self,
        owner_id: str,
        investigation_id: str,
        storage_name: str,
        digest: str,
        byte_length: int,
        reason: str,
    ) -> None:
        with self._transaction() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO video_asset_cleanup (
                    storage_name, owner_id, investigation_id, sha256, byte_length, reason, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (storage_name, owner_id, investigation_id, digest, byte_length, reason, _now()),
            )

    def finish_video_cleanup(self, storage_name: str) -> None:
        with self._transaction() as conn:
            conn.execute("DELETE FROM video_asset_cleanup WHERE storage_name = ?", (storage_name,))

    def set_video_attachment_status(
        self,
        owner_id: str,
        investigation_id: str,
        status: str,
        failure_code: str | None = None,
    ) -> bool:
        with self._transaction() as conn:
            cur = conn.execute(
                """
                UPDATE video_assets
                SET attachment_status = ?, failure_code = ?
                WHERE investigation_id = ? AND owner_id = ?
                """,
                (status, failure_code, investigation_id, owner_id),
            )
            return cur.rowcount > 0

    def prepare_account_deletion(self, user_id: str, password: str) -> str:
        """Block new uploads and snapshots before any image file is unlinked.

        The account-wide marker is committed even when the account has no
        image. When an image or cleanup row exists, its snapshots are removed
        in this same transaction and the image is marked ``retiring``. When
        none exist, snapshots stay until the final erasure removes them with
        the marker. A failed erasure rolls those snapshots back and leaves the
        marker, so upload and sealing stay refused. Returns the same status
        words as erasure.
        """
        try:
            with self._transaction() as conn:
                status = _password_status(conn, user_id, password)
                if status != "ok":
                    return status
                owned = "(SELECT id FROM investigations WHERE owner_id = ?)"
                images = conn.execute(
                    f"SELECT 1 FROM image_assets WHERE owner_id = ? OR investigation_id IN {owned} LIMIT 1",
                    (user_id, user_id),
                ).fetchone()
                cleanup = conn.execute(
                    f"SELECT 1 FROM asset_cleanup WHERE owner_id = ? OR investigation_id IN {owned} LIMIT 1",
                    (user_id, user_id),
                ).fetchone()
                videos = conn.execute(
                    f"SELECT 1 FROM video_assets WHERE owner_id = ? OR investigation_id IN {owned} LIMIT 1",
                    (user_id, user_id),
                ).fetchone()
                video_cleanup = conn.execute(
                    f"SELECT 1 FROM video_asset_cleanup WHERE owner_id = ? OR investigation_id IN {owned} LIMIT 1",
                    (user_id, user_id),
                ).fetchone()
                _mark_account_deletion(conn, user_id)
                if images is not None or cleanup is not None or videos is not None or video_cleanup is not None:
                    _retire_owner_assets(conn, user_id)
        except LedgerError:
            raise
        except sqlite3.Error as exc:
            raise LedgerError("The evidence ledger is unavailable.") from exc
        return "ok"

    def prepare_investigation_deletion(self, owner_id: str, investigation_id: str) -> bool:
        """Block new uploads and snapshots before this investigation's file is unlinked.

        The marker is committed even when the investigation has no image.
        Snapshots are removed in this transaction only when an image or
        cleanup row must be unlinked. Otherwise the final delete removes the
        snapshots and the marker together.
        """
        with self._transaction() as conn:
            row = conn.execute(
                "SELECT id FROM investigations WHERE id = ? AND owner_id = ?",
                (investigation_id, owner_id),
            ).fetchone()
            if row is None:
                return False
            images = conn.execute(
                "SELECT 1 FROM image_assets WHERE investigation_id = ? AND owner_id = ? LIMIT 1",
                (investigation_id, owner_id),
            ).fetchone()
            cleanup = conn.execute(
                """
                SELECT 1 FROM asset_cleanup
                WHERE investigation_id = ? AND owner_id = ? LIMIT 1
                """,
                (investigation_id, owner_id),
            ).fetchone()
            videos = conn.execute(
                "SELECT 1 FROM video_assets WHERE investigation_id = ? AND owner_id = ? LIMIT 1",
                (investigation_id, owner_id),
            ).fetchone()
            video_cleanup = conn.execute(
                """
                SELECT 1 FROM video_asset_cleanup
                WHERE investigation_id = ? AND owner_id = ? LIMIT 1
                """,
                (investigation_id, owner_id),
            ).fetchone()
            _mark_investigation_deletion(conn, owner_id, investigation_id)
            if images is not None or cleanup is not None or videos is not None or video_cleanup is not None:
                _retire_investigation_assets(conn, owner_id, investigation_id)
        return True

    def erase_account(self, user_id: str, password: str) -> str:
        """Delete one registered account and the records that belong to it.

        Returns ``ok``, ``rejected`` for a wrong password, ``missing`` when
        the id is not an account, or ``legacy`` when the row has no email or
        password hash. A legacy row and every other account are left in place.
        Any failure rolls the transaction back.
        """
        try:
            with self._transaction() as conn:
                row = conn.execute(
                    "SELECT email, password_hash FROM users WHERE id = ?",
                    (user_id,),
                ).fetchone()
                if row is None:
                    return "missing"
                if not row["email"] or not row["password_hash"]:
                    return "legacy"
                if not verify_password(row["password_hash"], password if isinstance(password, str) else ""):
                    return "rejected"
                owned = "(SELECT id FROM investigations WHERE owner_id = ?)"
                delete_graph_for_owner(conn, user_id)
                conn.execute(
                    f"""
                    DELETE FROM assessment_supersessions
                    WHERE owner_id = ?
                       OR investigation_id IN {owned}
                    """,
                    (user_id, user_id),
                )
                conn.execute(
                    f"""
                    DELETE FROM assessment_results
                    WHERE owner_id = ?
                       OR investigation_id IN {owned}
                    """,
                    (user_id, user_id),
                )
                conn.execute(
                    f"""
                    DELETE FROM assessment_snapshots
                    WHERE owner_id = ?
                       OR investigation_id IN {owned}
                    """,
                    (user_id, user_id),
                )
                conn.execute(
                    f"DELETE FROM image_assets WHERE owner_id = ? OR investigation_id IN {owned}",
                    (user_id, user_id),
                )
                conn.execute(
                    f"DELETE FROM asset_cleanup WHERE owner_id = ? OR investigation_id IN {owned}",
                    (user_id, user_id),
                )
                conn.execute(
                    f"DELETE FROM video_processing_runs WHERE owner_id = ? OR investigation_id IN {owned}",
                    (user_id, user_id),
                )
                conn.execute(
                    f"DELETE FROM video_assets WHERE owner_id = ? OR investigation_id IN {owned}",
                    (user_id, user_id),
                )
                conn.execute(
                    f"DELETE FROM video_asset_cleanup WHERE owner_id = ? OR investigation_id IN {owned}",
                    (user_id, user_id),
                )
                for table in ("evidence_sources", "page_fetches", "claim_analyses"):
                    conn.execute(
                        f"DELETE FROM {table} WHERE investigation_id IN {owned}",
                        (user_id,),
                    )
                conn.execute("DELETE FROM investigations WHERE owner_id = ?", (user_id,))
                conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
                conn.execute("DELETE FROM rate_limits WHERE subject = ?", (user_id,))
                conn.execute("DELETE FROM pending_deletions WHERE owner_id = ?", (user_id,))
                deleted = conn.execute(
                    """
                    DELETE FROM users
                    WHERE id = ? AND email IS NOT NULL AND password_hash IS NOT NULL
                    """,
                    (user_id,),
                )
                if deleted.rowcount != 1:
                    raise LedgerError("The evidence ledger is unavailable.")
        except LedgerError:
            raise
        except sqlite3.Error as exc:
            raise LedgerError("The evidence ledger is unavailable.") from exc
        return "ok"

    def delete_investigation(self, owner_id: str, investigation_id: str) -> bool:
        with self._transaction() as conn:
            row = conn.execute(
                "SELECT id FROM investigations WHERE id = ? AND owner_id = ?",
                (investigation_id, owner_id),
            ).fetchone()
            if row is None:
                return False
            delete_graph_for_investigation(conn, owner_id, investigation_id)
            conn.execute(
                "DELETE FROM assessment_supersessions WHERE investigation_id = ? AND owner_id = ?",
                (investigation_id, owner_id),
            )
            conn.execute(
                "DELETE FROM assessment_results WHERE investigation_id = ? AND owner_id = ?",
                (investigation_id, owner_id),
            )
            conn.execute("DELETE FROM assessment_snapshots WHERE investigation_id = ?", (investigation_id,))
            conn.execute("DELETE FROM image_assets WHERE investigation_id = ?", (investigation_id,))
            conn.execute("DELETE FROM asset_cleanup WHERE investigation_id = ?", (investigation_id,))
            conn.execute("DELETE FROM video_processing_runs WHERE investigation_id = ?", (investigation_id,))
            conn.execute("DELETE FROM video_assets WHERE investigation_id = ?", (investigation_id,))
            conn.execute("DELETE FROM video_asset_cleanup WHERE investigation_id = ?", (investigation_id,))
            conn.execute(
                """
                DELETE FROM pending_deletions
                WHERE owner_id = ? AND investigation_id = ?
                """,
                (owner_id, investigation_id),
            )
            conn.execute("DELETE FROM evidence_sources WHERE investigation_id = ?", (investigation_id,))
            conn.execute("DELETE FROM page_fetches WHERE investigation_id = ?", (investigation_id,))
            conn.execute("DELETE FROM claim_analyses WHERE investigation_id = ?", (investigation_id,))
            conn.execute(
                "DELETE FROM investigations WHERE id = ? AND owner_id = ?",
                (investigation_id, owner_id),
            )
        return True

    def _asset_files_consistent(self, conn: sqlite3.Connection) -> bool:
        """True when stored names, sizes, and digests match the asset directory."""
        root = self.path.parent / "assets"
        if root.is_symlink():
            return False
        expected: dict[str, tuple[str, int]] = {}
        for table in ("image_assets", "asset_cleanup"):
            for row in conn.execute(f"SELECT storage_name, sha256, byte_length FROM {table}"):
                expected[row["storage_name"]] = (row["sha256"], int(row["byte_length"]))
        if not root.exists():
            return not expected
        if _unexpected_asset_files(root):
            return False
        found: dict[str, Path] = {}
        for item in root.iterdir():
            if item.name.startswith("."):
                continue
            if item.is_symlink() or not item.is_file() or not item.name.endswith(".bin"):
                if item.name.endswith(".bin"):
                    return False
                continue
            found[item.name] = item
        if set(found) != set(expected):
            return False
        for name, (digest, length) in expected.items():
            path = found[name]
            try:
                if path.stat().st_size != length:
                    return False
                if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                    return False
            except OSError:
                return False
        return True


def _authorize_commit(authorize, provenance) -> None:
    """Reject a credential record that is not authorized at commit time.

    A policy requires a callback. A missing callback, a denial, and a
    callback exception raise ``LedgerError`` so the open write transaction
    rolls back. A null policy, including a technical failure, does not
    require a callback. This helper does not import the trust store.
    """
    if not isinstance(provenance, dict) or provenance.get("policy") is None:
        return
    if authorize is None:
        raise LedgerError("The evidence ledger is unavailable.", failure_code="trust_configuration")
    try:
        decision = authorize(provenance)
    except LedgerError:
        raise
    except Exception:
        raise LedgerError("The evidence ledger is unavailable.", failure_code="trust_configuration") from None
    if isinstance(decision, Mapping) and decision.get("ok") is True:
        return
    code = decision.get("failureCode") if isinstance(decision, Mapping) else None
    if not isinstance(code, str) or not code:
        code = "trust_configuration"
    raise LedgerError("The evidence ledger is unavailable.", failure_code=code)


def _password_status(conn: sqlite3.Connection, user_id: str, password: str) -> str:
    row = conn.execute(
        "SELECT email, password_hash FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    if row is None:
        return "missing"
    if not row["email"] or not row["password_hash"]:
        return "legacy"
    if not verify_password(row["password_hash"], password if isinstance(password, str) else ""):
        return "rejected"
    return "ok"


def _deletion_pending(conn: sqlite3.Connection, owner_id: str, investigation_id: str) -> bool:
    """True when this investigation, or the whole account, is already being deleted."""
    row = conn.execute(
        """
        SELECT 1 FROM pending_deletions
        WHERE owner_id = ? AND investigation_id IN (?, '')
        LIMIT 1
        """,
        (owner_id, investigation_id),
    ).fetchone()
    return row is not None


def _mark_account_deletion(conn: sqlite3.Connection, user_id: str) -> None:
    """Remember an account deletion until that account row is deleted.

    The empty investigation id covers every investigation of this owner,
    including one created after this row. The row is not removed if unlinking
    a file fails or the final erasure rolls back.
    """
    conn.execute(
        """
        INSERT OR IGNORE INTO pending_deletions (owner_id, investigation_id, created_at)
        VALUES (?, '', ?)
        """,
        (user_id, _now()),
    )


def _mark_investigation_deletion(conn: sqlite3.Connection, owner_id: str, investigation_id: str) -> None:
    """Remember one investigation deletion until that investigation is deleted."""
    conn.execute(
        """
        INSERT OR IGNORE INTO pending_deletions (owner_id, investigation_id, created_at)
        VALUES (?, ?, ?)
        """,
        (owner_id, investigation_id, _now()),
    )


def _retire_owner_assets(conn: sqlite3.Connection, user_id: str) -> None:
    owned = "(SELECT id FROM investigations WHERE owner_id = ?)"
    # Graph and assessment rows reference sealed snapshots; remove them first.
    delete_graph_for_owner(conn, user_id)
    conn.execute(
        f"""
        DELETE FROM assessment_supersessions
        WHERE owner_id = ? OR investigation_id IN {owned}
        """,
        (user_id, user_id),
    )
    conn.execute(
        f"""
        DELETE FROM assessment_results
        WHERE owner_id = ? OR investigation_id IN {owned}
        """,
        (user_id, user_id),
    )
    conn.execute(
        f"""
        DELETE FROM assessment_snapshots
        WHERE owner_id = ? OR investigation_id IN {owned}
        """,
        (user_id, user_id),
    )
    rows = conn.execute(
        f"""
        SELECT storage_name, owner_id, investigation_id, sha256, byte_length
        FROM image_assets
        WHERE owner_id = ? OR investigation_id IN {owned}
        """,
        (user_id, user_id),
    ).fetchall()
    for row in rows:
        conn.execute(
            """
            INSERT OR REPLACE INTO asset_cleanup (
                storage_name, owner_id, investigation_id, sha256, byte_length, reason, created_at
            ) VALUES (?, ?, ?, ?, ?, 'deleting', ?)
            """,
            (
                row["storage_name"],
                row["owner_id"],
                row["investigation_id"],
                row["sha256"],
                row["byte_length"],
                _now(),
            ),
        )
    conn.execute(
        f"""
        UPDATE image_assets SET retention = 'retiring'
        WHERE owner_id = ? OR investigation_id IN {owned}
        """,
        (user_id, user_id),
    )
    video_rows = conn.execute(
        f"""
        SELECT storage_name, owner_id, investigation_id, sha256, byte_length
        FROM video_assets
        WHERE owner_id = ? OR investigation_id IN {owned}
        """,
        (user_id, user_id),
    ).fetchall()
    for row in video_rows:
        conn.execute(
            """
            INSERT OR REPLACE INTO video_asset_cleanup (
                storage_name, owner_id, investigation_id, sha256, byte_length, reason, created_at
            ) VALUES (?, ?, ?, ?, ?, 'deleting', ?)
            """,
            (
                row["storage_name"],
                row["owner_id"],
                row["investigation_id"],
                row["sha256"],
                row["byte_length"],
                _now(),
            ),
        )
    conn.execute(
        f"""
        UPDATE video_assets
        SET retention = 'retiring', attachment_status = 'retiring'
        WHERE owner_id = ? OR investigation_id IN {owned}
        """,
        (user_id, user_id),
    )


def _retire_investigation_assets(conn: sqlite3.Connection, owner_id: str, investigation_id: str) -> None:
    # Graph and assessment rows reference sealed snapshots; remove them before snapshots.
    delete_graph_for_investigation(conn, owner_id, investigation_id)
    conn.execute(
        "DELETE FROM assessment_supersessions WHERE investigation_id = ? AND owner_id = ?",
        (investigation_id, owner_id),
    )
    conn.execute(
        "DELETE FROM assessment_results WHERE investigation_id = ? AND owner_id = ?",
        (investigation_id, owner_id),
    )
    conn.execute(
        "DELETE FROM assessment_snapshots WHERE investigation_id = ?",
        (investigation_id,),
    )
    rows = conn.execute(
        """
        SELECT storage_name, owner_id, investigation_id, sha256, byte_length
        FROM image_assets WHERE investigation_id = ? AND owner_id = ?
        """,
        (investigation_id, owner_id),
    ).fetchall()
    for row in rows:
        conn.execute(
            """
            INSERT OR REPLACE INTO asset_cleanup (
                storage_name, owner_id, investigation_id, sha256, byte_length, reason, created_at
            ) VALUES (?, ?, ?, ?, ?, 'deleting', ?)
            """,
            (
                row["storage_name"],
                row["owner_id"],
                row["investigation_id"],
                row["sha256"],
                row["byte_length"],
                _now(),
            ),
        )
    conn.execute(
        """
        UPDATE image_assets SET retention = 'retiring'
        WHERE investigation_id = ? AND owner_id = ?
        """,
        (investigation_id, owner_id),
    )
    video_rows = conn.execute(
        """
        SELECT storage_name, owner_id, investigation_id, sha256, byte_length
        FROM video_assets WHERE investigation_id = ? AND owner_id = ?
        """,
        (investigation_id, owner_id),
    ).fetchall()
    for row in video_rows:
        conn.execute(
            """
            INSERT OR REPLACE INTO video_asset_cleanup (
                storage_name, owner_id, investigation_id, sha256, byte_length, reason, created_at
            ) VALUES (?, ?, ?, ?, ?, 'deleting', ?)
            """,
            (
                row["storage_name"],
                row["owner_id"],
                row["investigation_id"],
                row["sha256"],
                row["byte_length"],
                _now(),
            ),
        )
    conn.execute(
        """
        UPDATE video_assets
        SET retention = 'retiring', attachment_status = 'retiring'
        WHERE investigation_id = ? AND owner_id = ?
        """,
        (investigation_id, owner_id),
    )


def _referenced_storage_names(conn: sqlite3.Connection) -> set[str]:
    names = set()
    for table in ("image_assets", "asset_cleanup"):
        try:
            rows = conn.execute(f"SELECT storage_name FROM {table}").fetchall()
        except sqlite3.Error:
            continue
        names.update(row["storage_name"] for row in rows)
    return names


def _referenced_video_storage_names(conn: sqlite3.Connection) -> set[str]:
    names = set()
    for table in ("video_assets", "video_asset_cleanup"):
        try:
            rows = conn.execute(f"SELECT storage_name FROM {table}").fetchall()
        except sqlite3.Error:
            continue
        names.update(row["storage_name"] for row in rows if row["storage_name"])
    return names


def _video_verify_rows(conn: sqlite3.Connection) -> list[tuple[str, str, int]]:
    try:
        rows = conn.execute(
            """
            SELECT storage_name, sha256, byte_length FROM video_assets
            WHERE attachment_status IN ('ready', 'missing', 'integrity_failed')
            """
        ).fetchall()
    except sqlite3.Error:
        return []
    return [
        (row["storage_name"], row["sha256"], int(row["byte_length"]))
        for row in rows
    ]


def _same_sealed_asset(previous: dict, row) -> bool:
    return (
        previous["id"] == row["id"]
        and previous["sha256"] == row["sha256"]
        and int(previous["byte_length"]) == int(row["byte_length"])
        and previous["storage_name"] == row["storage_name"]
        and previous["owner_id"] == row["owner_id"]
        and previous["consent_version"] == row["consent_version"]
        and previous["metadata_consent_version"] == row["metadata_consent_version"]
        and previous["metadata_consent_decision"] == row["metadata_consent_decision"]
        and previous["metadata_consent_at"] == row["metadata_consent_at"]
        and previous["retention"] == row["retention"]
    )


def _read_asset_buffer(path: Path, byte_length: int) -> bytes | None:
    """Read one regular file into the buffer whose length is checked.

    The file is opened without following a symlink. A size other than
    ``byte_length`` is rejected before the read. One extra byte after that
    length means the file changed during the read.
    """
    if isinstance(byte_length, bool) or not isinstance(byte_length, int) or byte_length < 0:
        return None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size != byte_length:
            return None
        handle = os.fdopen(descriptor, "rb", closefd=True)
        descriptor = -1
        with handle:
            data = handle.read(byte_length)
            if len(data) != byte_length or handle.read(1):
                return None
            return data
    except OSError:
        return None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _buffer_matches(data: bytes | None, digest: str, byte_length: int) -> bool:
    if data is None or len(data) != byte_length:
        return False
    return hashlib.sha256(data).hexdigest() == digest


def _read_matching_asset(path: Path, digest: str, byte_length: int) -> bytes:
    """Return the one buffer whose length and SHA-256 match the asset row."""
    data = _read_asset_buffer(path, byte_length)
    if not _buffer_matches(data, digest, byte_length):
        raise LedgerError("The evidence ledger is unavailable.")
    return data


def _asset_file_matches(path: Path, digest: str, byte_length: int) -> bool:
    return _buffer_matches(_read_asset_buffer(path, byte_length), digest, byte_length)


def _unexpected_asset_files(root: Path) -> bool:
    """True when a partial, intent, or quarantined file still needs attention."""
    quarantine = root / ".quarantine"
    if quarantine.is_dir() and not quarantine.is_symlink() and any(quarantine.iterdir()):
        return True
    intent = root / ".intent"
    if intent.is_dir() and not intent.is_symlink() and any(intent.iterdir()):
        return True
    for item in root.iterdir():
        if item.name.endswith(".partial"):
            return True
    return False


def _is_past(value: str) -> bool:
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return True
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) >= moment


def _migrate(conn: sqlite3.Connection) -> None:
    """Add account columns to a ledger created before authentication.

    This does not delete investigations and does not attach old anonymous
    owner rows to a new account. Phase A assessment tables are created by
    schema.sql via CREATE TABLE IF NOT EXISTS when the ledger opens.
    """
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "email" not in columns:
        conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
    if "password_hash" not in columns:
        conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_email ON users(email) WHERE email IS NOT NULL")
    asset_columns = {row["name"] for row in conn.execute("PRAGMA table_info(image_assets)").fetchall()}
    if asset_columns and "consent_version" not in asset_columns:
        conn.execute("ALTER TABLE image_assets ADD COLUMN consent_version TEXT")
    for column in ("metadata_consent_version", "metadata_consent_decision", "metadata_consent_at"):
        if asset_columns and column not in asset_columns:
            conn.execute(f"ALTER TABLE image_assets ADD COLUMN {column} TEXT")
    # Composite uniqueness for Phase A ownership foreign keys (idempotent).
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS investigations_id_owner ON investigations(id, owner_id)"
    )
    conn.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS assessment_snapshots_id_inv_owner
        ON assessment_snapshots(id, investigation_id, owner_id)
        """
    )
    # Recreate certainty trigger so existing ledgers pick up PUBLISHED_AT /
    # CONFIRMED allow-list rules (CREATE TRIGGER IF NOT EXISTS is a no-op).
    conn.execute("DROP TRIGGER IF EXISTS evidence_edges_certainty_policy")
    conn.execute(
        """
        CREATE TRIGGER evidence_edges_certainty_policy
        BEFORE INSERT ON evidence_edges
        BEGIN
            SELECT RAISE(ABORT, 'invalid certainty for relationship')
            WHERE
                (NEW.rel_type = 'PUBLISHED_AT' AND NEW.certainty = 'CONFIRMED')
                OR (
                    NEW.certainty = 'CONFIRMED'
                    AND NEW.method NOT IN (
                        'system_structural',
                        'system_clock',
                        'system_supersession',
                        'system_literal_alignment'
                    )
                );
        END
        """
    )


OFFICIAL_ASSESSMENT_OUTCOMES = frozenset({
    "VERIFIED",
    "PARTIALLY_VERIFIED",
    "CONTRADICTED",
    "INSUFFICIENT_EVIDENCE",
    "POTENTIAL_MANIPULATION",
    "UNRESOLVED",
})

# Safe catalog only. Never store raw provider HTTP bodies or secrets.
ASSESSMENT_FAILURE_CATALOG = {
    "no_model": "The analysis model is unavailable.",
    "upstream_error": "The analysis model could not complete this request.",
    "server_unavailable": "The analysis model did not respond in time.",
    "persist_failed": "The assessment could not be saved.",
    "unknown": "The assessment could not be completed.",
}


def assessment_failure_message(code: str | None) -> str:
    if not isinstance(code, str) or not code:
        return ASSESSMENT_FAILURE_CATALOG["unknown"]
    return ASSESSMENT_FAILURE_CATALOG.get(code, ASSESSMENT_FAILURE_CATALOG["unknown"])


def _asset_record(row: sqlite3.Row) -> dict:
    return {
        "assetId": row["id"],
        "investigationId": row["investigation_id"],
        "ownerId": row["owner_id"],
        "sha256": row["sha256"],
        "byteLength": row["byte_length"],
        "mediaType": row["media_type"],
        "receivedAt": row["received_at"],
        "retention": row["retention"],
        "clientHashStatus": row["client_hash_status"],
        "consentVersion": row["consent_version"],
        "metadataConsentVersion": row["metadata_consent_version"] or "declined",
        "metadataConsentDecision": row["metadata_consent_decision"] or "omitted",
        "metadataConsentAt": row["metadata_consent_at"] or "",
        "storageName": row["storage_name"],
    }


def _video_record(row: sqlite3.Row) -> dict:
    return {
        "videoAssetId": row["id"],
        "investigationId": row["investigation_id"],
        "ownerId": row["owner_id"],
        "sha256": row["sha256"],
        "byteLength": row["byte_length"],
        "mediaType": row["media_type"],
        "receivedAt": row["received_at"],
        "retention": row["retention"],
        "clientHashStatus": row["client_hash_status"],
        "consentVersion": row["consent_version"],
        "metadataConsentVersion": row["metadata_consent_version"] or "declined",
        "metadataConsentDecision": row["metadata_consent_decision"] or "omitted",
        "metadataConsentAt": row["metadata_consent_at"] or "",
        "attachmentStatus": row["attachment_status"],
        "failureCode": row["failure_code"],
        "durationMs": row["duration_ms"],
        "width": row["width"],
        "height": row["height"],
        "videoCodec": row["video_codec"],
        "audioCodec": row["audio_codec"],
        "formatName": row["format_name"],
        "frameRate": row["frame_rate"],
        "bitRate": row["bit_rate"],
        "storageName": row["storage_name"],
    }


def _sealed_video_identity(
    row: sqlite3.Row,
    *,
    verified_sha256: str,
    verified_byte_length: int,
    sealed_at: str,
) -> dict:
    """Compact, path-free video identity for ``snapshot_json``.

    Contains verified identity and probe metadata only. Never includes
    media bytes, storage names, filesystem paths, or raw probe JSON.
    Does not assert authenticity.
    """
    return {
        "schemaVersion": "1",
        "assetId": row["id"],
        "sha256": verified_sha256,
        "byteLength": verified_byte_length,
        "mediaType": row["media_type"],
        "receivedAt": row["received_at"],
        "retention": row["retention"],
        "clientHashStatus": row["client_hash_status"],
        "consentVersion": row["consent_version"],
        "metadataConsentVersion": row["metadata_consent_version"] or "declined",
        "metadataConsentDecision": row["metadata_consent_decision"] or "omitted",
        "attachmentStatus": "ready",
        "durationMs": row["duration_ms"],
        "width": row["width"],
        "height": row["height"],
        "videoCodec": row["video_codec"],
        "audioCodec": row["audio_codec"],
        "formatName": row["format_name"],
        "frameRate": row["frame_rate"],
        "bitRate": row["bit_rate"],
        "sealedAt": sealed_at,
    }


def _source_dict(source_id: str, position: int, source: dict) -> dict:
    quality = source.get("quality") or {}
    return {
        "id": source_id,
        "url": source.get("url") or "",
        "title": source.get("title"),
        "snippet": source.get("snippet") or "",
        "publishedAt": source.get("publishedAt"),
        "dateCertainty": source.get("dateCertainty"),
        "dateType": source.get("dateType"),
        "provider": source.get("provider"),
        "quality": {"tier": quality.get("tier") or "UNKNOWN", "reason": quality.get("reason") or ""},
        "position": position,
    }
