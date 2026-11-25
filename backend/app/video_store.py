"""Private durable storage for uploaded video evidence.

Bytes live under ``{ledger_dir}/assets/video/``, never inside SQLite.
Names are server-generated. Paths are not returned to API callers.

Filesystem rename and SQLite commit are not one atomic operation: durable
``.intent`` markers and ``video_asset_cleanup`` rows bridge the gap
(see V1.2.2B ordering).
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import stat
import time
from pathlib import Path

from app.ledger import LedgerError, inside_project_data, protecting_tests

STORAGE_NAME = re.compile(r"[0-9a-f]{32}\.bin")
ASSET_ID = re.compile(r"[0-9a-f]{32}")
UPLOAD_ID = re.compile(r"[0-9a-f]{16,32}")

# Quarantine retention: 30 days, subject to the smaller of 5 GiB or 5% free volume.
QUARANTINE_RETENTION_SECONDS = 30 * 24 * 60 * 60
QUARANTINE_MAX_BYTES = 5 * 1024 * 1024 * 1024
QUARANTINE_MAX_FREE_FRACTION = 0.05


class VideoStoreError(Exception):
    """A video file could not be written or removed. The message is generic."""


class VideoStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        if protecting_tests() and inside_project_data(self.root):
            raise LedgerError("The evidence ledger is unavailable.")
        self._prepare()

    @classmethod
    def for_ledger(cls, ledger_file: Path) -> "VideoStore":
        return cls(Path(ledger_file).parent / "assets" / "video")

    def _prepare(self) -> None:
        if self.root.is_symlink():
            raise VideoStoreError("The video could not be stored.")
        try:
            self.root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise VideoStoreError("The video could not be stored.") from exc
        if self.root.is_symlink() or not self.root.is_dir():
            raise VideoStoreError("The video could not be stored.")
        try:
            os.chmod(self.root, 0o700)
        except OSError as exc:
            raise VideoStoreError("The video could not be stored.") from exc
        for name in (".partial", ".intent", ".pending", ".quarantine", ".scratch", ".locks"):
            self._private_dir(name)

    def partial_dir(self) -> Path:
        return self._private_dir(".partial")

    def scratch_dir(self) -> Path:
        return self._private_dir(".scratch")

    def open_partial(self, upload_id: str) -> Path:
        if UPLOAD_ID.fullmatch(upload_id) is None:
            raise VideoStoreError("The video could not be stored.")
        directory = self.partial_dir()
        path = directory / (upload_id + ".part")
        if path.is_symlink() or path.parent != directory:
            raise VideoStoreError("The video could not be stored.")
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except OSError as exc:
            raise VideoStoreError("The video could not be stored.") from exc
        os.close(fd)
        return path

    def append_partial(self, partial: Path, chunk: bytes) -> None:
        if partial.is_symlink() or partial.parent != self.partial_dir():
            raise VideoStoreError("The video could not be stored.")
        try:
            fd = os.open(partial, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
        except OSError as exc:
            raise VideoStoreError("The video could not be stored.") from exc
        try:
            self._write_all(fd, chunk)
        except (OSError, VideoStoreError) as exc:
            os.close(fd)
            raise VideoStoreError("The video could not be stored.") from exc
        os.close(fd)

    def fsync_partial(self, partial: Path) -> int:
        if partial.is_symlink() or partial.parent != self.partial_dir():
            raise VideoStoreError("The video could not be stored.")
        try:
            fd = os.open(partial, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as exc:
            raise VideoStoreError("The video could not be stored.") from exc
        try:
            os.fsync(fd)
            size = os.fstat(fd).st_size
        except OSError as exc:
            os.close(fd)
            raise VideoStoreError("The video could not be stored.") from exc
        os.close(fd)
        return int(size)

    def sha256_file(self, path: Path) -> str:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()

    def unlink_partial(self, partial: Path) -> None:
        if partial.parent != self.partial_dir():
            return
        self._unlink_quiet(partial)

    def record_intent(
        self,
        storage_name: str,
        owner_id: str,
        investigation_id: str,
        digest: str,
        byte_length: int,
    ) -> None:
        if STORAGE_NAME.fullmatch(storage_name) is None:
            raise VideoStoreError("The video could not be stored.")
        directory = self._private_dir(".intent")
        marker = directory / storage_name
        if marker.is_symlink() or marker.parent != directory:
            raise VideoStoreError("The video could not be stored.")
        payload = (
            str(owner_id) + "\n" + str(investigation_id) + "\n"
            + str(digest) + "\n" + str(int(byte_length)) + "\n"
        ).encode()
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        try:
            self._write_all(fd, payload)
            os.fsync(fd)
        except (OSError, VideoStoreError):
            os.close(fd)
            raise VideoStoreError("The video could not be stored.")
        os.close(fd)
        self._fsync_directory(directory)

    def finish_intent(self, storage_name: str) -> None:
        self._remove_marker(self.root / ".intent", storage_name)

    def promote_partial(
        self,
        partial: Path,
        asset_id: str,
        *,
        owner_id: str,
        investigation_id: str,
        digest: str,
        byte_length: int,
    ) -> str:
        """Intent then replace partial → ``{asset_id}.bin``. Returns storage_name."""
        if ASSET_ID.fullmatch(asset_id) is None:
            raise VideoStoreError("The video could not be stored.")
        if partial.is_symlink() or partial.parent != self.partial_dir():
            raise VideoStoreError("The video could not be stored.")
        storage_name = asset_id + ".bin"
        target = self._path(storage_name)
        size = self.fsync_partial(partial)
        if size != byte_length:
            raise VideoStoreError("The video could not be stored.")
        actual = self.sha256_file(partial)
        if actual != digest:
            raise VideoStoreError("The video could not be stored.")
        self.record_intent(storage_name, owner_id, investigation_id, digest, byte_length)
        try:
            os.replace(partial, target)
            os.chmod(target, 0o600)
            self._fsync_directory(self.root)
            if target.is_symlink() or target.stat().st_size != byte_length:
                raise VideoStoreError("The video could not be stored.")
        except (OSError, VideoStoreError) as exc:
            self._unlink_quiet(partial)
            if target.exists() and not self._unlink_quiet(target):
                self.note_pending(storage_name, owner_id, investigation_id)
            raise VideoStoreError("The video could not be stored.") from exc
        return storage_name

    def path_for(self, storage_name: str) -> Path:
        return self._path(storage_name)

    def exists(self, storage_name: str) -> bool:
        try:
            path = self._path(storage_name)
        except VideoStoreError:
            return False
        return path.is_file() and not path.is_symlink()

    def verify_file(self, storage_name: str, digest: str, byte_length: int) -> bool:
        """Return True when the stored object is a regular file matching digest/size.

        Opens with ``O_NOFOLLOW`` so a symlink cannot redirect verification.
        Streams the full SHA-256; does not load the whole file into memory.
        """
        try:
            path = self._path(storage_name)
        except VideoStoreError:
            return False
        return self.verify_path(path, digest, byte_length)

    def verify_path(self, path: Path, digest: str, byte_length: int) -> bool:
        """Hash one regular file under this store without following symlinks."""
        if isinstance(byte_length, bool) or not isinstance(byte_length, int) or byte_length < 0:
            return False
        if not isinstance(digest, str) or len(digest) != 64:
            return False
        try:
            digest.encode("ascii")
            int(digest, 16)
        except (UnicodeEncodeError, ValueError):
            return False
        try:
            if path.is_symlink():
                return False
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            return False
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size != byte_length:
                return False
            hasher = hashlib.sha256()
            remaining = byte_length
            while remaining > 0:
                chunk = os.read(fd, min(1024 * 1024, remaining))
                if not chunk:
                    return False
                hasher.update(chunk)
                remaining -= len(chunk)
            if os.read(fd, 1):
                return False
            info_after = os.fstat(fd)
            if info_after.st_size != byte_length:
                return False
            return hasher.hexdigest() == digest.lower()
        except OSError:
            return False
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

    def remove(self, storage_name: str) -> bool:
        return self.remove_report(storage_name) != "failed"

    def remove_report(self, storage_name: str) -> str:
        try:
            path = self._path(storage_name)
        except VideoStoreError:
            return "failed"
        if path.is_symlink():
            return "failed"
        existed = path.exists()
        try:
            path.unlink()
        except FileNotFoundError:
            return "missing"
        except OSError:
            return "failed"
        if path.exists():
            return "failed"
        self.clear_pending(storage_name)
        return "removed" if existed else "missing"

    def note_pending(self, storage_name: str, owner_id: str, investigation_id: str) -> None:
        if STORAGE_NAME.fullmatch(storage_name) is None:
            raise VideoStoreError("The video could not be stored.")
        directory = self._private_dir(".pending")
        marker = directory / storage_name
        if marker.is_symlink() or marker.parent != directory:
            raise VideoStoreError("The video could not be stored.")
        payload = (str(owner_id) + "\n" + str(investigation_id) + "\n").encode()
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        try:
            self._write_all(fd, payload)
            os.fsync(fd)
        except (OSError, VideoStoreError):
            os.close(fd)
            raise VideoStoreError("The video could not be stored.")
        os.close(fd)
        self._fsync_directory(directory)

    def clear_pending(self, storage_name: str) -> None:
        directory = self.root / ".pending"
        if STORAGE_NAME.fullmatch(storage_name) is None or not directory.is_dir():
            return
        marker = directory / storage_name
        if marker.parent != directory or marker.is_symlink():
            return
        try:
            marker.unlink()
        except FileNotFoundError:
            return
        except OSError:
            return

    def try_acquire_upload_lock(self, owner_id: str):
        """Cross-process exclusive lock for one owner's video upload.

        Returns a lock handle that must be released with ``release_upload_lock``,
        or None when another process/thread already holds the lock.
        Uses ``fcntl.flock`` so a crashed holder releases automatically.

        Topology: safe for multiple workers on **one host** sharing a local
        filesystem with working POSIX flock semantics. This is **not** a
        distributed multi-host lock; do not run concurrent video uploads for
        the same owner across hosts without an external coordination layer.
        """
        if not isinstance(owner_id, str) or not owner_id or len(owner_id) > 80:
            raise VideoStoreError("The video could not be stored.")
        if "/" in owner_id or ".." in owner_id or owner_id.startswith("."):
            raise VideoStoreError("The video could not be stored.")
        directory = self._private_dir(".locks")
        safe = re.sub(r"[^0-9a-fA-F-]", "", owner_id)[:64]
        if not safe:
            raise VideoStoreError("The video could not be stored.")
        path = directory / (safe + ".lock")
        if path.parent != directory or path.is_symlink():
            raise VideoStoreError("The video could not be stored.")
        try:
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        except OSError as exc:
            raise VideoStoreError("The video could not be stored.") from exc
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            return None
        except OSError:
            os.close(fd)
            raise VideoStoreError("The video could not be stored.")
        try:
            os.ftruncate(fd, 0)
            payload = (str(os.getpid()) + "\n" + str(int(time.time())) + "\n").encode()
            os.write(fd, payload)
            os.fsync(fd)
        except OSError:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(fd)
            raise VideoStoreError("The video could not be stored.")
        return (fd, path)

    def release_upload_lock(self, handle) -> None:
        if handle is None:
            return
        fd, _path = handle
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            os.close(fd)
        except OSError:
            pass

    def quarantine_size_bytes(self) -> int:
        directory = self.root / ".quarantine"
        if not directory.is_dir() or directory.is_symlink():
            return 0
        total = 0
        for item in directory.iterdir():
            if item.is_symlink() or not item.is_file():
                continue
            try:
                total += item.stat().st_size
            except OSError:
                continue
        return total

    def _path(self, storage_name: str) -> Path:
        if STORAGE_NAME.fullmatch(storage_name) is None:
            raise VideoStoreError("The video could not be stored.")
        candidate = self.root / storage_name
        if candidate.parent != self.root:
            raise VideoStoreError("The video could not be stored.")
        if candidate.is_symlink():
            raise VideoStoreError("The video could not be stored.")
        return candidate

    def _private_dir(self, name: str) -> Path:
        directory = self.root / name
        if directory.is_symlink():
            raise VideoStoreError("The video could not be stored.")
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
        self._fsync_directory(self.root)
        return directory

    def _remove_marker(self, directory: Path, storage_name: str) -> None:
        if STORAGE_NAME.fullmatch(storage_name) is None or not directory.is_dir() or directory.is_symlink():
            return
        marker = directory / storage_name
        if marker.parent != directory or marker.is_symlink():
            raise VideoStoreError("The video could not be stored.")
        try:
            marker.unlink()
        except FileNotFoundError:
            return
        self._fsync_directory(directory)

    def _fsync_directory(self, directory: Path) -> None:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        except OSError as exc:
            raise VideoStoreError("The video could not be stored.") from exc
        finally:
            os.close(fd)

    def _write_all(self, fd: int, data: bytes) -> None:
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            written = os.write(fd, view[offset:])
            if written <= 0:
                raise VideoStoreError("The video could not be stored.")
            offset += written

    def _unlink_quiet(self, path: Path) -> bool:
        try:
            path.unlink()
        except FileNotFoundError:
            return True
        except OSError:
            return False
        return not path.exists()


def reconcile_video_assets(
    root: Path,
    referenced: set[str],
    *,
    mark_missing=None,
    mark_integrity_failed=None,
    verify_rows: list[tuple[str, str, int]] | None = None,
) -> dict:
    """Make incomplete video files recoverable without dropping attachment rows.

    - Deletes all ``.partial`` files (uploads do not survive process restart).
    - Clears ``.scratch``.
    - Intent without a DB row: delete published ``.bin`` and intent.
    - Intent with a DB row: finish intent marker only.
    - Orphan ``.bin`` (no row, no intent): move to ``.quarantine``.
    - Optional ``verify_rows``: (storage_name, sha256, byte_length) — missing
      file calls ``mark_missing``; mismatch calls ``mark_integrity_failed``.
      Rows are never auto-deleted here (V1.2.2E).

    Safe to run again. Does not open the live ledger.
    """
    root = Path(root)
    summary = {
        "partials_removed": 0,
        "intents_finished": 0,
        "intents_orphans_removed": 0,
        "quarantined": 0,
        "marked_missing": 0,
        "marked_integrity_failed": 0,
    }
    if not root.exists() or root.is_symlink() or not root.is_dir():
        return summary

    partial_dir = root / ".partial"
    if partial_dir.is_dir() and not partial_dir.is_symlink():
        for partial in list(partial_dir.iterdir()):
            if partial.is_symlink() or not partial.is_file():
                continue
            if not partial.name.endswith(".part"):
                continue
            try:
                partial.unlink()
                summary["partials_removed"] += 1
            except OSError:
                continue

    scratch = root / ".scratch"
    if scratch.is_dir() and not scratch.is_symlink():
        for item in list(scratch.iterdir()):
            try:
                if item.is_dir() and not item.is_symlink():
                    for child in item.iterdir():
                        try:
                            child.unlink()
                        except OSError:
                            pass
                    item.rmdir()
                elif item.is_file() and not item.is_symlink():
                    item.unlink()
            except OSError:
                continue

    intent_dir = root / ".intent"
    if intent_dir.is_dir() and not intent_dir.is_symlink():
        for marker in list(intent_dir.iterdir()):
            if marker.is_symlink() or not marker.is_file():
                continue
            if STORAGE_NAME.fullmatch(marker.name) is None:
                continue
            if marker.name in referenced:
                try:
                    marker.unlink()
                    summary["intents_finished"] += 1
                except OSError:
                    continue
                continue
            published = root / marker.name
            if published.is_file() and not published.is_symlink():
                try:
                    published.unlink()
                except OSError:
                    pass
            try:
                marker.unlink()
                summary["intents_orphans_removed"] += 1
            except OSError:
                continue

    for item in list(root.iterdir()):
        if item.name.startswith(".") or not item.name.endswith(".bin"):
            continue
        if item.is_symlink() or not item.is_file():
            continue
        if item.name in referenced:
            continue
        # Skip if intent still present (handled above); orphan publish.
        quarantine = root / ".quarantine"
        try:
            quarantine.mkdir(parents=True, exist_ok=True)
            os.chmod(quarantine, 0o700)
        except OSError:
            continue
        destination = quarantine / item.name
        if destination.exists():
            continue
        try:
            os.replace(item, destination)
            os.chmod(destination, 0o600)
            summary["quarantined"] += 1
        except OSError:
            continue

    if verify_rows:
        store = VideoStore(root)
        for storage_name, digest, byte_length in verify_rows:
            if storage_name not in referenced:
                continue
            path_ok = store.exists(storage_name)
            if not path_ok:
                if mark_missing:
                    mark_missing(storage_name)
                    summary["marked_missing"] += 1
                continue
            if not store.verify_file(storage_name, digest, byte_length):
                if mark_integrity_failed:
                    mark_integrity_failed(storage_name)
                    summary["marked_integrity_failed"] += 1

    return summary


def purge_video_quarantine(root: Path) -> dict:
    """Expire or shrink ``.quarantine`` under the approved retention/size caps."""
    root = Path(root)
    summary = {"expired": 0, "trimmed": 0, "bytes_removed": 0}
    quarantine = root / ".quarantine"
    if not quarantine.is_dir() or quarantine.is_symlink():
        return summary
    now = time.time()
    entries: list[tuple[float, int, Path]] = []
    for item in quarantine.iterdir():
        if item.is_symlink() or not item.is_file():
            continue
        try:
            st = item.stat()
        except OSError:
            continue
        age = now - st.st_mtime
        if age > QUARANTINE_RETENTION_SECONDS:
            try:
                size = st.st_size
                item.unlink()
                summary["expired"] += 1
                summary["bytes_removed"] += size
            except OSError:
                continue
            continue
        entries.append((st.st_mtime, st.st_size, item))

    total = sum(size for _mtime, size, _path in entries)
    cap = QUARANTINE_MAX_BYTES
    try:
        usage = os.statvfs(quarantine)
        free = usage.f_bavail * usage.f_frsize
        fraction_cap = int(free * QUARANTINE_MAX_FREE_FRACTION)
        if fraction_cap > 0:
            cap = min(cap, fraction_cap)
    except OSError:
        pass
    if total <= cap:
        return summary
    entries.sort(key=lambda row: row[0])
    for _mtime, size, path in entries:
        if total <= cap:
            break
        try:
            path.unlink()
        except OSError:
            continue
        total -= size
        summary["trimmed"] += 1
        summary["bytes_removed"] += size
    return summary
