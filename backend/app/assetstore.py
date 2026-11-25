"""Private files for sealed image identity.

Bytes live beside the ledger, never inside it. Names are server-generated.
Paths are not returned to callers.
"""

import hashlib
import os
import re
from pathlib import Path

from app.ledger import LedgerError, inside_project_data, protecting_tests

STORAGE_NAME = re.compile(r"[0-9a-f]{32}\.bin")
ASSET_ID = re.compile(r"[0-9a-f]{32}")


class AssetStoreError(Exception):
    """A stored image could not be written or removed. The message is generic."""


class AssetStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        if protecting_tests() and inside_project_data(self.root):
            raise LedgerError("The evidence ledger is unavailable.")
        self._prepare()

    @classmethod
    def for_ledger(cls, ledger_file: Path) -> "AssetStore":
        return cls(Path(ledger_file).parent / "assets")

    def _prepare(self) -> None:
        if self.root.is_symlink():
            raise AssetStoreError("The image could not be stored.")
        try:
            self.root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise AssetStoreError("The image could not be stored.") from exc
        if self.root.is_symlink() or not self.root.is_dir():
            raise AssetStoreError("The image could not be stored.")
        try:
            os.chmod(self.root, 0o700)
        except OSError as exc:
            raise AssetStoreError("The image could not be stored.") from exc

    def _path(self, storage_name: str) -> Path:
        if STORAGE_NAME.fullmatch(storage_name) is None:
            raise AssetStoreError("The image could not be stored.")
        candidate = self.root / storage_name
        if candidate.parent != self.root:
            raise AssetStoreError("The image could not be stored.")
        if candidate.is_symlink():
            raise AssetStoreError("The image could not be stored.")
        return candidate

    def write(
        self,
        asset_id: str,
        data: bytes,
        *,
        owner_id: str = "",
        investigation_id: str = "",
    ) -> str:
        if ASSET_ID.fullmatch(asset_id) is None:
            raise AssetStoreError("The image could not be stored.")
        self._prepare()
        storage_name = asset_id + ".bin"
        target = self._path(storage_name)
        partial = self.root / ("." + asset_id + ".partial")
        if partial.is_symlink() or partial.parent != self.root:
            raise AssetStoreError("The image could not be stored.")
        try:
            fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except OSError as exc:
            raise AssetStoreError("The image could not be stored.") from exc
        try:
            self._write_all(fd, data)
            os.fsync(fd)
        except (OSError, AssetStoreError) as exc:
            os.close(fd)
            self._unlink_quiet(partial)
            raise AssetStoreError("The image could not be stored.") from exc
        os.close(fd)
        try:
            os.chmod(partial, 0o600)
            if partial.stat().st_size != len(data):
                raise AssetStoreError("The image could not be stored.")
            digest = hashlib.sha256(data).hexdigest()
            self.record_intent(storage_name, owner_id, investigation_id, digest, len(data))
            os.replace(partial, target)
            os.chmod(target, 0o600)
            self._fsync_directory(self.root)
            if target.is_symlink() or target.stat().st_size != len(data):
                raise AssetStoreError("The image could not be stored.")
        except (OSError, AssetStoreError) as exc:
            self._unlink_quiet(partial)
            if target.exists() and not self._unlink_quiet(target):
                self.note_pending(storage_name, owner_id, investigation_id)
            raise AssetStoreError("The image could not be stored.") from exc
        return storage_name

    def remove(self, storage_name: str) -> bool:
        """Delete one stored file. True when it is gone. False when it remains."""
        return self.remove_report(storage_name) != "failed"

    def remove_report(self, storage_name: str) -> str:
        """Return ``removed``, ``missing``, or ``failed``."""
        try:
            path = self._path(storage_name)
        except AssetStoreError:
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
        """Remember a file that still has to be deleted.

        A failure is raised. The name is not dropped on the floor.
        """
        if STORAGE_NAME.fullmatch(storage_name) is None:
            raise AssetStoreError("The image could not be stored.")
        directory = self._pending_dir()
        marker = directory / storage_name
        if marker.is_symlink() or marker.parent != directory:
            raise AssetStoreError("The image could not be stored.")
        payload = (str(owner_id) + "\n" + str(investigation_id) + "\n").encode()
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        try:
            self._write_all(fd, payload)
            os.fsync(fd)
        except (OSError, AssetStoreError):
            os.close(fd)
            raise AssetStoreError("The image could not be stored.")
        os.close(fd)
        self._fsync_directory(directory)

    def record_intent(
        self,
        storage_name: str,
        owner_id: str,
        investigation_id: str,
        digest: str,
        byte_length: int,
    ) -> None:
        """Record an image before its final filename is visible."""
        if STORAGE_NAME.fullmatch(storage_name) is None:
            raise AssetStoreError("The image could not be stored.")
        directory = self._intent_dir()
        marker = directory / storage_name
        if marker.is_symlink() or marker.parent != directory:
            raise AssetStoreError("The image could not be stored.")
        payload = (
            str(owner_id) + "\n" + str(investigation_id) + "\n"
            + str(digest) + "\n" + str(int(byte_length)) + "\n"
        ).encode()
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        try:
            self._write_all(fd, payload)
            os.fsync(fd)
        except (OSError, AssetStoreError):
            os.close(fd)
            raise AssetStoreError("The image could not be stored.")
        os.close(fd)
        self._fsync_directory(directory)

    def finish_intent(self, storage_name: str) -> None:
        """Drop the intent after the database row has committed."""
        self._remove_marker(self.root / ".intent", storage_name)

    def intent_entries(self) -> list[tuple[str, str, str]]:
        directory = self.root / ".intent"
        if not directory.is_dir() or directory.is_symlink():
            return []
        found = []
        for marker in directory.iterdir():
            if marker.is_symlink() or not marker.is_file():
                continue
            if STORAGE_NAME.fullmatch(marker.name) is None:
                continue
            try:
                text = marker.read_text(encoding="utf-8")
            except OSError:
                continue
            owner_id, _sep, rest = text.partition("\n")
            investigation_id = rest.split("\n", 1)[0]
            found.append((marker.name, owner_id, investigation_id))
        return found

    def pending_entries(self) -> list[tuple[str, str, str]]:
        directory = self.root / ".pending"
        if not directory.is_dir() or directory.is_symlink():
            return []
        found = []
        for marker in directory.iterdir():
            if marker.is_symlink() or not marker.is_file():
                continue
            if STORAGE_NAME.fullmatch(marker.name) is None:
                continue
            try:
                text = marker.read_text(encoding="utf-8")
            except OSError:
                continue
            owner_id, _sep, rest = text.partition("\n")
            investigation_id = rest.split("\n", 1)[0]
            found.append((marker.name, owner_id, investigation_id))
        return found

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

    def _pending_dir(self) -> Path:
        return self._private_dir(".pending")

    def _intent_dir(self) -> Path:
        return self._private_dir(".intent")

    def _private_dir(self, name: str) -> Path:
        directory = self.root / name
        if directory.is_symlink():
            raise AssetStoreError("The image could not be stored.")
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
        self._fsync_directory(self.root)
        return directory

    def _remove_marker(self, directory: Path, storage_name: str) -> None:
        if STORAGE_NAME.fullmatch(storage_name) is None or not directory.is_dir() or directory.is_symlink():
            return
        marker = directory / storage_name
        if marker.parent != directory or marker.is_symlink():
            raise AssetStoreError("The image could not be stored.")
        try:
            marker.unlink()
        except FileNotFoundError:
            return
        self._fsync_directory(directory)
        if directory.exists() and not any(directory.iterdir()):
            directory.rmdir()
            self._fsync_directory(self.root)

    def _fsync_directory(self, directory: Path) -> None:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        except OSError as exc:
            raise AssetStoreError("The image could not be stored.") from exc
        finally:
            os.close(fd)

    def _write_all(self, fd: int, data: bytes) -> None:
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            written = os.write(fd, view[offset:])
            if written <= 0:
                raise AssetStoreError("The image could not be stored.")
            offset += written

    def _unlink_quiet(self, path: Path) -> bool:
        try:
            if path.is_symlink():
                return False
            path.unlink()
        except FileNotFoundError:
            return True
        except OSError:
            return False
        return not path.exists()


def reconcile_assets(root: Path, referenced: set[str]) -> None:
    """Make incomplete image files recoverable without removing a referenced one.

    An intent with no database row is an image that never committed: its file
    is removed. A ``.bin`` with neither a row nor an intent is quarantined.
    Partial files are removed. The function is safe to run again.
    """
    root = Path(root)
    if not root.exists() or root.is_symlink() or not root.is_dir():
        return
    for partial in root.glob("*.partial"):
        if partial.is_symlink() or not partial.is_file():
            continue
        try:
            partial.unlink()
        except FileNotFoundError:
            continue
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
                except OSError:
                    continue
                continue
            published = root / marker.name
            if published.is_file() and not published.is_symlink():
                try:
                    published.unlink()
                except OSError:
                    continue
            try:
                marker.unlink()
            except OSError:
                continue
    for item in list(root.iterdir()):
        if item.name.startswith(".") or not item.name.endswith(".bin"):
            continue
        if item.is_symlink() or not item.is_file():
            continue
        if item.name in referenced:
            continue
        quarantine = root / ".quarantine"
        quarantine.mkdir(parents=True, exist_ok=True)
        os.chmod(quarantine, 0o700)
        destination = quarantine / item.name
        if destination.exists():
            continue
        try:
            os.replace(item, destination)
            os.chmod(destination, 0o600)
        except OSError:
            continue
