"""SQLite backup and restore for the evidence ledger and its image files.

The database copy uses SQLite's backup API, so committed WAL pages are
included. The same write lock covers the image rows and the asset files, so
a successful backup is one consistent point. Beside the database file are a
manifest and a directory of those files. Filenames are timestamps only.
Messages from this module do not contain paths, passwords, tokens, or API keys.

Image bytes stay on disk until account deletion removes them. A cleanup row
keeps a name when a file could not be unlinked yet. Deletion can be retried:
a missing file is already gone, and the row is removed on the next success.
A backup includes those cleanup files. Restore checks every name, size, and
SHA-256 and stops without reporting success when any check fails. The previous
database and asset directory are renamed aside and are not deleted. A backup
with no manifest is a ledger-only copy. It restores only when it has no image
or cleanup rows. This tool does not modify an existing backup file.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

BUSY_SECONDS = 5
FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"
_STORAGE_NAME = re.compile(r"[0-9a-f]{32}\.bin")


class BackupError(Exception):
    """A backup or restore could not be completed. The message is safe to print."""


def backup_ledger(
    source: Path,
    destination_dir: Path,
    *,
    frontend_dir: Path = FRONTEND_DIR,
    now: datetime | None = None,
) -> Path:
    """Copy a consistent ledger snapshot into a new file outside the frontend.

    An existing backup file is left unchanged. The new file is mode 0600 and
    its directory is mode 0700.
    """
    _assert_private(source, frontend_dir, "The ledger could not be read.")
    _assert_private(destination_dir, frontend_dir, "The backup destination is not available.")
    if source.is_symlink() or not source.is_file():
        raise BackupError("The ledger could not be read.")
    if destination_dir.exists() and (destination_dir.is_symlink() or not destination_dir.is_dir()):
        raise BackupError("The backup destination is not available.")
    _protect_directory(destination_dir)
    target = _new_backup_path(destination_dir, now or datetime.now(timezone.utc))
    try:
        files = _backup_consistent(source, target)
        manifest_path = Path(str(target) + ".manifest.json")
        _write_manifest(manifest_path, target.name, files)
        if _load_manifest(manifest_path) != files:
            raise BackupError("The backup could not be created.")
        if not _integrity_ok(target):
            raise BackupError("The backup file failed the integrity check.")
        _match_database(target, files)
        _check_files(files, Path(str(target) + ".assets"))
    except BackupError:
        _discard_bundle(target)
        raise
    except (OSError, sqlite3.Error, ValueError) as exc:
        _discard_bundle(target)
        raise BackupError("The backup could not be created.") from exc
    return target


def restore_ledger(
    backup: Path,
    destination: Path,
    *,
    frontend_dir: Path = FRONTEND_DIR,
    application_stopped: bool = False,
    now: datetime | None = None,
) -> None:
    """Replace a stopped ledger with a checked backup.

    The application must be stopped. When the destination is open, this
    returns without changing it. The previous database file, WAL, and SHM
    are renamed aside and are not deleted.
    """
    if not application_stopped:
        raise BackupError("Stop the application before restoring the database.")
    _assert_private(backup, frontend_dir, "The backup could not be read.")
    _assert_private(destination, frontend_dir, "The restore could not be completed.")
    if backup.is_symlink() or not backup.is_file():
        raise BackupError("The backup could not be read.")
    if destination.exists() and (destination.is_symlink() or not destination.is_file()):
        raise BackupError("The restore could not be completed.")
    try:
        if backup.resolve() == destination.resolve():
            raise BackupError("The restore could not be completed.")
    except OSError as exc:
        raise BackupError("The restore could not be completed.") from exc
    if not _integrity_ok(backup):
        raise BackupError("The backup file failed the integrity check.")
    files = _restore_files(backup)
    if destination.exists() and not _exclusive_available(destination):
        raise BackupError("Stop the application before restoring the database.")

    parent = destination.parent
    if parent.exists() and (parent.is_symlink() or not parent.is_dir()):
        raise BackupError("The restore could not be completed.")
    _protect_directory(parent)
    if _journal_path(destination).exists():
        recover_restore(destination)
    stamp = _unique_restore_stamp(parent, destination, now or datetime.now(timezone.utc))
    incoming_db = f".{stamp}.incoming.sqlite"
    incoming_assets = f".{stamp}.incoming-assets" if files else None
    journal = {
        "version": 1,
        "state": "prepared",
        "stamp": stamp,
        "ledger": destination.name,
        "incoming_db": incoming_db,
        "incoming_assets": incoming_assets,
        "previous_db": destination.name + f".pre-restore-{stamp}",
        "previous_wal": destination.name + f"-wal.pre-restore-{stamp}",
        "previous_shm": destination.name + f"-shm.pre-restore-{stamp}",
        "previous_assets": f"assets.pre-restore-{stamp}",
        "had_db": destination.exists(),
        "had_wal": Path(str(destination) + "-wal").exists(),
        "had_shm": Path(str(destination) + "-shm").exists(),
        "had_assets": (parent / "assets").exists(),
        "files": files,
    }
    try:
        _copy_database(backup, parent / incoming_db, "The restore could not be completed.")
        if not _integrity_ok(parent / incoming_db):
            raise BackupError("The restored database failed the integrity check.")
        if incoming_assets is not None:
            _install_assets(parent / incoming_assets, files, Path(str(backup) + ".assets"))
            _check_files(files, parent / incoming_assets)
            _fsync_directory(parent / incoming_assets)
        _match_database(parent / incoming_db, files)
        _fsync_directory(parent)
        # The journal is durable before any live name is renamed. Recovery does
        # not depend on an in-memory flag. These two directories cannot be
        # replaced as one atomic operation.
        _commit_restore_state(parent, destination, journal, "prepared")
        if journal["had_db"]:
            if not _checkpoint_if_idle(destination):
                raise BackupError("Stop the application before restoring the database.")
            journal["had_wal"] = Path(str(destination) + "-wal").exists()
            journal["had_shm"] = Path(str(destination) + "-shm").exists()
            _commit_restore_state(parent, destination, journal, "moving-database")
            os.replace(destination, parent / journal["previous_db"])
            _chmod_private(parent / journal["previous_db"], 0o600, "The restore could not be completed.")
            for flag, key, suffix in (
                ("had_wal", "previous_wal", "-wal"),
                ("had_shm", "previous_shm", "-shm"),
            ):
                sidecar = Path(str(destination) + suffix)
                if journal[flag] and sidecar.exists():
                    os.replace(sidecar, parent / journal[key])
            _fsync_directory(parent)
            _commit_restore_state(parent, destination, journal, "database-aside")
        _commit_restore_state(parent, destination, journal, "installing-database")
        os.replace(parent / incoming_db, destination)
        _chmod_private(destination, 0o600, "The restore could not be completed.")
        _fsync_directory(parent)
        _commit_restore_state(parent, destination, journal, "database-installed")
        if journal["had_assets"]:
            _commit_restore_state(parent, destination, journal, "moving-assets")
            os.replace(parent / "assets", parent / journal["previous_assets"])
            _fsync_directory(parent)
            _commit_restore_state(parent, destination, journal, "assets-aside")
        if incoming_assets is not None:
            _commit_restore_state(parent, destination, journal, "installing-assets")
            os.replace(parent / incoming_assets, parent / "assets")
            _fsync_directory(parent)
            _commit_restore_state(parent, destination, journal, "assets-installed")
        _validate_restored_pair(destination, journal)
        _commit_restore_state(parent, destination, journal, "validated")
        _remove_journal(destination)
        _fsync_directory(parent)
    except BackupError:
        _abort_incomplete_restore(destination, parent, incoming_db, incoming_assets)
        raise
    except (OSError, sqlite3.Error) as exc:
        _abort_incomplete_restore(destination, parent, incoming_db, incoming_assets)
        raise BackupError("The restore could not be completed.") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="app.backup")
    commands = parser.add_subparsers(dest="command", required=True)

    backup = commands.add_parser("backup")
    backup.add_argument("--ledger", required=True)
    backup.add_argument("--dest", required=True)

    restore = commands.add_parser("restore")
    restore.add_argument("--backup", required=True)
    restore.add_argument("--ledger", required=True)
    restore.add_argument("--application-stopped", action="store_true")

    args = parser.parse_args(argv)
    try:
        if args.command == "backup":
            written = backup_ledger(Path(args.ledger), Path(args.dest))
            print(f"Backup written: {written.name}")
            return 0
        restore_ledger(
            Path(args.backup),
            Path(args.ledger),
            application_stopped=bool(args.application_stopped),
        )
    except BackupError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except (OSError, sqlite3.Error):
        message = "The backup could not be created." if args.command == "backup" else "The restore could not be completed."
        print(message, file=sys.stderr)
        return 1
    print("Restore completed.")
    return 0


def _backup_consistent(source: Path, target: Path) -> list[dict]:
    """Copy the database and the asset files named by that database.

    The write lock is held from the row read through the database copy, so a
    commit cannot change one without the other.
    """
    conn = sqlite3.connect(source, timeout=BUSY_SECONDS)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("BEGIN IMMEDIATE")
        files = _referenced_files(conn)
        root = source.parent / "assets"
        if _unreferenced_names(root, {item["name"] for item in files}):
            raise BackupError("The backup could not be created.")
        assets_dir = Path(str(target) + ".assets")
        if files:
            assets_dir.mkdir()
            os.chmod(assets_dir, 0o700)
            for item in files:
                _copy_private(root / item["name"], assets_dir / item["name"], item)
        # A second connection copies the committed pages. The write lock above
        # stays held, so no upload or seal can commit between the file copy
        # and this snapshot. Backing up the locked connection itself retries
        # forever, because that connection already owns the write lock.
        _backup_locked_database(source, target, "The backup could not be created.")
        conn.rollback()
    finally:
        conn.close()
    return files


def _backup_locked_database(source: Path, target: Path, failure: str) -> None:
    src = sqlite3.connect(source, timeout=BUSY_SECONDS)
    try:
        _backup_connection(src, target, failure)
    finally:
        src.close()


def _backup_connection(source: sqlite3.Connection, target: Path, failure: str) -> None:
    if target.exists():
        raise BackupError(failure)
    dest = sqlite3.connect(target, timeout=BUSY_SECONDS)
    try:
        source.backup(dest)
        dest.execute("PRAGMA journal_mode = DELETE")
        rows = dest.execute("PRAGMA integrity_check").fetchall()
        if not _integrity_rows(rows):
            raise BackupError("The backup file failed the integrity check.")
    except BackupError:
        raise
    except (OSError, sqlite3.Error) as exc:
        raise BackupError(failure) from exc
    finally:
        dest.close()
    _chmod_private(target, 0o600, failure)
    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(target) + suffix)
        if sidecar.exists():
            raise BackupError(failure)


def _referenced_files(conn: sqlite3.Connection) -> list[dict]:
    files = []
    for role, table in (("asset", "image_assets"), ("cleanup", "asset_cleanup")):
        if not _table_exists(conn, table):
            continue
        for row in conn.execute(f"SELECT storage_name, sha256, byte_length FROM {table}"):
            name = row["storage_name"]
            if _STORAGE_NAME.fullmatch(str(name)) is None:
                raise BackupError("The backup could not be created.")
            files.append({
                "name": name,
                "sha256": str(row["sha256"]),
                "bytes": int(row["byte_length"]),
                "role": role,
            })
    if len({item["name"] for item in files}) != len(files):
        raise BackupError("The backup could not be created.")
    return files


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (name,),
    ).fetchone()
    return row is not None


def _unreferenced_names(root: Path, referenced: set[str]) -> list[str]:
    if not root.exists():
        return []
    if root.is_symlink() or not root.is_dir():
        raise BackupError("The backup could not be created.")
    extra = []
    for item in root.iterdir():
        if item.name.startswith("."):
            continue
        if not item.name.endswith(".bin"):
            continue
        if item.is_symlink() or not item.is_file() or item.name not in referenced:
            extra.append(item.name)
    return extra


def _copy_private(source: Path, target: Path, expected: dict) -> None:
    if source.is_symlink() or not source.is_file():
        raise BackupError("The backup could not be created.")
    blob = source.read_bytes()
    if len(blob) != expected["bytes"] or hashlib.sha256(blob).hexdigest() != expected["sha256"]:
        raise BackupError("The backup could not be created.")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(blob)
        offset = 0
        while offset < len(view):
            written = os.write(fd, view[offset:])
            if written <= 0:
                raise BackupError("The backup could not be created.")
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(target, 0o600)


def _write_manifest(path: Path, ledger_name: str, files: list[dict]) -> None:
    payload = json.dumps({"format": 1, "ledger": ledger_name, "files": files}, sort_keys=True).encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        _write_all(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
    if path.read_bytes() != payload:
        raise BackupError("The backup could not be created.")


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    offset = 0
    while offset < len(view):
        written = os.write(fd, view[offset:])
        if written <= 0:
            raise BackupError("The backup could not be created.")
        offset += written


def _load_manifest(path: Path) -> list[dict]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BackupError("The backup could not be created.") from exc
    files = payload.get("files") if isinstance(payload, dict) else None
    if not isinstance(files, list):
        raise BackupError("The backup could not be created.")
    return files


_restore_observer = None

RESTORE_STATES = (
    "prepared",
    "moving-database",
    "database-aside",
    "installing-database",
    "database-installed",
    "moving-assets",
    "assets-aside",
    "installing-assets",
    "assets-installed",
    "validated",
)


def _journal_path(destination: Path) -> Path:
    return destination.parent / f".{destination.name}.restore-journal"


def _commit_restore_state(parent: Path, destination: Path, journal: dict, state: str) -> None:
    journal["state"] = state
    _save_journal(destination, journal)
    observer = _restore_observer
    if observer is not None:
        observer(state)


def _save_journal(destination: Path, journal: dict) -> None:
    path = _journal_path(destination)
    payload = json.dumps(journal, sort_keys=True).encode()
    temporary = Path(str(path) + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        _write_all(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
    os.chmod(path, 0o600)
    _fsync_directory(destination.parent)
    if path.read_bytes() != payload:
        raise BackupError("The restore could not be completed.")


def _remove_journal(destination: Path) -> None:
    path = _journal_path(destination)
    if path.is_symlink():
        raise BackupError("The restore could not be completed.")
    if path.is_file():
        path.unlink()


def _fsync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    except OSError as exc:
        raise BackupError("The restore could not be completed.") from exc
    finally:
        os.close(fd)


def _unique_restore_stamp(parent: Path, destination: Path, moment: datetime) -> str:
    base = _stamp(moment)
    suffixes = [""] + [f"-{number}" for number in range(2, 50)]
    for suffix in suffixes:
        stamp = base + suffix
        names = [
            f".{stamp}.incoming.sqlite",
            f".{stamp}.incoming-assets",
            destination.name + f".pre-restore-{stamp}",
            destination.name + f"-wal.pre-restore-{stamp}",
            destination.name + f"-shm.pre-restore-{stamp}",
            f"assets.pre-restore-{stamp}",
            f".{stamp}.abandoned.sqlite",
            f"assets.abandoned-{stamp}",
        ]
        if all(not (parent / name).exists() for name in names):
            return stamp
    raise BackupError("The restore could not be completed.")


def recover_restore(destination: Path) -> None:
    """Finish a validated restore, or put the previous database and assets back.

    The journal is the record. An in-memory flag is not required. Previous
    files are renamed, not deleted.
    """
    path = _journal_path(destination)
    if not path.exists():
        return
    if path.is_symlink() or not path.is_file():
        raise BackupError("The restore could not be completed.")
    try:
        journal = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BackupError("The restore could not be completed.") from exc
    if not isinstance(journal, dict) or journal.get("version") != 1 or journal.get("ledger") != destination.name:
        raise BackupError("The restore could not be completed.")
    parent = destination.parent
    if _installed_pair_is_valid(destination, journal):
        _discard_incoming(parent, journal)
        _remove_journal(destination)
        _fsync_directory(parent)
        return
    _reinstate_previous(destination, journal)
    _discard_incoming(parent, journal)
    _remove_journal(destination)
    _fsync_directory(parent)


def _installed_pair_is_valid(destination: Path, journal: dict) -> bool:
    """True only after the journal records that the live pair was checked."""
    if journal.get("state") != "validated":
        return False
    if journal.get("had_db") and not (destination.parent / str(journal.get("previous_db"))).is_file():
        return False
    return _pair_matches(destination, journal)


def _pair_matches(destination: Path, journal: dict) -> bool:
    parent = destination.parent
    if not destination.is_file() or destination.is_symlink():
        return False
    files = journal.get("files")
    if not isinstance(files, list):
        return False
    try:
        if not _integrity_ok(destination):
            return False
        _match_database(destination, files)
        _check_files(files, parent / "assets")
    except BackupError:
        return False
    return True


def _reinstate_previous(destination: Path, journal: dict) -> None:
    parent = destination.parent
    stamp = str(journal.get("stamp") or "restore")
    if journal.get("had_db"):
        previous = parent / str(journal.get("previous_db"))
        if previous.is_file() and not previous.is_symlink():
            if destination.exists() or destination.is_symlink():
                _park(destination, parent / f".{stamp}.abandoned.sqlite")
            os.replace(previous, destination)
            _chmod_private(destination, 0o600, "The restore could not be completed.")
        for flag, key, suffix in (
            ("had_wal", "previous_wal", "-wal"),
            ("had_shm", "previous_shm", "-shm"),
        ):
            if not journal.get(flag):
                continue
            saved = parent / str(journal.get(key))
            sidecar = Path(str(destination) + suffix)
            if saved.exists():
                if sidecar.exists() or sidecar.is_symlink():
                    _park(sidecar, parent / f".{stamp}.abandoned{suffix}")
                os.replace(saved, sidecar)
    if journal.get("had_assets"):
        previous_assets = parent / str(journal.get("previous_assets"))
        live = parent / "assets"
        if previous_assets.exists():
            if live.exists() or live.is_symlink():
                _park(live, parent / f"assets.abandoned-{stamp}")
            os.replace(previous_assets, live)
    _fsync_directory(parent)


def _park(path: Path, abandoned: Path) -> None:
    if abandoned.exists():
        raise BackupError("The restore could not be completed.")
    os.replace(path, abandoned)


def _discard_incoming(parent: Path, journal: dict) -> None:
    incoming = parent / str(journal.get("incoming_db"))
    live = parent / str(journal.get("ledger"))
    if incoming.is_file() and not incoming.is_symlink() and incoming != live:
        incoming.unlink()
    assets_name = journal.get("incoming_assets")
    if assets_name:
        assets = parent / str(assets_name)
        if assets.is_dir() and not assets.is_symlink() and assets.name != "assets":
            shutil.rmtree(assets)


def _abort_incomplete_restore(destination: Path, parent: Path, incoming_db: str, incoming_assets: str | None) -> None:
    if _journal_path(destination).exists():
        recover_restore(destination)
        return
    incoming = parent / incoming_db
    if incoming.is_file() and not incoming.is_symlink():
        incoming.unlink()
    if incoming_assets:
        assets = parent / incoming_assets
        if assets.is_dir() and not assets.is_symlink():
            shutil.rmtree(assets)


def _validate_restored_pair(destination: Path, journal: dict) -> None:
    if not _pair_matches(destination, journal):
        raise BackupError("The restored database failed the integrity check.")


def _restore_files(backup: Path) -> list[dict]:
    manifest = Path(str(backup) + ".manifest.json")
    directory = Path(str(backup) + ".assets")
    if not manifest.exists():
        if _database_has_assets(backup):
            raise BackupError("The backup does not include the image files.")
        return []
    if manifest.is_symlink() or not manifest.is_file():
        raise BackupError("The backup could not be read.")
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BackupError("The backup could not be read.") from exc
    files = payload.get("files") if isinstance(payload, dict) else None
    if payload.get("format") != 1 or not isinstance(files, list):
        raise BackupError("The backup could not be read.")
    _check_files(files, directory)
    _match_database(backup, files)
    return files


def _database_has_assets(path: Path) -> bool:
    conn = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=BUSY_SECONDS)
    try:
        conn.row_factory = sqlite3.Row
        for table in ("image_assets", "asset_cleanup"):
            if _table_exists(conn, table):
                count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                if int(count) > 0:
                    return True
        return False
    except sqlite3.Error as exc:
        raise BackupError("The backup could not be read.") from exc
    finally:
        conn.close()


def _check_files(files: list[dict], directory: Path) -> None:
    names = []
    for item in files:
        if not isinstance(item, dict):
            raise BackupError("The backup could not be read.")
        name = item.get("name")
        if not isinstance(name, str) or _STORAGE_NAME.fullmatch(name) is None:
            raise BackupError("The backup could not be read.")
        if item.get("role") not in ("asset", "cleanup"):
            raise BackupError("The backup could not be read.")
        names.append(name)
    if len(names) != len(set(names)):
        raise BackupError("The backup could not be read.")
    present = set()
    if directory.exists():
        if directory.is_symlink() or not directory.is_dir():
            raise BackupError("The backup could not be read.")
        for item in directory.iterdir():
            if item.name.endswith(".bin"):
                if item.is_symlink() or not item.is_file():
                    raise BackupError("The backup could not be read.")
                present.add(item.name)
    elif names:
        raise BackupError("The backup could not be read.")
    if present != set(names):
        raise BackupError("The backup could not be read.")
    for item in files:
        blob = (directory / item["name"]).read_bytes()
        if len(blob) != item.get("bytes") or hashlib.sha256(blob).hexdigest() != item.get("sha256"):
            raise BackupError("The backup could not be read.")


def _match_database(path: Path, files: list[dict]) -> None:
    conn = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=BUSY_SECONDS)
    try:
        conn.row_factory = sqlite3.Row
        expected = {(item["name"], item["sha256"], int(item["bytes"]), item["role"]) for item in files}
        found = set()
        for role, table in (("asset", "image_assets"), ("cleanup", "asset_cleanup")):
            if not _table_exists(conn, table):
                continue
            for row in conn.execute(f"SELECT storage_name, sha256, byte_length FROM {table}"):
                found.add((row["storage_name"], row["sha256"], int(row["byte_length"]), role))
        if found != expected:
            raise BackupError("The backup could not be read.")
    except BackupError:
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
        raise BackupError("The backup could not be read.") from exc
    finally:
        conn.close()


def _install_assets(live: Path, files: list[dict], source: Path) -> None:
    if not files:
        return
    live.mkdir()
    os.chmod(live, 0o700)
    try:
        for item in files:
            _copy_private(source / item["name"], live / item["name"], item)
    except Exception:
        if live.exists() and not live.is_symlink():
            shutil.rmtree(live, ignore_errors=True)
        raise


def _move_assets_aside(destination: Path, stamp: str) -> Path | None:
    live = destination.parent / "assets"
    if not live.exists():
        return None
    if live.is_symlink() or not live.is_dir():
        raise BackupError("The restore could not be completed.")
    aside = destination.parent / f"assets.pre-restore-{stamp}"
    if aside.exists():
        raise BackupError("The restore could not be completed.")
    os.replace(live, aside)
    return aside


def _restore_assets(live: Path, aside: Path | None) -> None:
    """Move a previous asset directory back. It is not deleted."""
    if aside is None or not aside.exists() or aside.is_symlink():
        return
    if live.exists() or live.is_symlink():
        _park(live, live.parent / f"{live.name}.abandoned-restore")
    os.replace(aside, live)


def _discard_bundle(target: Path) -> None:
    _discard_new(target)
    manifest = Path(str(target) + ".manifest.json")
    assets = Path(str(target) + ".assets")
    if manifest.is_file() and not manifest.is_symlink():
        try:
            manifest.unlink()
        except OSError:
            return
    if assets.is_dir() and not assets.is_symlink():
        shutil.rmtree(assets, ignore_errors=True)


def _copy_database(source: Path, target: Path, failure: str = "The backup could not be created.") -> None:
    if target.exists():
        raise BackupError(failure)
    src = sqlite3.connect(source, timeout=BUSY_SECONDS)
    try:
        dest = sqlite3.connect(target, timeout=BUSY_SECONDS)
        try:
            src.backup(dest)
            dest.execute("PRAGMA journal_mode = DELETE")
            rows = dest.execute("PRAGMA integrity_check").fetchall()
            if not _integrity_rows(rows):
                raise BackupError("The backup file failed the integrity check.")
        finally:
            dest.close()
    except BackupError:
        raise
    except (OSError, sqlite3.Error) as exc:
        raise BackupError(failure) from exc
    finally:
        src.close()
    _chmod_private(target, 0o600, failure)
    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(target) + suffix)
        if sidecar.exists():
            raise BackupError(failure)


def _integrity_ok(path: Path) -> bool:
    try:
        conn = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=BUSY_SECONDS)
    except (OSError, sqlite3.Error):
        return False
    try:
        rows = conn.execute("PRAGMA integrity_check").fetchall()
    except sqlite3.Error:
        return False
    finally:
        conn.close()
    return _integrity_rows(rows)


def _integrity_rows(rows) -> bool:
    return len(rows) == 1 and str(rows[0][0]).lower() == "ok"


def _exclusive_available(path: Path) -> bool:
    try:
        conn = sqlite3.connect(path, timeout=0.1)
    except sqlite3.Error:
        return False
    try:
        conn.execute("BEGIN EXCLUSIVE")
        conn.rollback()
        return True
    except sqlite3.Error:
        return False
    finally:
        conn.close()


def _checkpoint_if_idle(path: Path) -> bool:
    try:
        conn = sqlite3.connect(path, timeout=0.1)
    except sqlite3.Error:
        return False
    try:
        conn.execute("BEGIN EXCLUSIVE")
        conn.commit()
        busy, _log, _checkpointed = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        return int(busy) == 0
    except sqlite3.Error:
        try:
            conn.rollback()
        except sqlite3.Error:
            pass
        return False
    finally:
        conn.close()


def _new_backup_path(directory: Path, moment: datetime) -> Path:
    stamp = _stamp(moment)
    candidates = [directory / f"realitycheck-ledger-{stamp}.sqlite"]
    candidates.extend(directory / f"realitycheck-ledger-{stamp}-{number}.sqlite" for number in range(2, 21))
    for candidate in candidates:
        if not candidate.exists():
            return candidate
    raise BackupError("The backup could not be created.")


def _stamp(moment: datetime) -> str:
    current = moment.astimezone(timezone.utc)
    return current.strftime("%Y%m%dT%H%M%SZ")


def _assert_private(path: Path, frontend_dir: Path, message: str) -> None:
    if path.is_symlink():
        raise BackupError(message)
    parent = path.parent
    if parent.exists() and parent.is_symlink():
        raise BackupError(message)
    try:
        resolved = path.resolve()
        frontend = frontend_dir.resolve()
    except OSError as exc:
        raise BackupError(message) from exc
    if resolved == frontend or frontend in resolved.parents:
        raise BackupError(message)


def _protect_directory(directory: Path) -> None:
    if directory.is_symlink():
        raise BackupError("The backup destination is not available.")
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise BackupError("The backup destination is not available.") from exc
    _chmod_private(directory, 0o700, "The backup destination is not available.")


def _chmod_private(path: Path, mode: int, failure: str) -> None:
    if path.is_symlink():
        raise BackupError(failure)
    try:
        os.chmod(path, mode)
    except OSError as exc:
        raise BackupError(failure) from exc


def _rename_aside(path: Path, stamp: str) -> tuple[Path, Path]:
    if path.is_symlink():
        raise BackupError("The restore could not be completed.")
    target = Path(str(path) + f".pre-restore-{stamp}")
    if target.exists():
        raise BackupError("The restore could not be completed.")
    os.replace(path, target)
    if target.is_file():
        _chmod_private(target, 0o600, "The restore could not be completed.")
    return path, target


def _rollback(temporary: Path, destination: Path, saved: list[tuple[Path, Path]], replaced: bool) -> None:
    if replaced and destination.exists() and not destination.is_symlink():
        try:
            destination.unlink()
        except OSError:
            return
    for original, aside in reversed(saved):
        if aside.exists() and not original.exists():
            try:
                os.replace(aside, original)
            except OSError:
                return
    if temporary.exists() and temporary.is_file() and not temporary.is_symlink():
        try:
            temporary.unlink()
        except OSError:
            return


def _discard_new(path: Path) -> None:
    for candidate in (path, Path(str(path) + "-wal"), Path(str(path) + "-shm")):
        if candidate.is_file() and not candidate.is_symlink():
            try:
                candidate.unlink()
            except OSError:
                return


if __name__ == "__main__":
    sys.exit(main())
