"""WAL backups, restore checks, and the ledger health response."""

import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.backup import RESTORE_STATES, BackupError, _save_journal, backup_ledger, main, recover_restore, restore_ledger
from app.ledger import Ledger
from test_api import _settings
from app.main import create_app

FRONTEND = Path(__file__).resolve().parents[2] / "frontend"
ROOT = Path(__file__).resolve().parents[2]
PASSWORD = "backup-stage-password"
SESSION = "backup-stage-session-token"
ASSESSMENT = "backup-stage-assessment-token"
API_KEY = "backup-stage-api-key"
WAL_EMAIL = "wal-only@example.com"
WHEN = datetime(2026, 11, 16, 18, 45, tzinfo=timezone.utc)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _emails(path: Path) -> set[str]:
    conn = sqlite3.connect(path)
    try:
        return {row[0] for row in conn.execute("SELECT email FROM users")}
    except sqlite3.Error:
        return set()
    finally:
        conn.close()


def _populate(path: Path) -> str:
    ledger = Ledger(path)
    owner = ledger.create_account("owner@example.com", PASSWORD)
    assert owner
    investigation = ledger.create_investigation(owner, "claim", f"Warm water cures diabetes. {API_KEY}")
    assert investigation
    assert ledger.save_page(owner, investigation, {
        "requested_url": "https://www.cdc.gov/diabetes",
        "final_url": "https://www.cdc.gov/diabetes",
        "title": "Diabetes",
        "body_text": "No cure is described.",
        "published_at": "2024-01-15",
        "date_certainty": "provider-reported",
        "date_type": "published",
        "provider": "Parallel Extract",
    })
    stored = ledger.replace_sources(owner, investigation, [{
        "url": "https://www.cdc.gov/diabetes",
        "title": "Diabetes facts",
        "snippet": "No cure is described.",
        "publishedAt": "2024-01-15",
        "dateCertainty": "provider-reported",
        "dateType": "published",
        "provider": "Parallel Search",
        "quality": {"tier": "HIGH", "reason": "Government domain."},
    }])
    assert stored
    assert ledger.save_claims(owner, investigation, "Warm water cures diabetes.", ["The claim names a cure."])
    expires = (datetime.now(timezone.utc) + timedelta(hours=1)).replace(microsecond=0).isoformat()
    ledger.create_session(owner, SESSION, "csrf-value", expires)
    assert ledger.seal_assessment(
        owner,
        investigation,
        ASSESSMENT,
        {"primaryClaim": "Warm water cures diabetes."},
        expires,
    )
    return owner


def _counts(path: Path) -> dict[str, int]:
    conn = sqlite3.connect(path)
    try:
        tables = (
            "users",
            "investigations",
            "page_fetches",
            "evidence_sources",
            "claim_analyses",
            "sessions",
            "assessment_snapshots",
        )
        return {table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in tables}
    finally:
        conn.close()


def test_backup_includes_committed_wal_pages_and_restore_keeps_records(tmp_path):
    source = tmp_path / "ledger.sqlite"
    owner = _populate(source)
    holder = sqlite3.connect(source)
    holder.execute("PRAGMA journal_mode = WAL")
    holder.execute(
        "INSERT INTO users (id, created_at, email, password_hash) VALUES (?, ?, ?, ?)",
        ("wal-user", "2026-11-16T18:45:00+00:00", WAL_EMAIL, PASSWORD),
    )
    holder.commit()
    assert holder.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert Path(str(source) + "-wal").stat().st_size > 0

    naive = tmp_path / "naive.sqlite"
    shutil.copy(source, naive)
    assert WAL_EMAIL not in _emails(naive)

    destination = tmp_path / "backups"
    written = backup_ledger(source, destination, now=WHEN)
    assert written.name == "realitycheck-ledger-20261116T184500Z.sqlite"
    assert _mode(destination) == 0o700
    assert _mode(written) == 0o600
    assert not Path(str(written) + "-wal").exists()
    assert WAL_EMAIL in _emails(written)
    assert "owner@example.com" in _emails(written)
    for secret in (PASSWORD, SESSION, ASSESSMENT, API_KEY):
        assert secret not in written.name

    conn = sqlite3.connect(written)
    try:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert conn.execute("SELECT token_hash FROM sessions").fetchone()[0] == SESSION
        assert conn.execute("SELECT token_hash FROM assessment_snapshots").fetchone()[0] == ASSESSMENT
        assert conn.execute("SELECT primary_claim FROM claim_analyses").fetchone()[0] == "Warm water cures diabetes."
        assert conn.execute("SELECT url FROM evidence_sources").fetchone()[0] == "https://www.cdc.gov/diabetes"
        assert API_KEY in conn.execute("SELECT input_text FROM investigations").fetchone()[0]
    finally:
        conn.close()
    holder.close()

    restored = tmp_path / "restored" / "ledger.sqlite"
    restore_ledger(written, restored, application_stopped=True, now=WHEN)
    assert _mode(restored) == 0o600
    assert _mode(restored.parent) == 0o700
    assert _counts(restored) == _counts(written)
    reopened = Ledger(restored)
    assert reopened.get_account_by_email(WAL_EMAIL)["password_hash"] == PASSWORD
    lookup = sqlite3.connect(restored)
    try:
        investigation_id = lookup.execute(
            "SELECT id FROM investigations WHERE owner_id = ?",
            (owner,),
        ).fetchone()[0]
    finally:
        lookup.close()
    assert reopened.list_sources(owner, investigation_id)[0]["url"] == "https://www.cdc.gov/diabetes"
    assert reopened.get_claims(owner, investigation_id)["primaryClaim"] == "Warm water cures diabetes."


def test_restore_refuses_an_open_database_and_a_failed_integrity_check(tmp_path):
    source = tmp_path / "source.sqlite"
    _populate(source)
    written = backup_ledger(source, tmp_path / "backups", now=WHEN)
    live = tmp_path / "live.sqlite"
    shutil.copy(source, live)
    before = _counts(live)

    holder = sqlite3.connect(live)
    holder.execute("BEGIN EXCLUSIVE")
    try:
        with pytest.raises(BackupError, match="Stop the application before restoring the database."):
            restore_ledger(written, live, application_stopped=True, now=WHEN)
    finally:
        holder.rollback()
        holder.close()
    assert _counts(live) == before
    assert not list(live.parent.glob("*.pre-restore-*"))

    damaged = tmp_path / "damaged.sqlite"
    damaged.write_bytes(written.read_bytes())
    blob = bytearray(damaged.read_bytes())
    blob[100] ^= 0xFF
    damaged.write_bytes(blob)
    with pytest.raises(BackupError, match="The backup file failed the integrity check."):
        restore_ledger(damaged, live, application_stopped=True, now=WHEN)
    assert _counts(live) == before

    restore_ledger(written, live, application_stopped=True, now=datetime(2026, 11, 16, 18, 46, tzinfo=timezone.utc))
    assert _counts(live) == _counts(written)
    previous = list(live.parent.glob("live.sqlite.pre-restore-*"))
    assert len(previous) == 1
    assert _counts(previous[0]) == before


def test_backup_destination_cannot_be_inside_the_frontend(tmp_path):
    source = tmp_path / "ledger.sqlite"
    Ledger(source).create_owner()
    with pytest.raises(BackupError, match="The backup destination is not available."):
        backup_ledger(source, FRONTEND / "backups", now=WHEN)
    assert not (FRONTEND / "backups").exists()


def test_command_output_uses_the_timestamp_name_and_omits_secrets(tmp_path):
    source = tmp_path / "ledger.sqlite"
    _populate(source)
    holder = sqlite3.connect(source)
    holder.execute("INSERT INTO users (id, created_at, email, password_hash) VALUES ('x', '2026-11-16T18:45:00+00:00', ?, ?)", (WAL_EMAIL, PASSWORD))
    holder.commit()
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "app.backup",
            "backup",
            "--ledger",
            str(source),
            "--dest",
            str(tmp_path / "backups"),
        ],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": "backend"},
        text=True,
        capture_output=True,
        check=False,
    )
    holder.close()
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.startswith("Backup written: realitycheck-ledger-")
    assert completed.stdout.strip().endswith(".sqlite")
    combined = completed.stdout + completed.stderr
    for secret in (PASSWORD, SESSION, ASSESSMENT, API_KEY, WAL_EMAIL):
        assert secret not in combined
    assert str(source) not in combined

    backup = next((tmp_path / "backups").glob("realitycheck-ledger-*.sqlite"))
    refused = subprocess.run(
        [
            sys.executable,
            "-m",
            "app.backup",
            "restore",
            "--backup",
            str(backup),
            "--ledger",
            str(tmp_path / "restored.sqlite"),
        ],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": "backend"},
        text=True,
        capture_output=True,
        check=False,
    )
    assert refused.returncode == 1
    assert refused.stderr.strip() == "Stop the application before restoring the database."
    assert not (tmp_path / "restored.sqlite").exists()

    restored = subprocess.run(
        [
            sys.executable,
            "-m",
            "app.backup",
            "restore",
            "--backup",
            str(backup),
            "--ledger",
            str(tmp_path / "restored.sqlite"),
            "--application-stopped",
        ],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": "backend"},
        text=True,
        capture_output=True,
        check=False,
    )
    assert restored.returncode == 0, restored.stderr
    assert restored.stdout.strip() == "Restore completed."
    for secret in (PASSWORD, SESSION, ASSESSMENT, API_KEY):
        assert secret not in restored.stdout + restored.stderr
    assert _counts(tmp_path / "restored.sqlite") == _counts(backup)
    conn = sqlite3.connect(tmp_path / "restored.sqlite")
    try:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        conn.close()


def test_restore_failure_and_interruption_keep_the_original_pair(tmp_path, monkeypatch):
    source = tmp_path / "source.sqlite"
    _populate(source)
    written = backup_ledger(source, tmp_path / "backups", now=WHEN)
    early = (
        "prepared",
        "moving-database",
        "database-aside",
        "installing-database",
        "database-installed",
        "moving-assets",
        "assets-aside",
    )
    for state in early:
        live_dir = tmp_path / f"live-{state}"
        live_dir.mkdir()
        live = live_dir / "ledger.sqlite"
        shutil.copy(source, live)
        os.chmod(live, 0o600)
        assets = live_dir / "assets"
        assets.mkdir(mode=0o700)
        marker = assets / "keep.txt"
        marker.write_bytes(b"original-asset")
        before = _counts(live)

        def observer(current, expected=state):
            if current == expected:
                raise BackupError("stop")

        monkeypatch.setattr("app.backup._restore_observer", observer)
        with pytest.raises(BackupError):
            restore_ledger(written, live, application_stopped=True, now=WHEN)
        monkeypatch.setattr("app.backup._restore_observer", None)
        assert _counts(live) == before
        assert marker.read_bytes() == b"original-asset"
        assert not (live_dir / f".{live.name}.restore-journal").exists()
        assert (live_dir / "assets").is_dir()

    occupied = tmp_path / "occupied"
    occupied.mkdir()
    occupied_live = occupied / "ledger.sqlite"
    shutil.copy(source, occupied_live)
    stamp = "20261116T184500Z"
    collision = occupied / f"ledger.sqlite.pre-restore-{stamp}"
    collision.write_bytes(b"leave-this-name")
    os.chmod(collision, 0o600)
    restore_ledger(written, occupied_live, application_stopped=True, now=WHEN)
    assert collision.read_bytes() == b"leave-this-name"
    assert _counts(occupied_live) == _counts(written)
    assert any(path.name != collision.name for path in occupied.glob("ledger.sqlite.pre-restore-*"))


def test_simulated_restore_interruption_rolls_back_until_validation(tmp_path):
    source = tmp_path / "source.sqlite"
    _populate(source)
    written = backup_ledger(source, tmp_path / "backups", now=WHEN)
    for state in RESTORE_STATES:
        if state == "validated":
            continue
        folder = tmp_path / state
        folder.mkdir()
        live = folder / "ledger.sqlite"
        shutil.copy(source, live)
        os.chmod(live, 0o600)
        assets = folder / "assets"
        assets.mkdir(mode=0o700)
        (assets / "keep.txt").write_bytes(b"original-asset")
        before = live.read_bytes()
        journal = {
            "version": 1,
            "state": state,
            "stamp": "interrupt",
            "ledger": live.name,
            "incoming_db": ".interrupt.incoming.sqlite",
            "incoming_assets": None,
            "previous_db": live.name + ".pre-restore-interrupt",
            "previous_wal": live.name + "-wal.pre-restore-interrupt",
            "previous_shm": live.name + "-shm.pre-restore-interrupt",
            "previous_assets": "assets.pre-restore-interrupt",
            "had_db": True,
            "had_wal": False,
            "had_shm": False,
            "had_assets": True,
            "files": [],
        }
        if state in {"database-aside", "installing-database", "database-installed", "moving-assets", "assets-aside", "installing-assets", "assets-installed"}:
            os.replace(live, folder / journal["previous_db"])
            shutil.copy(written, live)
            os.chmod(live, 0o600)
        if state in {"assets-aside", "installing-assets", "assets-installed"}:
            os.replace(assets, folder / journal["previous_assets"])
        if state == "assets-installed":
            installed = folder / "assets"
            installed.mkdir(mode=0o700)
            (installed / "other.txt").write_bytes(b"new-asset")
        _save_journal(live, journal)
        recover_restore(live)
        assert not (folder / f".{live.name}.restore-journal").exists()
        assert live.read_bytes() == before
        assert (assets / "keep.txt").read_bytes() == b"original-asset"

    folder = tmp_path / "validated"
    folder.mkdir()
    live = folder / "ledger.sqlite"
    shutil.copy(written, live)
    os.chmod(live, 0o600)
    previous = folder / "ledger.sqlite.pre-restore-done"
    previous.write_bytes(b"previous-database")
    os.chmod(previous, 0o600)
    _save_journal(live, {
        "version": 1,
        "state": "validated",
        "stamp": "done",
        "ledger": live.name,
        "incoming_db": ".done.incoming.sqlite",
        "incoming_assets": None,
        "previous_db": previous.name,
        "previous_wal": live.name + "-wal.pre-restore-done",
        "previous_shm": live.name + "-shm.pre-restore-done",
        "previous_assets": "assets.pre-restore-done",
        "had_db": True,
        "had_wal": False,
        "had_shm": False,
        "had_assets": False,
        "files": [],
    })
    expected = live.read_bytes()
    recover_restore(live)
    assert live.read_bytes() == expected
    assert previous.read_bytes() == b"previous-database"
    assert not (folder / f".{live.name}.restore-journal").exists()


def test_manifest_short_writes_are_reassembled_and_a_bad_manifest_is_discarded(tmp_path, monkeypatch):
    source = tmp_path / "ledger.sqlite"
    _populate(source)
    real_write = os.write

    def short_write(fd, data):
        return real_write(fd, bytes(data[:1]))

    monkeypatch.setattr(os, "write", short_write)
    written = backup_ledger(source, tmp_path / "backups", now=WHEN)
    monkeypatch.undo()
    manifest = json.loads(Path(str(written) + ".manifest.json").read_text())
    assert manifest["format"] == 1
    assert manifest["files"] == []

    def bad_manifest(path, ledger_name, files):
        path.write_bytes(b"{}")
        os.chmod(path, 0o600)

    monkeypatch.setattr("app.backup._write_manifest", bad_manifest)
    with pytest.raises(BackupError):
        backup_ledger(source, tmp_path / "bad-manifest", now=WHEN)
    assert list((tmp_path / "bad-manifest").glob("*")) == []


def test_health_reports_an_unreadable_ledger_without_internal_detail(tmp_path):
    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory")
    path = blocked / "ledger.sqlite"
    app = create_app(settings=_settings(ledger_path=str(path)))
    with TestClient(app) as client:
        response = client.get("/api/health")
    assert response.status_code == 503
    assert response.json() == {
        "status": "unhealthy",
        "openaiConfigured": False,
        "parallelConfigured": False,
        "authReady": True,
        "videoIngestEnabled": False,
        "videoIngestAvailable": False,
    }
    assert str(path) not in response.text
    assert "sqlite" not in response.text.lower()
    assert "traceback" not in response.text.lower()


def test_health_reports_a_failed_integrity_check_without_internal_detail(tmp_path):
    path = tmp_path / "ledger.sqlite"
    ledger = Ledger(path)
    ledger.create_owner()
    assert ledger.check_health() is True
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.close()
    for extra in (Path(str(path) + "-wal"), Path(str(path) + "-shm")):
        if extra.exists():
            extra.unlink()
    blob = bytearray(path.read_bytes())
    blob[4096] ^= 0xFF
    path.write_bytes(blob)

    app = create_app(settings=_settings(ledger_path=str(path)))
    with TestClient(app) as client:
        response = client.get("/api/health")
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "unhealthy"
    assert set(body) == {
        "status",
        "openaiConfigured",
        "parallelConfigured",
        "authReady",
        "videoIngestEnabled",
        "videoIngestAvailable",
    }
    text = response.text.lower()
    assert str(path) not in response.text
    assert "malformed" not in text
    assert "integrity" not in text
    assert "sqlite" not in text


def test_cli_rejects_a_missing_ledger_without_echoing_the_path(tmp_path, capsys):
    missing = tmp_path / "missing.sqlite"
    code = main(["backup", "--ledger", str(missing), "--dest", str(tmp_path / "backups")])
    captured = capsys.readouterr()
    assert code == 1
    assert captured.err.strip() == "The ledger could not be read."
    assert str(missing) not in captured.err
    assert str(missing) not in captured.out

