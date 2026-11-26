"""Production startup must fail closed. Ledger files stay private."""

import os
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.ledger import Ledger, LedgerError, production_ledger_path
from app.main import FRONTEND_DIR, StartupError, create_app
from test_api import _ledger, _settings

SECRET = "p" * 32
PASSWORD = "correct-horse-battery"


def _mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def _production(tmp_path: Path, **overrides):
    data = dict(
        realitycheck_env="production",
        cookie_secure=True,
        auth_secret=SECRET,
        ledger_path=str(tmp_path / "ledger.sqlite"),
        trusted_proxies="127.0.0.1",
    )
    data.update(overrides)
    return _settings(**data)


def test_local_development_still_starts_without_a_production_secret(monkeypatch, tmp_path):
    monkeypatch.setattr("app.main.new_secret", lambda: "local-process-secret-value-32b")
    app = create_app(settings=_settings(ledger_path=_ledger(tmp_path)))
    with TestClient(app) as client:
        response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["authReady"] is True


def test_local_secure_cookie_without_a_secret_still_returns_503(tmp_path):
    app = create_app(settings=_settings(ledger_path=_ledger(tmp_path), cookie_secure=True, auth_secret=""))
    with TestClient(app) as client:
        response = client.post("/api/auth/login", json={"email": "person@example.com", "password": PASSWORD})
    assert response.status_code == 503
    assert response.json()["code"] == "auth_unavailable"


def test_production_refuses_to_start_without_secure_cookies(tmp_path, monkeypatch):
    monkeypatch.setattr("app.main.new_secret", lambda: (_ for _ in ()).throw(AssertionError("ephemeral secret")))
    with pytest.raises(StartupError, match="COOKIE_SECURE must be true"):
        create_app(settings=_production(tmp_path, cookie_secure=False))


def test_production_refuses_a_missing_or_short_secret(tmp_path, monkeypatch):
    monkeypatch.setattr("app.main.new_secret", lambda: (_ for _ in ()).throw(AssertionError("ephemeral secret")))
    with pytest.raises(StartupError, match="AUTH_SECRET must be at least 32 characters"):
        create_app(settings=_production(tmp_path, auth_secret=""))
    with pytest.raises(StartupError, match="AUTH_SECRET must be at least 32 characters"):
        create_app(settings=_production(tmp_path, auth_secret="short-secret"))
    assert not (tmp_path / "ledger.sqlite").exists()


def test_production_refuses_an_unset_relative_or_public_ledger_path(tmp_path, monkeypatch):
    monkeypatch.setattr("app.main.new_secret", lambda: (_ for _ in ()).throw(AssertionError("ephemeral secret")))
    with pytest.raises(StartupError, match="LEDGER_PATH"):
        create_app(settings=_production(tmp_path, ledger_path=""))
    with pytest.raises(StartupError, match="LEDGER_PATH"):
        create_app(settings=_production(tmp_path, ledger_path="data/ledger.sqlite"))
    public = FRONTEND_DIR / "ledger.sqlite"
    with pytest.raises(StartupError, match="LEDGER_PATH"):
        create_app(settings=_production(tmp_path, ledger_path=str(public)))
    assert not public.exists()
    directory = tmp_path / "not-a-file"
    directory.mkdir()
    with pytest.raises(StartupError, match="LEDGER_PATH"):
        create_app(settings=_production(tmp_path, ledger_path=str(directory)))
    blocker = tmp_path / "blocked"
    blocker.write_text("not a directory")
    with pytest.raises(StartupError, match="LEDGER_PATH"):
        create_app(settings=_production(tmp_path, ledger_path=str(blocker / "ledger.sqlite")))
    link = tmp_path / "linked.sqlite"
    target = tmp_path / "target.sqlite"
    target.write_bytes(b"")
    link.symlink_to(target)
    assert production_ledger_path(str(link), FRONTEND_DIR) is None


def test_production_starts_with_a_persistent_secret_and_keeps_existing_rows(tmp_path, monkeypatch):
    monkeypatch.setattr("app.main.new_secret", lambda: (_ for _ in ()).throw(AssertionError("ephemeral secret")))
    path = tmp_path / "ledger.sqlite"
    existing = Ledger(path)
    owner = existing.create_owner()
    investigation_id = existing.create_investigation(owner, "claim", "Keep this investigation")
    app = create_app(settings=_production(tmp_path))
    with TestClient(app) as client:
        health = client.get("/api/health")
        registered = client.post("/api/auth/register", json={"email": "prod@example.com", "password": PASSWORD})
        logged = client.post("/api/auth/login", json={"email": "prod@example.com", "password": PASSWORD})
    assert health.json()["authReady"] is True
    assert registered.status_code == 200
    assert logged.status_code == 200
    assert logged.headers["set-cookie"].startswith("__Host-rc_session=")
    assert SECRET not in logged.text
    kept = Ledger(path).get_investigation(owner, investigation_id)
    assert kept["input_text"] == "Keep this investigation"
    assert _mode(path) == 0o600
    assert _mode(path.parent) == 0o700


def test_ledger_permissions_cover_existing_database_wal_and_shm(tmp_path):
    directory = tmp_path / "data"
    directory.mkdir(mode=0o755)
    path = directory / "ledger.sqlite"
    ledger = Ledger(path)
    owner = ledger.create_owner()
    investigation_id = ledger.create_investigation(owner, "claim", "Still here")
    os.chmod(directory, 0o755)
    os.chmod(path, 0o644)
    holder = sqlite3.connect(path)
    holder.execute("PRAGMA journal_mode = WAL")
    holder.execute("BEGIN")
    holder.execute("SELECT count(*) FROM investigations").fetchone()
    wal = Path(str(path) + "-wal")
    shm = Path(str(path) + "-shm")
    assert wal.is_file() and shm.is_file()
    os.chmod(wal, 0o644)
    os.chmod(shm, 0o644)
    marker = directory / "marker.txt"
    marker.write_text("keep")
    tightening = ledger._connect()
    tightening.close()
    assert _mode(directory) == 0o700
    assert _mode(path) == 0o600
    assert _mode(wal) == 0o600
    assert _mode(shm) == 0o600
    holder.close()
    assert marker.read_text() == "keep"
    kept = Ledger(path).get_investigation(owner, investigation_id)
    assert kept["input_text"] == "Still here"
    assert _mode(path) == 0o600
    assert _mode(directory) == 0o700


def test_permission_errors_do_not_include_the_path(tmp_path, monkeypatch):
    path = tmp_path / "ledger.sqlite"
    Ledger(path)

    def fail(*_args, **_kwargs):
        raise OSError(path, "permission denied")

    monkeypatch.setattr("app.ledger.os.chmod", fail)
    with pytest.raises(LedgerError, match="The evidence ledger is unavailable") as caught:
        Ledger(path)
    assert str(path) not in str(caught.value)
    assert "permission denied" not in str(caught.value)
