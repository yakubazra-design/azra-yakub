"""Registration, sessions, CSRF, and account ownership."""

import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from app.ledger import Ledger
from app.main import create_app
from test_api import NOT_FOUND, _create, _ledger, _settings

PASSWORD = "correct-horse-battery"
EMAIL = "person@example.com"
INVALID = {"code": "invalid_credentials", "message": "The email or password is incorrect."}
CSRF = {"code": "csrf_failed", "message": "The request could not be verified."}


def _register(client: TestClient, email: str = EMAIL, password: str = PASSWORD):
    return client.post("/api/auth/register", json={"email": email, "password": password})


def _login(client: TestClient, email: str = EMAIL, password: str = PASSWORD):
    return client.post("/api/auth/login", json={"email": email, "password": password})


def test_register_stores_argon2id_and_not_the_password(tmp_path):
    path = tmp_path / "ledger.sqlite"
    app = create_app(settings=_settings(ledger_path=str(path)))
    with TestClient(app) as client:
        created = _register(client)
        again = _register(client)
        logged = _login(client, "Person@Example.com", PASSWORD)
    assert created.status_code == 200
    assert created.json() == {"ok": True}
    assert again.status_code == 200
    assert again.json() == {"ok": True}
    assert "set-cookie" not in {key.lower() for key in created.headers}
    assert logged.status_code == 200
    raw = path.read_bytes()
    assert PASSWORD.encode() not in raw
    conn = sqlite3.connect(path)
    try:
        stored = conn.execute("SELECT password_hash FROM users WHERE email = ?", (EMAIL,)).fetchone()[0]
    finally:
        conn.close()
    assert stored.startswith("$argon2id$")


def test_validation_errors_do_not_echo_credentials_or_tokens(tmp_path):
    app = create_app(settings=_settings(ledger_path=_ledger(tmp_path)))
    secret = "not-a-string-secret"
    token = "assessment-token-must-not-echo"
    with TestClient(app) as client:
        login = client.post("/api/auth/login", json={"email": "person@example.com", "password": [secret]})
        assess = client.post("/api/investigations/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/assess", json={
            "assessmentToken": {"value": token},
        })
    assert login.status_code == assess.status_code == 400
    assert login.json() == assess.json() == {"code": "invalid_request", "message": "The request could not be read."}
    assert secret not in login.text
    assert token not in assess.text
    assert "traceback" not in login.text.lower()


def test_login_errors_do_not_reveal_whether_the_email_exists(tmp_path):
    app = create_app(settings=_settings(ledger_path=_ledger(tmp_path)))
    with TestClient(app) as client:
        _register(client)
        unknown = _login(client, "missing@example.com", PASSWORD)
        wrong = _login(client, EMAIL, "not-the-right-password")
        malformed = _login(client, "not-an-email", PASSWORD)
    assert unknown.status_code == wrong.status_code == malformed.status_code == 401
    assert unknown.json() == wrong.json() == malformed.json() == INVALID
    assert unknown.content == wrong.content == malformed.content


def test_duplicate_registration_does_not_replace_the_password(tmp_path):
    path = tmp_path / "ledger.sqlite"
    app = create_app(settings=_settings(ledger_path=str(path)))
    with TestClient(app) as client:
        _register(client)
        _register(client, EMAIL, "another-password-value")
        original = _login(client, EMAIL, PASSWORD)
        replaced = _login(client, EMAIL, "another-password-value")
    assert original.status_code == 200
    assert replaced.status_code == 401
    assert replaced.json() == INVALID


def test_logout_revokes_the_session_on_the_server(tmp_path):
    app = create_app(settings=_settings(ledger_path=_ledger(tmp_path)))
    with TestClient(app) as client:
        _register(client)
        logged = _login(client)
        token = client.cookies.get("rc_session")
        client.headers["X-CSRF-Token"] = logged.json()["csrfToken"]
        signed_out = client.post("/api/auth/logout")
        client.cookies.set("rc_session", token)
        again = client.get("/api/auth/session")
    assert signed_out.status_code == 200
    assert signed_out.json() == {"ok": True}
    assert again.status_code == 401
    assert again.json()["code"] == "unauthenticated"


def test_expired_session_is_rejected(tmp_path):
    path = tmp_path / "ledger.sqlite"
    app = create_app(settings=_settings(ledger_path=str(path)))
    with TestClient(app) as client:
        _register(client)
        logged = _login(client)
        conn = sqlite3.connect(path)
        conn.execute("UPDATE sessions SET expires_at = '2000-01-01T00:00:00+00:00'")
        conn.commit()
        conn.close()
        client.headers["X-CSRF-Token"] = logged.json()["csrfToken"]
        current = client.get("/api/auth/session")
        created = client.post("/api/investigations", json={"input": "A claim", "kind": "claim"})
    assert current.status_code == 401
    assert created.status_code == 401
    assert current.json() == created.json()
    assert current.json()["code"] == "unauthenticated"


def test_state_changing_requests_require_the_csrf_token(tmp_path):
    app = create_app(settings=_settings(ledger_path=_ledger(tmp_path)))
    with TestClient(app) as client:
        _register(client)
        logged = _login(client)
        missing = client.post("/api/investigations", json={"input": "A claim", "kind": "claim"})
        client.headers["X-CSRF-Token"] = "wrong-token"
        wrong = client.post("/api/investigations", json={"input": "A claim", "kind": "claim"})
        client.headers["X-CSRF-Token"] = logged.json()["csrfToken"]
        accepted = client.post("/api/investigations", json={"input": "A claim", "kind": "claim"})
        evidence = client.get(f"/api/investigations/{accepted.json()['investigationId']}/evidence")
    assert missing.status_code == 403
    assert wrong.status_code == 403
    assert missing.json() == wrong.json() == CSRF
    assert accepted.status_code == 200
    assert evidence.status_code == 200


def test_one_account_cannot_use_another_accounts_investigation(tmp_path):
    app = create_app(settings=_settings(ledger_path=_ledger(tmp_path)))
    with TestClient(app) as owner, TestClient(app) as other:
        investigation_id = _create(owner, "Private claim")
        _create(other, "Other claim")
        hidden = other.get(f"/api/investigations/{investigation_id}/evidence")
        removed = other.delete(f"/api/investigations/{investigation_id}")
        kept = owner.get(f"/api/investigations/{investigation_id}/evidence")
    assert hidden.status_code == 404
    assert removed.status_code == 404
    assert hidden.json() == removed.json() == NOT_FOUND
    assert kept.status_code == 200


def test_legacy_investigations_remain_but_the_old_cookie_is_not_a_session(tmp_path):
    path = tmp_path / "old.sqlite"
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE users (id TEXT PRIMARY KEY, created_at TEXT NOT NULL);
        CREATE TABLE investigations (
            id TEXT PRIMARY KEY,
            owner_id TEXT NOT NULL REFERENCES users(id),
            kind TEXT NOT NULL,
            input_text TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        INSERT INTO users (id, created_at) VALUES ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '2020-01-01T00:00:00+00:00');
        INSERT INTO investigations (id, owner_id, kind, input_text, created_at)
        VALUES ('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'claim', 'Legacy claim', '2020-01-01T00:00:00+00:00');
        """
    )
    conn.commit()
    conn.close()
    ledger = Ledger(path)
    assert ledger.get_investigation("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")["input_text"] == "Legacy claim"
    app = create_app(settings=_settings(ledger_path=str(path)))
    with TestClient(app) as client:
        denied = client.get(
            "/api/investigations/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/evidence",
            headers={"cookie": "rc_owner=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        )
    assert denied.status_code == 401
    assert Ledger(path).get_investigation(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )["input_text"] == "Legacy claim"


def test_production_without_a_long_auth_secret_refuses_sign_in(tmp_path):
    short = "too-short"
    app = create_app(settings=_settings(ledger_path=_ledger(tmp_path), cookie_secure=True, auth_secret=short))
    with TestClient(app) as client:
        health = client.get("/api/health")
        register = _register(client)
        login = _login(client)
        created = client.post("/api/investigations", json={"input": "A claim", "kind": "claim"})
    assert health.json()["authReady"] is False
    assert register.status_code == login.status_code == created.status_code == 503
    assert register.json()["code"] == "auth_unavailable"
    assert short not in register.text
    assert "AUTH_SECRET" not in register.text

    missing = create_app(settings=_settings(ledger_path=_ledger(tmp_path, "missing-secret.sqlite"), cookie_secure=True, auth_secret=""))
    with TestClient(missing) as client:
        response = client.post("/api/auth/login", json={"email": EMAIL, "password": PASSWORD})
    assert response.status_code == 503
    assert response.json() == {"code": "auth_unavailable", "message": "Authentication is unavailable."}
