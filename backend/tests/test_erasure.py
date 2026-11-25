"""Account erasure removes one account and leaves every other record."""

import sqlite3
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.auth import hash_password
from app.backup import backup_ledger
from app.ledger import Ledger, LedgerError
from app.main import create_app
from test_api import _settings

PASSWORD = "correct-horse-battery"
OTHER_PASSWORD = "other-horse-battery-ok"
LEGACY_TEXT = "Legacy claim stays"


def _future() -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=1)).replace(microsecond=0).isoformat()


def _counts(path) -> dict[str, int]:
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
            "rate_limits",
        )
        return {table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in tables}
    finally:
        conn.close()


def _emails(path) -> set[str]:
    conn = sqlite3.connect(path)
    try:
        return {row[0] for row in conn.execute("SELECT email FROM users") if row[0]}
    finally:
        conn.close()


def _populate(path):
    ledger = Ledger(path)
    owner = ledger.create_account("owner@example.com", hash_password(PASSWORD))
    other = ledger.create_account("other@example.com", hash_password(OTHER_PASSWORD))
    legacy = ledger.create_owner()
    assert owner and other and legacy
    owner_case = ledger.create_investigation(owner, "claim", "Warm water cures diabetes.")
    other_case = ledger.create_investigation(other, "claim", "Other person's claim.")
    legacy_case = ledger.create_investigation(legacy, "claim", LEGACY_TEXT)
    for owner_id, case, url in (
        (owner, owner_case, "https://www.cdc.gov/owner"),
        (other, other_case, "https://www.cdc.gov/other"),
    ):
        ledger.save_page(owner_id, case, {
            "requested_url": url,
            "final_url": url,
            "title": "Page",
            "body_text": url,
            "published_at": "2024-01-15",
            "date_certainty": "provider-reported",
            "date_type": "published",
            "provider": "Parallel Extract",
        })
        ledger.replace_sources(owner_id, case, [{
            "url": url,
            "title": "Source",
            "snippet": url,
            "publishedAt": "2024-01-15",
            "dateCertainty": "provider-reported",
            "dateType": "published",
            "provider": "Parallel Search",
            "quality": {"tier": "HIGH", "reason": "Government domain."},
        }])
        ledger.save_claims(owner_id, case, url, ["A point."])
        ledger.seal_assessment(owner_id, case, f"hash-{owner_id[:8]}", {"primaryClaim": url}, _future())
    ledger.create_session(owner, "active-session-hash", "csrf-active", _future())
    ledger.create_session(owner, "revoked-session-hash", "csrf-revoked", _future())
    ledger.create_session(other, "other-session-hash", "csrf-other", _future())
    conn = sqlite3.connect(path)
    conn.execute(
        "UPDATE sessions SET revoked_at = '2020-01-01T00:00:00+00:00', expires_at = '2000-01-01T00:00:00+00:00' WHERE token_hash = 'revoked-session-hash'"
    )
    current_window = int(datetime.now(timezone.utc).timestamp())
    conn.execute(
        "INSERT INTO rate_limits (bucket, subject, window_start, count) VALUES ('search', ?, ?, 2)",
        (owner, current_window),
    )
    conn.execute(
        "INSERT INTO rate_limits (bucket, subject, window_start, count) VALUES ('login', '203.0.113.5', ?, 1)",
        (current_window,),
    )
    conn.execute(
        "INSERT INTO rate_limits (bucket, subject, window_start, count) VALUES ('search', ?, ?, 4)",
        (other, current_window),
    )
    conn.execute(
        """
        INSERT INTO assessment_snapshots (
            id, investigation_id, owner_id, token_hash, snapshot_json,
            created_at, expires_at, consumed_at
        ) VALUES ('owned-on-other', ?, ?, 'hash-owned-on-other', '{"primaryClaim":"owner copy"}', ?, ?, NULL)
        """,
        (other_case, owner, _future(), _future()),
    )
    conn.commit()
    conn.close()
    return owner, other, legacy, owner_case, other_case, legacy_case


def _delete(client: TestClient, password: str):
    return client.request("DELETE", "/api/auth/account", json={"password": password, "email": "other@example.com"})


def _login(client: TestClient, email: str, password: str) -> str:
    logged = client.post("/api/auth/login", json={"email": email, "password": password})
    assert logged.status_code == 200, logged.text
    client.headers["X-CSRF-Token"] = logged.json()["csrfToken"]
    return logged.json()["csrfToken"]


def test_account_deletion_removes_only_that_account(tmp_path):
    path = tmp_path / "ledger.sqlite"
    owner, other, legacy, _owner_case, other_case, legacy_case = _populate(path)
    app = create_app(settings=_settings(ledger_path=str(path)))
    with TestClient(app) as client:
        _login(client, "owner@example.com", PASSWORD)
        first = client.cookies.get("rc_session")
        second_login = client.post("/api/auth/login", json={"email": "owner@example.com", "password": PASSWORD})
        assert second_login.status_code == 200
        second = client.cookies.get("rc_session")
        client.headers["X-CSRF-Token"] = second_login.json()["csrfToken"]
        deleted = _delete(client, PASSWORD)
        cleared = client.get("/api/auth/session")
        client.cookies.set("rc_session", first)
        old_first = client.get("/api/auth/session")
        client.cookies.set("rc_session", second)
        old_second = client.get("/api/auth/session")
        again = client.post("/api/auth/login", json={"email": "owner@example.com", "password": PASSWORD})
        other_login = client.post("/api/auth/login", json={"email": "other@example.com", "password": OTHER_PASSWORD})
    assert deleted.status_code == 200
    assert deleted.json() == {"ok": True}
    assert PASSWORD not in deleted.text
    assert "other@example.com" not in deleted.text
    assert "set-cookie" in {key.lower() for key in deleted.headers}
    assert cleared.status_code == old_first.status_code == old_second.status_code == 401
    assert again.status_code == 401
    assert other_login.status_code == 200
    conn = sqlite3.connect(path)
    try:
        assert conn.execute("SELECT id FROM users WHERE id = ?", (owner,)).fetchone() is None
        assert conn.execute("SELECT COUNT(*) FROM investigations WHERE owner_id = ?", (owner,)).fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM sessions WHERE user_id = ?", (owner,)).fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM rate_limits WHERE subject = ?", (owner,)).fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM assessment_snapshots WHERE owner_id = ?", (owner,)).fetchone()[0] == 0
        assert conn.execute("SELECT input_text FROM investigations WHERE id = ?", (other_case,)).fetchone()[0] == "Other person's claim."
        assert conn.execute("SELECT input_text FROM investigations WHERE id = ?", (legacy_case,)).fetchone()[0] == LEGACY_TEXT
        assert conn.execute("SELECT email, password_hash FROM users WHERE id = ?", (legacy,)).fetchone() == (None, None)
        assert conn.execute(
            "SELECT token_hash FROM sessions WHERE user_id = ?",
            (other,),
        ).fetchall()
        assert conn.execute(
            "SELECT 1 FROM sessions WHERE token_hash = 'other-session-hash'"
        ).fetchone() is not None
        assert conn.execute("SELECT primary_claim FROM claim_analyses WHERE investigation_id = ?", (other_case,)).fetchone()[0] == "https://www.cdc.gov/other"
        assert conn.execute("SELECT url FROM evidence_sources WHERE investigation_id = ?", (other_case,)).fetchone()[0] == "https://www.cdc.gov/other"
        assert conn.execute("SELECT body_text FROM page_fetches WHERE investigation_id = ?", (other_case,)).fetchone()[0] == "https://www.cdc.gov/other"
        assert conn.execute(
            "SELECT COUNT(*) FROM assessment_snapshots WHERE investigation_id = ? AND owner_id = ?",
            (other_case, other),
        ).fetchone()[0] == 1
        assert conn.execute("SELECT count FROM rate_limits WHERE subject = '203.0.113.5'").fetchone()[0] == 1
        assert conn.execute("SELECT count FROM rate_limits WHERE subject = ?", (other,)).fetchone()[0] == 4
    finally:
        conn.close()


def test_wrong_password_and_csrf_do_not_delete_the_account(tmp_path):
    path = tmp_path / "ledger.sqlite"
    _populate(path)
    app = create_app(settings=_settings(ledger_path=str(path)))
    with TestClient(app) as client:
        csrf = _login(client, "owner@example.com", PASSWORD)
        before = _counts(path)
        client.headers.pop("X-CSRF-Token", None)
        missing = _delete(client, PASSWORD)
        client.headers["X-CSRF-Token"] = "not-the-token"
        invalid = _delete(client, PASSWORD)
        client.headers["X-CSRF-Token"] = csrf
        wrong = client.request("DELETE", "/api/auth/account", json={"password": "not-the-right-password"})
        still = client.get("/api/auth/session")
    assert missing.status_code == invalid.status_code == 403
    assert missing.json() == invalid.json() == {"code": "csrf_failed", "message": "The request could not be verified."}
    assert wrong.status_code == 403
    assert wrong.json() == {"code": "invalid_password", "message": "The password is not correct."}
    assert PASSWORD not in wrong.text
    assert still.status_code == 200
    assert _counts(path) == before
    assert "owner@example.com" in _emails(path)


def test_legacy_anonymous_records_survive_erasure(tmp_path):
    path = tmp_path / "ledger.sqlite"
    owner, _other, legacy, _owner_case, _other_case, legacy_case = _populate(path)
    ledger = Ledger(path)
    assert ledger.erase_account(legacy, PASSWORD) == "legacy"
    assert ledger.get_investigation(legacy, legacy_case)["input_text"] == LEGACY_TEXT
    assert ledger.erase_account(owner, PASSWORD) == "ok"
    assert ledger.get_investigation(legacy, legacy_case)["input_text"] == LEGACY_TEXT
    conn = sqlite3.connect(path)
    try:
        row = conn.execute("SELECT email, password_hash FROM users WHERE id = ?", (legacy,)).fetchone()
    finally:
        conn.close()
    assert row == (None, None)


def test_a_failed_deletion_rolls_back(tmp_path):
    path = tmp_path / "ledger.sqlite"
    owner, _other, _legacy, _owner_case, _other_case, _legacy_case = _populate(path)
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TRIGGER users_refuse_delete
        BEFORE DELETE ON users
        BEGIN
            SELECT RAISE(ABORT, 'simulated failure');
        END
        """
    )
    conn.commit()
    conn.close()
    ledger = Ledger(path)
    before = _counts(path)
    try:
        ledger.erase_account(owner, PASSWORD)
    except LedgerError as exc:
        assert str(exc) == "The evidence ledger is unavailable."
        assert "simulated" not in str(exc)
    else:
        raise AssertionError("erasure should have failed")
    assert _counts(path) == before
    assert ledger.get_account_by_email("owner@example.com")["id"] == owner

    app = create_app(settings=_settings(ledger_path=str(path)))
    with TestClient(app) as client:
        _login(client, "owner@example.com", PASSWORD)
        after_login = _counts(path)
        failed = _delete(client, PASSWORD)
        still = client.get("/api/auth/session")
    assert failed.status_code == 503
    assert failed.json() == {"code": "ledger_unavailable", "message": "The evidence ledger is unavailable."}
    assert "simulated" not in failed.text
    assert str(path) not in failed.text
    assert still.status_code == 200
    assert _counts(path) == after_login


def test_a_backup_after_deletion_omits_the_account_and_an_earlier_backup_keeps_it(tmp_path):
    path = tmp_path / "ledger.sqlite"
    owner, _other, legacy, _owner_case, _other_case, legacy_case = _populate(path)
    destination = tmp_path / "backups"
    earlier = backup_ledger(path, destination, now=datetime(2026, 11, 17, 6, 0, tzinfo=timezone.utc))
    assert Ledger(path).erase_account(owner, PASSWORD) == "ok"
    later = backup_ledger(path, destination, now=datetime(2026, 11, 17, 6, 5, tzinfo=timezone.utc))
    assert "owner@example.com" in _emails(earlier)
    assert "owner@example.com" not in _emails(later)
    assert "owner@example.com" not in _emails(path)
    assert "other@example.com" in _emails(later)
    restored = tmp_path / "restored.sqlite"
    from app.backup import restore_ledger
    restore_ledger(earlier, restored, application_stopped=True)
    assert "owner@example.com" in _emails(restored)
    assert Ledger(restored).get_investigation(legacy, legacy_case)["input_text"] == LEGACY_TEXT
    assert "owner@example.com" not in _emails(path)
