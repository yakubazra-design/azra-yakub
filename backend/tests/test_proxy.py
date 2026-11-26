"""Visitor addresses come from a trusted proxy, never from an arbitrary header."""

import pytest
from fastapi.testclient import TestClient

from app.main import StartupError, client_address, create_app
from test_api import _ledger, _settings
from test_production import _production

PASSWORD = "correct-horse-battery"


def _login(client: TestClient, forwarded: str | None = None, extra: dict | None = None):
    headers = dict(extra or {})
    if forwarded is not None:
        headers["x-forwarded-for"] = forwarded
    return client.post(
        "/api/auth/login",
        json={"email": "person@example.com", "password": PASSWORD},
        headers=headers,
    )


def test_direct_requests_ignore_forwarded_headers(tmp_path):
    app = create_app(
        settings=_settings(ledger_path=str(tmp_path / "ledger.sqlite")),
        limits={"login": (1, 900)},
    )
    with TestClient(app, client=("203.0.113.10", 50000)) as client:
        first = _login(client, "198.51.100.8", {"forwarded": "for=198.51.100.9"})
        second = _login(client, "198.51.100.20")
    assert first.status_code == 401
    assert second.status_code == 429
    assert client_address("203.0.113.10", "198.51.100.8", frozenset()) == "203.0.113.10"


def test_separate_direct_visitors_have_separate_limits(tmp_path):
    app = create_app(
        settings=_settings(ledger_path=str(tmp_path / "ledger.sqlite")),
        limits={"login": (1, 900)},
    )
    with TestClient(app, client=("203.0.113.10", 50000)) as first_client:
        assert _login(first_client, "198.51.100.1").status_code == 401
        assert _login(first_client).status_code == 429
    with TestClient(app, client=("203.0.113.11", 50000)) as second_client:
        assert _login(second_client, "198.51.100.1").status_code == 401


def test_trusted_proxy_uses_one_visitor_address_for_login_and_registration(tmp_path):
    app = create_app(
        settings=_settings(
            ledger_path=str(tmp_path / "ledger.sqlite"),
            trusted_proxies="127.0.0.1",
        ),
        limits={"login": (1, 900), "register": (1, 900)},
    )
    with TestClient(app, client=("127.0.0.1", 443)) as client:
        first = _login(client, "203.0.113.10")
        repeated = _login(client, "203.0.113.10")
        other = _login(client, "203.0.113.11")
        registered = client.post(
            "/api/auth/register",
            json={"email": "one@example.com", "password": PASSWORD},
            headers={"x-forwarded-for": "203.0.113.20"},
        )
        registered_again = client.post(
            "/api/auth/register",
            json={"email": "two@example.com", "password": PASSWORD},
            headers={"x-forwarded-for": "203.0.113.20"},
        )
        other_registration = client.post(
            "/api/auth/register",
            json={"email": "three@example.com", "password": PASSWORD},
            headers={"x-forwarded-for": "203.0.113.21"},
        )
    assert first.status_code == 401
    assert repeated.status_code == 429
    assert other.status_code == 401
    assert registered.status_code == 200
    assert registered_again.status_code == 429
    assert other_registration.status_code == 200


def test_a_forwarded_list_or_forwarded_header_does_not_change_the_proxy_identity(tmp_path):
    app = create_app(
        settings=_settings(
            ledger_path=str(tmp_path / "ledger.sqlite"),
            trusted_proxies="127.0.0.1, ::1",
        ),
        limits={"login": (1, 900)},
    )
    with TestClient(app, client=("127.0.0.1", 443)) as client:
        listed = _login(client, "203.0.113.10, 198.51.100.5", {"forwarded": "for=203.0.113.10"})
        listed_again = _login(client, "198.51.100.9, 203.0.113.10")
        missing = _login(client, None)
        single = _login(client, "203.0.113.40")
    assert listed.status_code == 401
    assert listed_again.status_code == 429
    assert missing.status_code == 429
    assert single.status_code == 401
    trusted = frozenset({"127.0.0.1"})
    assert client_address("127.0.0.1", "203.0.113.10, 198.51.100.5", trusted) == "127.0.0.1"
    assert client_address("127.0.0.1", "203.0.113.40", trusted) == "203.0.113.40"


def test_an_untrusted_peer_cannot_spoof_its_address():
    trusted = frozenset({"127.0.0.1"})
    assert client_address("203.0.113.10", "198.51.100.8", trusted) == "203.0.113.10"
    assert client_address("203.0.113.10", "127.0.0.1", trusted) == "203.0.113.10"
    assert client_address("203.0.113.10", None, trusted) == "203.0.113.10"


def test_production_requires_a_list_of_proxy_addresses(tmp_path, monkeypatch):
    monkeypatch.setattr("app.main.new_secret", lambda: (_ for _ in ()).throw(AssertionError("ephemeral secret")))
    with pytest.raises(StartupError, match="TRUSTED_PROXIES must list the reverse proxy"):
        create_app(settings=_production(tmp_path, trusted_proxies=""))
    with pytest.raises(StartupError, match="TRUSTED_PROXIES must contain only IP addresses"):
        create_app(settings=_production(tmp_path, trusted_proxies="localhost"))
    with pytest.raises(StartupError, match="TRUSTED_PROXIES must contain only IP addresses"):
        create_app(settings=_production(tmp_path, trusted_proxies="10.0.0.0/8"))
    with pytest.raises(StartupError, match="TRUSTED_PROXIES must contain only IP addresses"):
        create_app(settings=_settings(ledger_path=_ledger(tmp_path), trusted_proxies="not-an-ip"))
