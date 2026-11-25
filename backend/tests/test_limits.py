"""Rate limits, request size, and empty inputs."""

import asyncio
import json
import logging
import sqlite3
import threading

import httpx
from fastapi.testclient import TestClient

from app.ledger import Ledger
from app.limits import LIMITS, MAX_BODY_BYTES, MAX_IMAGE_BYTES
from app.main import RequestSizeLimit, create_app
from test_api import DUMMY_OPENAI, DUMMY_PARALLEL, _create, _json_response, _ledger, _seal, _settings

PASSWORD = "correct-horse-battery"
LIMITED = {"code": "rate_limited", "message": "Too many requests. Try again later."}


def test_documented_limits():
    assert LIMITS["login"] == (10, 15 * 60)
    assert LIMITS["register"] == (5, 60 * 60)
    assert LIMITS["investigation"] == (30, 60 * 60)
    assert LIMITS["search"] == (60, 60 * 60)
    assert LIMITS["fetch"] == (30, 60 * 60)
    assert LIMITS["extract"] == (60, 60 * 60)
    assert LIMITS["seal"] == (60, 60 * 60)
    assert LIMITS["assess"] == (30, 60 * 60)
    assert LIMITS["evidence"] == (120, 60 * 60)
    assert LIMITS["asset"] == (20, 60 * 60)
    assert LIMITS["gps_reveal"] == (30, 60 * 60)
    assert MAX_BODY_BYTES == 64 * 1024
    assert MAX_IMAGE_BYTES == 8 * 1024 * 1024


def test_login_limit_is_per_address_and_stops_password_checks(monkeypatch, tmp_path):
    checks = {"n": 0}

    def count_check(*_args, **_kwargs):
        checks["n"] += 1
        return False

    monkeypatch.setattr("app.main.burn_password_check", count_check)
    monkeypatch.setattr("app.main.verify_password", count_check)
    app = create_app(settings=_settings(ledger_path=str(tmp_path / "ledger.sqlite")))
    with TestClient(app) as client:
        statuses = []
        for _ in range(10):
            response = client.post(
                "/api/auth/login",
                json={"email": "person@example.com", "password": PASSWORD},
                headers={"x-forwarded-for": "203.0.113.9"},
            )
            statuses.append(response.status_code)
        blocked = client.post(
            "/api/auth/login",
            json={"email": "other@example.com", "password": PASSWORD},
            headers={"x-forwarded-for": "198.51.100.4"},
        )
    assert statuses == [401] * 10
    assert checks["n"] == 10
    assert blocked.status_code == 429
    assert blocked.json() == LIMITED
    assert blocked.headers["retry-after"].isdigit()
    assert 1 <= int(blocked.headers["retry-after"]) <= 15 * 60
    assert PASSWORD not in blocked.text


def test_registration_limit_stops_before_hashing(monkeypatch, tmp_path):
    hashes = {"n": 0}

    def count_hash(password):
        hashes["n"] += 1
        return "hashed"

    monkeypatch.setattr("app.main.hash_password", count_hash)
    app = create_app(settings=_settings(ledger_path=str(tmp_path / "ledger.sqlite")))
    with TestClient(app) as client:
        for index in range(5):
            response = client.post("/api/auth/register", json={
                "email": f"person{index}@example.com",
                "password": PASSWORD,
            })
            assert response.status_code == 200
        blocked = client.post("/api/auth/register", json={
            "email": "person6@example.com",
            "password": PASSWORD,
        })
    assert hashes["n"] == 5
    assert blocked.status_code == 429
    assert blocked.json() == LIMITED
    assert "retry-after" in blocked.headers


def test_investigation_limit_is_thirty_per_user(tmp_path):
    app = create_app(settings=_settings(ledger_path=str(tmp_path / "ledger.sqlite")))
    with TestClient(app) as client:
        for _ in range(30):
            assert client.post(
                "/api/investigations",
                json={"input": "A claim", "kind": "claim"},
                headers={"x-csrf-token": _logged_in(client)},
            ).status_code == 200
        blocked = client.post(
            "/api/investigations",
            json={"input": "One more", "kind": "claim"},
        )
    assert blocked.status_code == 429
    assert blocked.json() == LIMITED


def test_search_limit_prevents_the_provider_call(tmp_path):
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return _json_response({"results": [], "session_id": "s"})

    app = create_app(
        settings=_settings(ledger_path=_ledger(tmp_path), parallel_api_key=DUMMY_PARALLEL),
        parallel_transport=httpx.MockTransport(handler),
        limits={"search": (1, 60 * 60)},
    )
    with TestClient(app) as client:
        investigation_id = _create(client)
        first = client.post(f"/api/investigations/{investigation_id}/search", json={"queries": ["claim"]})
        second = client.post(f"/api/investigations/{investigation_id}/search", json={"queries": ["claim"]})
    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json() == LIMITED
    assert calls["n"] == 1


def test_fetch_seal_assess_and_evidence_limits(tmp_path):
    calls = {"fetch": 0, "openai": 0}

    def parallel_handler(_request: httpx.Request) -> httpx.Response:
        calls["fetch"] += 1
        return _json_response({"results": [{"url": "https://example.com/page", "title": "Page", "full_content": "Text"}]})

    def openai_handler(_request: httpx.Request) -> httpx.Response:
        calls["openai"] += 1
        return _json_response({"choices": [{"message": {"content": json.dumps({
            "assessment": "INSUFFICIENT_EVIDENCE", "findings": [], "why": {}, "uncertainty": [],
        })}}]})

    path = tmp_path / "ledger.sqlite"
    app = create_app(
        settings=_settings(ledger_path=str(path), openai_api_key=DUMMY_OPENAI, parallel_api_key=DUMMY_PARALLEL),
        parallel_transport=httpx.MockTransport(parallel_handler),
        openai_transport=httpx.MockTransport(openai_handler),
        fetch_guard=lambda _url: None,
        limits={"fetch": (1, 3600), "seal": (1, 3600), "assess": (1, 3600), "evidence": (1, 3600), "extract": (1, 3600)},
    )
    with TestClient(app) as client:
        investigation_id = _create(client, "https://example.com/page", "url")
        first_fetch = client.post(f"/api/investigations/{investigation_id}/fetch")
        second_fetch = client.post(f"/api/investigations/{investigation_id}/fetch")
        first_extract = client.post(f"/api/investigations/{investigation_id}/extract-claims", json={"kind": "url"})
        second_extract = client.post(f"/api/investigations/{investigation_id}/extract-claims", json={"kind": "url"})
        claim_id = _create(client, "A claim")
        token = _seal(client, claim_id)
        first_evidence = client.get(f"/api/investigations/{claim_id}/evidence")
        second_evidence = client.get(f"/api/investigations/{claim_id}/evidence")
        lookup = sqlite3.connect(path)
        try:
            owner_id = lookup.execute(
                "SELECT owner_id FROM investigations WHERE id = ?",
                (claim_id,),
            ).fetchone()[0]
        finally:
            lookup.close()
        Ledger(path).hit_rate_limit("assess", owner_id, 1, 3600)
        blocked = client.post(f"/api/investigations/{claim_id}/assess", json={"assessmentToken": token})
        second_seal = client.post(f"/api/investigations/{claim_id}/seal")
    conn = sqlite3.connect(path)
    try:
        consumed = conn.execute(
            "SELECT consumed_at FROM assessment_snapshots WHERE investigation_id = ?",
            (claim_id,),
        ).fetchone()[0]
    finally:
        conn.close()
    assert first_fetch.status_code == 200
    assert second_fetch.status_code == 429
    assert calls["fetch"] == 1
    assert first_extract.status_code == 200
    assert second_extract.status_code == 429
    assert first_evidence.status_code == 200
    assert second_evidence.status_code == 429
    assert second_seal.status_code == 429
    assert blocked.status_code == 429
    assert blocked.json() == LIMITED
    assert calls["openai"] == 1
    assert consumed is None


def test_rate_window_expires_and_concurrent_hits_cannot_share_one_slot(tmp_path):
    ledger = Ledger(tmp_path / "ledger.sqlite")
    start = 1_700_000_000
    assert ledger.hit_rate_limit("login", "203.0.113.8", 1, 60, now=start)[0] is True
    blocked = ledger.hit_rate_limit("login", "203.0.113.8", 1, 60, now=start + 10)
    assert blocked[0] is False
    assert 1 <= blocked[1] <= 60
    assert ledger.hit_rate_limit("login", "203.0.113.8", 1, 60, now=start + 60)[0] is True
    ledger.hit_rate_limit("search", "user", 5, 60, now=start + 3 * 60 * 60)
    conn = sqlite3.connect(tmp_path / "ledger.sqlite")
    try:
        old = conn.execute("SELECT COUNT(*) FROM rate_limits WHERE window_start < ?", (start + 60 * 60,)).fetchone()[0]
    finally:
        conn.close()
    assert old == 0

    results = []
    barrier = threading.Barrier(6)

    def worker():
        barrier.wait()
        results.append(ledger.hit_rate_limit("assess", "same-user", 1, 3600)[0])

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count(True) == 1
    assert results.count(False) == 5


def test_oversized_body_is_rejected_without_echoing_it(tmp_path):
    app = create_app(settings=_settings(ledger_path=_ledger(tmp_path)))
    secret = "password-must-not-be-logged"
    oversized = b'{"email":"a@example.com","password":"' + secret.encode() + b'","pad":"' + (b"x" * MAX_BODY_BYTES) + b'"}'
    exact = b"x" * MAX_BODY_BYTES
    with TestClient(app) as client:
        too_big = client.post("/api/auth/login", content=oversized, headers={"content-type": "application/json"})
        boundary = client.post("/api/auth/login", content=exact, headers={"content-type": "application/json"})
    assert too_big.status_code == 413
    assert too_big.json() == {"code": "request_too_large", "message": "The request is too large."}
    assert secret not in too_big.text
    assert boundary.status_code != 413


def test_an_oversized_asgi_message_is_rejected_before_it_is_buffered():
    seen = {}

    async def inner(scope, receive, send):
        message = await receive()
        seen["body"] = message.get("body", b"")
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    async def once(body, more=False):
        sent = []
        calls = {"n": 0}

        async def receive():
            calls["n"] += 1
            if calls["n"] == 1:
                return {"type": "http.request", "body": body, "more_body": more}
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            sent.append(message)

        await RequestSizeLimit(inner)(
            {"type": "http", "method": "POST", "path": "/api/auth/login", "headers": []},
            receive,
            send,
        )
        return sent

    refused = asyncio.run(once(b"x" * (MAX_BODY_BYTES + 1)))
    assert refused[0]["status"] == 413
    assert "body" not in seen
    seen.clear()
    parts = [b"y" * MAX_BODY_BYTES, b"z"]

    async def two():
        sent = []
        calls = {"n": 0}

        async def receive():
            calls["n"] += 1
            if calls["n"] <= len(parts):
                return {"type": "http.request", "body": parts[calls["n"] - 1], "more_body": calls["n"] < len(parts)}
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            sent.append(message)

        await RequestSizeLimit(inner)(
            {"type": "http", "method": "POST", "path": "/api/auth/login", "headers": []},
            receive,
            send,
        )
        return sent

    chunked = asyncio.run(two())
    assert chunked[0]["status"] == 413
    assert "body" not in seen
    seen.clear()
    accepted = asyncio.run(once(b"x" * MAX_BODY_BYTES))
    assert accepted[0]["status"] == 200
    assert seen["body"] == b"x" * MAX_BODY_BYTES


def test_blank_claim_query_and_url_do_not_call_providers(tmp_path):
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return _json_response({"results": [], "session_id": "s"})

    app = create_app(
        settings=_settings(ledger_path=_ledger(tmp_path), parallel_api_key=DUMMY_PARALLEL, openai_api_key=DUMMY_OPENAI),
        parallel_transport=httpx.MockTransport(handler),
        openai_transport=httpx.MockTransport(handler),
    )
    with TestClient(app) as client:
        investigation_id = _create(client, "A real claim")
        blank_claim = client.post("/api/investigations", json={"input": "   ", "kind": "claim"})
        blank_url = client.post("/api/investigations", json={"input": " \n ", "kind": "url"})
        blank_query = client.post(f"/api/investigations/{investigation_id}/search", json={"queries": [" ", ""]})
        missing_query = client.post(f"/api/investigations/{investigation_id}/search", json={"queries": []})
        not_url = client.post(f"/api/investigations/{investigation_id}/fetch")
    assert blank_claim.status_code == 400
    assert blank_claim.json()["code"] == "empty_input"
    assert blank_url.status_code == 400
    assert blank_query.status_code == 400
    assert blank_query.json()["code"] == "empty_query"
    assert missing_query.status_code == 400
    assert not_url.status_code == 400
    assert not_url.json()["code"] == "bad_url"
    assert calls["n"] == 0


def test_limits_do_not_log_secrets(caplog, tmp_path):
    app = create_app(settings=_settings(ledger_path=_ledger(tmp_path)), limits={"login": (1, 900)})
    secret = "another-secret-password"
    with caplog.at_level(logging.DEBUG):
        with TestClient(app) as client:
            client.post("/api/auth/login", json={"email": "person@example.com", "password": secret})
            blocked = client.post("/api/auth/login", json={"email": "person@example.com", "password": secret})
    assert blocked.status_code == 429
    assert secret not in blocked.text
    assert secret not in caplog.text


def _logged_in(client: TestClient) -> str:
    if client.cookies.get("rc_session"):
        return client.headers.get("X-CSRF-Token", "")
    client.post("/api/auth/register", json={"email": "owner@example.com", "password": PASSWORD})
    logged = client.post("/api/auth/login", json={"email": "owner@example.com", "password": PASSWORD})
    assert logged.status_code == 200, logged.text
    client.headers["X-CSRF-Token"] = logged.json()["csrfToken"]
    return logged.json()["csrfToken"]
