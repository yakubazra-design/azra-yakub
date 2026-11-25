"""Single-use assessment tokens and sealed evidence snapshots."""

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

import httpx
from fastapi.testclient import TestClient

from app.auth import session_mac
from app.ledger import Ledger
from app.main import create_app
from test_api import DUMMY_OPENAI, _create, _json_response, _seal, _settings

PASSWORD = "correct-horse-battery"


def _login(client: TestClient, email: str):
    client.post("/api/auth/register", json={"email": email, "password": PASSWORD})
    logged = client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    assert logged.status_code == 200
    client.headers["X-CSRF-Token"] = logged.json()["csrfToken"]


def _assessment():
    return _json_response({"choices": [{"message": {"content": json.dumps({
        "assessment": "INSUFFICIENT_EVIDENCE",
        "findings": [],
        "why": {},
        "uncertainty": [],
    })}}]})


def test_seal_stores_a_hash_and_returns_the_token_once(tmp_path):
    path = tmp_path / "ledger.sqlite"
    app = create_app(settings=_settings(ledger_path=str(path), openai_api_key=DUMMY_OPENAI))
    with TestClient(app) as client:
        investigation_id = _create(client, "Warm water cures diabetes.")
        sealed = client.post(f"/api/investigations/{investigation_id}/seal")
    body = sealed.json()
    token = body["assessmentToken"]
    expires = datetime.fromisoformat(body["expiresAt"])
    remaining = expires - datetime.now(timezone.utc)
    raw = path.read_bytes()
    conn = sqlite3.connect(path)
    try:
        stored = conn.execute("SELECT token_hash, snapshot_json FROM assessment_snapshots").fetchone()
    finally:
        conn.close()
    assert sealed.status_code == 200
    assert set(body) == {"assessmentToken", "expiresAt"}
    assert 590 <= remaining.total_seconds() <= 600
    assert token.encode() not in raw
    assert stored[0] != token
    assert "Warm water cures diabetes." in stored[1]


def test_forged_expired_and_replayed_tokens_are_rejected(tmp_path):
    path = tmp_path / "ledger.sqlite"
    secret = "s" * 32
    app = create_app(
        settings=_settings(ledger_path=str(path), auth_secret=secret, openai_api_key=DUMMY_OPENAI),
        openai_transport=httpx.MockTransport(lambda _request: httpx.Response(500, json={"error": "down"})),
    )
    with TestClient(app) as client:
        investigation_id = _create(client, "A claim")
        forged = client.post(f"/api/investigations/{investigation_id}/assess", json={
            "assessmentToken": "forged-assessment-token",
            "primaryClaim": "FORGED",
        })
        expired_token = "expired-assessment-token-value"
        lookup = sqlite3.connect(path)
        try:
            owner_id = lookup.execute(
                "SELECT owner_id FROM investigations WHERE id = ?",
                (investigation_id,),
            ).fetchone()[0]
        finally:
            lookup.close()
        Ledger(path).seal_assessment(
            owner_id,
            investigation_id,
            session_mac(secret, expired_token),
            {"primaryClaim": "A claim", "verifiablePoints": [], "sources": [], "independence": {}, "timeline": {}},
            "2000-01-01T00:00:00+00:00",
        )
        expired = client.post(f"/api/investigations/{investigation_id}/assess", json={"assessmentToken": expired_token})
        expired_again = client.post(f"/api/investigations/{investigation_id}/assess", json={"assessmentToken": expired_token})
        fresh = _seal(client, investigation_id)
        failed = client.post(f"/api/investigations/{investigation_id}/assess", json={"assessmentToken": fresh})
        replay = client.post(f"/api/investigations/{investigation_id}/assess", json={"assessmentToken": fresh})
    conn = sqlite3.connect(path)
    try:
        consumed = conn.execute(
            "SELECT consumed_at FROM assessment_snapshots WHERE expires_at = '2000-01-01T00:00:00+00:00'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert forged.status_code == 403
    assert forged.json()["code"] == "assessment_token_invalid"
    assert "forged-assessment-token" not in forged.text
    assert expired.status_code == expired_again.status_code == 403
    assert expired.json()["code"] == expired_again.json()["code"] == "assessment_token_expired"
    assert consumed is None
    assert failed.status_code == 502
    assert replay.status_code == 403
    assert replay.json()["code"] == "assessment_token_used"


def test_a_token_cannot_be_consumed_twice_at_the_same_time(tmp_path):
    ledger = Ledger(tmp_path / "ledger.sqlite")
    owner = ledger.create_owner()
    investigation_id = ledger.create_investigation(owner, "claim", "Claim")
    token_hash = "ab" * 32
    snapshot = {
        "primaryClaim": "Claim",
        "verifiablePoints": ["Claim"],
        "sources": [],
        "independence": {},
        "timeline": {},
    }
    expires = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    assert ledger.seal_assessment(owner, investigation_id, token_hash, snapshot, expires)
    barrier = threading.Barrier(2)
    results = []

    def worker():
        barrier.wait()
        results.append(ledger.consume_assessment(owner, investigation_id, token_hash)[1])

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(results) == ["ok", "used"]


def test_another_user_or_investigation_cannot_spend_the_token(tmp_path):
    path = tmp_path / "ledger.sqlite"
    app = create_app(
        settings=_settings(ledger_path=str(path), openai_api_key=DUMMY_OPENAI),
        openai_transport=httpx.MockTransport(lambda _request: _assessment()),
    )
    with TestClient(app) as owner, TestClient(app) as other:
        _login(owner, "owner@example.com")
        _login(other, "other@example.com")
        first = owner.post("/api/investigations", json={"input": "First claim", "kind": "claim"}).json()["investigationId"]
        second = owner.post("/api/investigations", json={"input": "Second claim", "kind": "claim"}).json()["investigationId"]
        theirs = other.post("/api/investigations", json={"input": "Other claim", "kind": "claim"}).json()["investigationId"]
        token = _seal(owner, first)
        stolen_case = other.post(f"/api/investigations/{first}/assess", json={"assessmentToken": token})
        wrong_case = owner.post(f"/api/investigations/{second}/assess", json={"assessmentToken": token})
        other_case = other.post(f"/api/investigations/{theirs}/assess", json={"assessmentToken": token})
        kept = owner.post(f"/api/investigations/{first}/assess", json={
            "assessmentToken": token,
            "primaryClaim": "FORGED",
            "snapshot": {"primaryClaim": "FORGED"},
        })
    conn = sqlite3.connect(path)
    try:
        rows = conn.execute("SELECT investigation_id, consumed_at FROM assessment_snapshots").fetchall()
    finally:
        conn.close()
    assert stolen_case.status_code == 404
    assert wrong_case.status_code == 403
    assert wrong_case.json()["code"] == "assessment_token_invalid"
    assert other_case.status_code == 403
    assert other_case.json()["code"] == "assessment_token_invalid"
    assert kept.status_code == 200
    assert rows == [(first, rows[0][1])]
    assert rows[0][1] is not None


def test_later_edits_do_not_change_the_sealed_snapshot(tmp_path):
    path = tmp_path / "ledger.sqlite"
    calls = {"n": 0}
    seen = {}

    def parallel_handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        url = "https://www.cdc.gov/first" if calls["n"] == 1 else "https://www.reuters.com/second"
        title = "First source" if calls["n"] == 1 else "Second source"
        return _json_response({
            "results": [{"url": url, "title": title, "publish_date": "2024-03-12", "excerpts": ["Kept text."]}],
            "session_id": "s",
        })

    def openai_handler(request: httpx.Request) -> httpx.Response:
        seen["prompt"] = json.loads(request.content.decode())["messages"][0]["content"]
        return _assessment()

    app = create_app(
        settings=_settings(ledger_path=str(path), openai_api_key=DUMMY_OPENAI, parallel_api_key="test-parallel-key"),
        parallel_transport=httpx.MockTransport(parallel_handler),
        openai_transport=httpx.MockTransport(openai_handler),
    )
    with TestClient(app) as client:
        investigation_id = _create(client, "A claim")
        client.post(f"/api/investigations/{investigation_id}/search", json={"queries": ["first"]})
        token = _seal(client, investigation_id)
        client.post(f"/api/investigations/{investigation_id}/search", json={"queries": ["second"]})
        response = client.post(f"/api/investigations/{investigation_id}/assess", json={
            "assessmentToken": token,
            "primaryClaim": "FORGED-PRIMARY",
            "sources": [{"url": "https://evil.example/forged", "title": "Forged", "snippet": "no"}],
            "independence": {"note": "CLIENT-SUPPLIED-NOTE", "totalSources": 9},
            "timeline": {"entries": [{"date": "1999-01-01", "desc": "Forged", "certainty": "confirmed"}]},
            "snapshot": {"primaryClaim": "SNAPSHOT-FORGED", "sources": [{"url": "https://evil.example/snap"}]},
        })
        live = client.get(f"/api/investigations/{investigation_id}/evidence").json()
    conn = sqlite3.connect(path)
    try:
        stored = conn.execute("SELECT snapshot_json FROM assessment_snapshots").fetchone()[0]
        try:
            conn.execute("UPDATE assessment_snapshots SET snapshot_json = ?", ('{"primaryClaim":"changed"}',))
            conn.commit()
            changed = True
        except sqlite3.IntegrityError:
            conn.rollback()
            changed = False
        after = conn.execute("SELECT snapshot_json FROM assessment_snapshots").fetchone()[0]
    finally:
        conn.close()
    assert response.status_code == 200
    assert "title=First source" in seen["prompt"]
    assert "host=cdc.gov" in seen["prompt"]
    assert "title=Second source" not in seen["prompt"]
    assert "reuters.com" not in seen["prompt"]
    assert "evil.example" not in seen["prompt"]
    assert "FORGED-PRIMARY" not in seen["prompt"]
    assert "SNAPSHOT-FORGED" not in seen["prompt"]
    assert "CLIENT-SUPPLIED-NOTE" not in seen["prompt"]
    assert "1999-01-01" not in seen["prompt"]
    assert live["sources"][0]["url"] == "https://www.reuters.com/second"
    assert "https://www.cdc.gov/first" in stored
    assert changed is False
    assert after == stored
