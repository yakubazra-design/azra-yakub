"""Persistence and ownership for the SQLite evidence ledger."""

import json
import sqlite3
import threading
import time

import pytest

import httpx
from fastapi.testclient import TestClient

from app.ledger import Ledger, LedgerError
from app.main import create_app
from test_api import DUMMY_OPENAI, DUMMY_PARALLEL, _create, _json_response, _ledger, _seal, _settings


def test_records_persist_across_a_new_connection(tmp_path):
    path = tmp_path / "ledger.sqlite"
    first = Ledger(path)
    owner = first.create_owner()
    investigation_id = first.create_investigation(owner, "claim", "Warm water cures diabetes.")
    stored = first.replace_sources(owner, investigation_id, [{
        "url": "https://www.cdc.gov/diabetes",
        "title": "Diabetes facts",
        "snippet": "No cure is described.",
        "publishedAt": "2024-01-15",
        "dateCertainty": "provider-reported",
        "dateType": "unspecified",
        "provider": "Parallel Search",
        "quality": {"tier": "HIGH", "reason": "Government domain."},
    }])
    second = Ledger(path)
    again = second.list_sources(owner, investigation_id)
    assert again[0]["id"] == stored[0]["id"]
    assert again[0]["url"] == "https://www.cdc.gov/diabetes"
    assert again[0]["provider"] == "Parallel Search"
    assert again[0]["dateCertainty"] == "provider-reported"
    assert again[0]["publishedAt"] == "2024-01-15"


def test_investigations_do_not_share_evidence_rows(tmp_path):
    ledger = Ledger(tmp_path / "ledger.sqlite")
    owner = ledger.create_owner()
    first = ledger.create_investigation(owner, "claim", "First")
    second = ledger.create_investigation(owner, "claim", "Second")
    ledger.replace_sources(owner, first, [{
        "url": "https://www.cdc.gov/a",
        "title": "A",
        "snippet": "alpha",
        "publishedAt": None,
        "dateCertainty": None,
        "dateType": None,
        "provider": "Parallel Search",
        "quality": {"tier": "HIGH", "reason": "Government domain."},
    }])
    ledger.replace_sources(owner, second, [{
        "url": "https://www.reuters.com/b",
        "title": "B",
        "snippet": "beta",
        "publishedAt": None,
        "dateCertainty": None,
        "dateType": None,
        "provider": "Parallel Search",
        "quality": {"tier": "MEDIUM", "reason": "News."},
    }])
    assert [source["url"] for source in ledger.list_sources(owner, first)] == ["https://www.cdc.gov/a"]
    assert [source["url"] for source in ledger.list_sources(owner, second)] == ["https://www.reuters.com/b"]


def test_another_owner_cannot_read_or_replace_evidence(tmp_path):
    def handler(_request: httpx.Request) -> httpx.Response:
        return _json_response({
            "results": [{"url": "https://www.cdc.gov/private", "title": "Private", "excerpts": ["kept"]}],
            "session_id": "s",
        })

    app = create_app(
        settings=_settings(ledger_path=_ledger(tmp_path), parallel_api_key=DUMMY_PARALLEL),
        parallel_transport=httpx.MockTransport(handler),
    )
    with TestClient(app) as owner, TestClient(app) as stranger:
        investigation_id = _create(owner, "Private claim")
        saved = owner.post(f"/api/investigations/{investigation_id}/search", json={"queries": ["claim"]})
        source_id = saved.json()["sources"][0]["id"]
        _create(stranger, "Someone else")
        hidden = stranger.get(f"/api/investigations/{investigation_id}/evidence")
        replaced = stranger.post(
            f"/api/investigations/{investigation_id}/assess",
            json={"primaryClaim": "Stolen", "sources": [{"url": "https://evil.example/x", "snippet": "no"}]},
        )
        still = owner.get(f"/api/investigations/{investigation_id}/evidence")
    assert hidden.status_code == 404
    assert replaced.status_code == 404
    assert still.json()["sources"][0]["id"] == source_id
    assert still.json()["sources"][0]["url"] == "https://www.cdc.gov/private"
    assert "evil.example" not in still.text


def test_assessment_ignores_replacement_evidence(tmp_path):
    seen = {}

    def parallel_handler(_request: httpx.Request) -> httpx.Response:
        return _json_response({
            "results": [{
                "url": "https://www.cdc.gov/diabetes",
                "title": "Diabetes facts",
                "publish_date": "2024-03-12",
                "excerpts": ["Warm water is not a treatment."],
            }],
            "session_id": "s",
        })

    def openai_handler(request: httpx.Request) -> httpx.Response:
        seen["prompt"] = json.loads(request.content.decode())["messages"][0]["content"]
        return _json_response({"choices": [{"message": {"content": json.dumps({
            "assessment": "INSUFFICIENT_EVIDENCE",
            "findings": [],
            "why": {},
            "uncertainty": [],
        })}}]})

    app = create_app(
        settings=_settings(ledger_path=_ledger(tmp_path), openai_api_key=DUMMY_OPENAI, parallel_api_key=DUMMY_PARALLEL),
        parallel_transport=httpx.MockTransport(parallel_handler),
        openai_transport=httpx.MockTransport(openai_handler),
    )
    with TestClient(app) as client:
        investigation_id = _create(client)
        client.post(f"/api/investigations/{investigation_id}/search", json={"queries": ["warm water"]})
        before = client.get(f"/api/investigations/{investigation_id}/evidence").json()
        response = client.post(f"/api/investigations/{investigation_id}/assess", json={
            "assessmentToken": _seal(client, investigation_id),
            "primaryClaim": "Warm water cures diabetes.",
            "sources": [{
                "url": "https://evil.example/replacement",
                "title": "Replacement",
                "snippet": "forged",
                "publishedAt": "1999-01-01",
                "dateCertainty": "confirmed",
                "quality": {"tier": "HIGH", "reason": "forged"},
            }],
            "independence": {"note": "CLIENT-SUPPLIED-NOTE", "totalSources": 9, "independentCount": 9, "uniqueHostCount": 9},
            "timeline": {"entries": [{"date": "1999-01-01", "desc": "Forged", "certainty": "confirmed"}], "missingCount": 0},
        })
        after = client.get(f"/api/investigations/{investigation_id}/evidence").json()
    assert response.status_code == 200
    assert before["sources"][0]["id"] == after["sources"][0]["id"]
    assert after["sources"][0]["dateCertainty"] == "provider-reported"
    assert "cdc.gov" in seen["prompt"]
    assert "provider-reported" in seen["prompt"]
    assert "evil.example" not in seen["prompt"]
    assert "1999-01-01" not in seen["prompt"]
    assert "CLIENT-SUPPLIED-NOTE" not in seen["prompt"]
    assert "(confirmed)" not in seen["prompt"]


def test_ledger_failure_does_not_reveal_the_file_path(tmp_path):
    blocker = tmp_path / "blocked"
    blocker.write_text("not a directory")
    try:
        Ledger(blocker / "ledger.sqlite")
    except LedgerError as exc:
        assert "blocked" not in str(exc)
    app = create_app(settings=_settings(ledger_path=str(blocker / "ledger.sqlite")))
    with TestClient(app) as client:
        response = client.post("/api/investigations", json={"input": "A claim", "kind": "claim"})
    assert response.status_code == 503
    assert response.json()["code"] == "ledger_unavailable"
    assert "blocked" not in response.text
    assert "sqlite" not in response.text.lower()


def test_delete_removes_related_rows_for_that_owner_only(tmp_path):
    ledger = Ledger(tmp_path / "ledger.sqlite")
    owner = ledger.create_owner()
    other = ledger.create_owner()
    investigation_id = ledger.create_investigation(owner, "url", "https://example.com/a")
    other_id = ledger.create_investigation(other, "claim", "Leave this")
    ledger.save_page(owner, investigation_id, {
        "requested_url": "https://example.com/a",
        "final_url": "https://example.com/a",
        "title": "Page",
        "body_text": "Body",
        "published_at": "2024-03-12",
        "date_certainty": "provider-reported",
        "date_type": "unspecified",
        "provider": "Parallel Search",
    })
    ledger.replace_sources(owner, investigation_id, [{
        "url": "https://www.cdc.gov/a",
        "title": "A",
        "snippet": "alpha",
        "publishedAt": "2024-03-12",
        "dateCertainty": "provider-reported",
        "dateType": "unspecified",
        "provider": "Parallel Search",
        "quality": {"tier": "HIGH", "reason": "Government domain."},
    }])
    assert ledger.save_claims(owner, investigation_id, "Stored primary", ["Stored point"]) is True
    assert ledger.delete_investigation(other, investigation_id) is False
    assert ledger.get_page(owner, investigation_id)["provider"] == "Parallel Search"
    assert ledger.get_claims(owner, investigation_id)["primaryClaim"] == "Stored primary"
    assert ledger.delete_investigation(owner, investigation_id) is True
    assert ledger.get_investigation(owner, investigation_id) is None
    assert ledger.list_sources(owner, investigation_id) is None
    assert ledger.get_page(owner, investigation_id) is None
    assert ledger.get_claims(owner, investigation_id) is None
    assert ledger.get_investigation(other, other_id)["input_text"] == "Leave this"
    conn = sqlite3.connect(tmp_path / "ledger.sqlite")
    try:
        assert conn.execute("SELECT COUNT(*) FROM evidence_sources").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM page_fetches").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM claim_analyses").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM investigations").fetchone()[0] == 1
    finally:
        conn.close()


def test_wal_busy_timeout_and_rolled_back_writes(tmp_path):
    path = tmp_path / "ledger.sqlite"
    ledger = Ledger(path)
    conn = ledger._connect()
    try:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    finally:
        conn.close()

    raw = sqlite3.connect(path, isolation_level=None)
    raw.execute("BEGIN")
    raw.execute("INSERT INTO users (id, created_at) VALUES ('abcd' || 'abcd', 't')")
    raw.execute("ROLLBACK")
    raw.close()
    assert ledger.owner_exists("abcdabcd") is False
    assert ledger.create_owner()


def test_interrupted_replace_keeps_the_previous_sources(tmp_path):
    path = tmp_path / "ledger.sqlite"
    ledger = Ledger(path)
    owner = ledger.create_owner()
    investigation_id = ledger.create_investigation(owner, "claim", "Keep")
    original = ledger.replace_sources(owner, investigation_id, [{
        "url": "https://www.cdc.gov/kept",
        "title": "Kept",
        "snippet": "stay",
        "publishedAt": "2024-01-15",
        "dateCertainty": "provider-reported",
        "dateType": "unspecified",
        "provider": "Parallel Search",
        "quality": {"tier": "HIGH", "reason": "Government domain."},
    }])
    raw = sqlite3.connect(path, isolation_level=None)
    raw.execute("""
        CREATE TRIGGER fail_second_source
        BEFORE INSERT ON evidence_sources
        WHEN (SELECT COUNT(*) FROM evidence_sources) >= 1
        BEGIN
            SELECT RAISE(ROLLBACK, 'disk');
        END
    """)
    raw.close()
    with pytest.raises(sqlite3.IntegrityError):
        ledger.replace_sources(owner, investigation_id, [
            {
                "url": "https://example.com/one",
                "title": "One",
                "snippet": "a",
                "publishedAt": None,
                "dateCertainty": None,
                "dateType": None,
                "provider": "Parallel Search",
                "quality": {"tier": "UNKNOWN", "reason": ""},
            },
            {
                "url": "https://example.com/two",
                "title": "Two",
                "snippet": "b",
                "publishedAt": None,
                "dateCertainty": None,
                "dateType": None,
                "provider": "Parallel Search",
                "quality": {"tier": "UNKNOWN", "reason": ""},
            },
        ])
    kept = ledger.list_sources(owner, investigation_id)
    assert [source["url"] for source in kept] == ["https://www.cdc.gov/kept"]
    assert kept[0]["id"] == original[0]["id"]
    assert kept[0]["provider"] == "Parallel Search"
    assert kept[0]["dateCertainty"] == "provider-reported"


def test_a_locked_database_waits_instead_of_failing_immediately(tmp_path):
    path = tmp_path / "ledger.sqlite"
    ledger = Ledger(path)
    holder = sqlite3.connect(path, isolation_level=None, timeout=5)
    holder.execute("BEGIN EXCLUSIVE")
    done = []
    errors = []

    def writer():
        try:
            done.append(ledger.create_owner())
        except Exception as exc:
            errors.append(exc)

    thread = threading.Thread(target=writer)
    thread.start()
    time.sleep(0.4)
    assert thread.is_alive()
    holder.execute("COMMIT")
    thread.join(3)
    holder.close()
    assert errors == []
    assert done
    assert ledger.owner_exists(done[0]) is True


def test_database_file_is_not_served(tmp_path):
    path = tmp_path / "ledger.sqlite"
    app = create_app(settings=_settings(ledger_path=str(path)))
    with TestClient(app) as client:
        _create(client, "A claim")
        response = client.get("/data/ledger.sqlite")
    assert b"SQLite format 3" not in response.content
    assert path.read_bytes().startswith(b"SQLite format 3")
