"""Transport-adapter tests. Live Parallel calls are marked integration."""

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from backend.app.errors import AppError
from backend.app.main import app
from backend.app.parallel_mcp import has_usable_fetch_content, normalize_tool_payload


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_health_hides_secrets(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["parallel_configured"] is True
    assert "api_key" not in json.dumps(body).lower()
    assert "sk-" not in json.dumps(body)


def test_invalid_url_rejected(client):
    response = client.post(
        "/api/investigations/fetch",
        json={
            "urls": ["file:///etc/passwd"],
            "objective": "Extract the page text needed to identify the factual claims it makes.",
            "full_content": True,
            "session_id": "rc-test",
        },
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"


def test_private_url_rejected(client):
    response = client.post(
        "/api/investigations/fetch",
        json={
            "urls": ["http://127.0.0.1/secret"],
            "objective": "Extract the page text needed to identify the factual claims it makes.",
            "full_content": True,
            "session_id": "rc-test",
        },
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"


def test_missing_openai_configuration(client):
    response = client.post(
        "/api/investigations/extract-claims",
        json={"prompt": "Reply with JSON only.", "modelTier": "default"},
    )
    assert response.status_code == 503
    body = response.json()
    assert body["error"]["code"] == "not_configured"
    assert "INSUFFICIENT_EVIDENCE" not in json.dumps(body)
    assert "OPENAI_API_KEY" not in body["error"]["message"] or "not set" in body["error"]["message"].lower() or "not configured" in body["error"]["message"].lower()


def test_wrong_model_tier(client):
    response = client.post(
        "/api/investigations/assess",
        json={"prompt": "Reply with JSON only.", "modelTier": "default"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"


def test_empty_search_stays_empty(client, monkeypatch):
    def fake_search(_arguments, _timeout):
        return {
            "results": [],
            "errors": [],
            "warnings": [],
            "session_id": "rc-test",
        }

    monkeypatch.setattr(client.app.state.parallel, "search", fake_search)
    response = client.post(
        "/api/investigations/search",
        json={
            "objective": "Find sources that confirm, contradict, or provide context for the claim being investigated.",
            "search_queries": ["underground city on Mars"],
            "session_id": "rc-test",
        },
    )
    assert response.status_code == 200
    payload = response.json()["payload"]
    assert payload["results"] == []
    assert "assessment" not in response.json()


def test_fetch_empty_is_technical_failure(client, monkeypatch):
    def fake_fetch(_arguments, _timeout):
        return {"results": [], "errors": ["The page returned no usable content."], "warnings": []}

    monkeypatch.setattr(client.app.state.parallel, "fetch", fake_fetch)
    response = client.post(
        "/api/investigations/fetch",
        json={
            "urls": ["https://www.britannica.com/topic/Eiffel-Tower-Paris-France"],
            "objective": "Extract the page text needed to identify the factual claims it makes.",
            "full_content": True,
            "session_id": "rc-test",
        },
    )
    assert response.status_code == 502
    body = response.json()
    assert body["error"]["code"] == "fetch_empty"
    assert body["error"]["code"] != "INSUFFICIENT_EVIDENCE"


def test_missing_parallel_configuration(client, monkeypatch):
    def fake_search(_arguments, _timeout):
        raise AppError(503, "not_configured", "Parallel Search MCP is not configured. Set PARALLEL_MCP_URL.", False)

    monkeypatch.setattr(client.app.state.parallel, "search", fake_search)
    response = client.post(
        "/api/investigations/search",
        json={
            "objective": "Find sources.",
            "search_queries": ["Eiffel Tower Paris"],
            "session_id": "rc-test",
        },
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "not_configured"


def test_normalize_does_not_invent_dates():
    payload = normalize_tool_payload(
        {
            "results": [
                {"url": "https://example.com/a", "title": "A", "publish_date": None, "excerpts": ["text"]},
                {"url": "https://example.com/b", "title": "B", "excerpts": []},
            ],
            "warnings": None,
            "session_id": "rc-1",
        },
        include_full_content=False,
    )
    assert payload["results"][0]["publish_date"] is None
    assert payload["results"][1]["publish_date"] is None
    assert "full_content" not in payload["results"][0]
    assert payload["warnings"] == []


def test_fetch_content_detection():
    assert has_usable_fetch_content({"results": [{"full_content": "  ", "excerpts": []}]}) is False
    assert has_usable_fetch_content({"results": [{"full_content": None, "excerpts": ["page"]}]}) is True


@pytest.mark.integration
def test_live_searches_and_fetch(client):
    session = "rc-live-phase5-transport-test"

    eiffel = client.post(
        "/api/investigations/search",
        json={
            "objective": "Find sources that confirm, contradict, or provide context for the claim being investigated.",
            "search_queries": ["Eiffel Tower located Paris"],
            "session_id": session,
        },
    )
    assert eiffel.status_code == 200, eiffel.text
    eiffel_results = eiffel.json()["payload"]["results"]
    assert eiffel_results, "expected real Eiffel Tower results"
    for item in eiffel_results:
        assert item["url"].startswith("http")
        assert item["title"]
        assert item["publish_date"] is None or isinstance(item["publish_date"], str)

    water = client.post(
        "/api/investigations/search",
        json={
            "objective": "Find sources that confirm, contradict, or provide context for the claim being investigated.",
            "search_queries": ["eight glasses water daily necessary"],
            "session_id": session,
        },
    )
    assert water.status_code == 200, water.text
    assert water.json()["payload"]["results"], "expected real water-claim sources"

    mars = client.post(
        "/api/investigations/search",
        json={
            "objective": "Find sources that confirm, contradict, or provide context for the claim being investigated.",
            "search_queries": ["underground city discovered Mars"],
            "session_id": session,
        },
    )
    assert mars.status_code == 200, mars.text
    mars_body = mars.json()
    assert "assessment" not in mars_body
    for item in mars_body["payload"]["results"]:
        assert item["url"].startswith("http")
        assert "publish_date" in item

    fetched = client.post(
        "/api/investigations/fetch",
        json={
            "urls": ["https://www.britannica.com/topic/Eiffel-Tower-Paris-France"],
            "objective": "Extract the page text needed to identify the factual claims it makes.",
            "full_content": True,
            "session_id": session,
        },
    )
    assert fetched.status_code == 200, fetched.text
    page = fetched.json()["payload"]["results"][0]
    assert page["url"].startswith("https://www.britannica.com/")
    assert isinstance(page.get("full_content"), str) and page["full_content"].strip()
