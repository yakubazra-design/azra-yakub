"""Non-live tests. Parallel and OpenAI are replaced with in-process HTTP mocks."""

import json

import httpx
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

DUMMY_PARALLEL = "test-parallel-key"
DUMMY_OPENAI = "test-openai-key"


def _settings(**overrides) -> Settings:
    data = dict(
        openai_api_key="",
        parallel_api_key="",
        parallel_mcp_url="https://search.parallel.ai/mcp",
        openai_model_default="gpt-4.1-mini",
        openai_model_complex="gpt-4.1",
        allowed_origins="",
    )
    data.update(overrides)
    return Settings(**data)


def _json_response(payload, status=200):
    return httpx.Response(status, json=payload)


def test_health_reports_configuration_without_secrets():
    app = create_app(settings=_settings())
    with TestClient(app) as client:
        response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body == {
        "status": "ok",
        "openaiConfigured": False,
        "parallelConfigured": False,
    }
    assert DUMMY_OPENAI not in response.text
    assert DUMMY_PARALLEL not in response.text


def test_health_configured_flags_when_keys_present():
    app = create_app(settings=_settings(openai_api_key=DUMMY_OPENAI, parallel_api_key=DUMMY_PARALLEL))
    with TestClient(app) as client:
        body = client.get("/api/health").json()
    assert body["openaiConfigured"] is True
    assert body["parallelConfigured"] is True
    assert DUMMY_OPENAI not in json.dumps(body)
    assert DUMMY_PARALLEL not in json.dumps(body)


def test_search_maps_parallel_results_and_clamps_queries():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["key"] = request.headers.get("x-api-key")
        seen["body"] = json.loads(request.content.decode())
        return _json_response({
            "search_id": "search_test",
            "session_id": "session-from-parallel",
            "results": [
                {
                    "url": "https://www.cdc.gov/example",
                    "title": "Published: Example finding",
                    "publish_date": "2024-05-01",
                    "excerpts": ["Posted on the agency site.", "Second excerpt."],
                },
                {"title": "missing url"},
            ],
        })

    app = create_app(
        settings=_settings(parallel_api_key=DUMMY_PARALLEL),
        parallel_transport=httpx.MockTransport(handler),
    )
    with TestClient(app) as client:
        response = client.post("/api/investigations/search", json={
            "queries": ["one two three four five six seven extra", "   ", "second query"],
            "sessionId": "rc-fixed",
        })
    assert response.status_code == 200
    body = response.json()
    assert seen["path"] == "/v1/search"
    assert seen["key"] == DUMMY_PARALLEL
    assert seen["body"]["objective"].startswith("Find sources that confirm, contradict")
    assert seen["body"]["search_queries"] == ["one two three four five six", "second query"]
    assert seen["body"]["session_id"] == "rc-fixed"
    assert body["sessionId"] == "session-from-parallel"
    assert body["sources"] == [{
        "url": "https://www.cdc.gov/example",
        "title": "Published: Example finding",
        "snippet": "Posted on the agency site. Second excerpt.",
        "publishedAt": "2024-05-01",
        "dateCertainty": "provider-reported",
        "dateType": "published",
        "provider": "Parallel Search",
    }]
    assert DUMMY_PARALLEL not in response.text


def test_search_retries_once_then_succeeds():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(503, json={"error": {"message": "temporary"}})
        return _json_response({"results": [], "session_id": "s2"})

    app = create_app(
        settings=_settings(parallel_api_key=DUMMY_PARALLEL),
        parallel_transport=httpx.MockTransport(handler),
    )
    with TestClient(app) as client:
        response = client.post("/api/investigations/search", json={"queries": ["warm water claim"]})
    assert response.status_code == 200
    assert calls["n"] == 2
    assert response.json()["sources"] == []


def test_search_requires_server_key_and_hides_it():
    app = create_app(settings=_settings())
    with TestClient(app) as client:
        response = client.post("/api/investigations/search", json={"queries": ["a claim"]})
    assert response.status_code == 503
    assert response.json()["code"] == "not_configured"
    assert "key" not in response.json()["message"].lower() or "configured" in response.json()["message"].lower()


def test_fetch_uses_full_content_and_reports_empty():
    seen = {}

    def ok(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content.decode())
        return _json_response({
            "results": [{
                "url": "https://example.com/page",
                "title": "Updated: Page",
                "publish_date": "2020-01-02",
                "full_content": "Last updated January. Full page text.",
                "excerpts": ["ignored when full content exists"],
            }],
            "errors": [],
            "session_id": "fetch-session",
        })

    app = create_app(
        settings=_settings(parallel_api_key=DUMMY_PARALLEL),
        parallel_transport=httpx.MockTransport(ok),
    )
    with TestClient(app) as client:
        response = client.post("/api/investigations/fetch", json={"url": "https://example.com/page"})
    assert response.status_code == 200
    assert seen["body"]["objective"] == "Extract the page text needed to identify the factual claims it makes."
    assert seen["body"]["advanced_settings"] == {"full_content": True}
    page = response.json()
    assert page["text"] == "Last updated January. Full page text."
    assert page["dateType"] == "updated"
    assert page["publishedAt"] == "2020-01-02"
    assert DUMMY_PARALLEL not in response.text

    def empty(_request: httpx.Request) -> httpx.Response:
        return _json_response({"results": [], "errors": [{"content": "blocked"}], "session_id": "e"})

    app_empty = create_app(
        settings=_settings(parallel_api_key=DUMMY_PARALLEL),
        parallel_transport=httpx.MockTransport(empty),
    )
    with TestClient(app_empty) as client:
        missing = client.post("/api/investigations/fetch", json={"url": "https://example.com/missing"})
    assert missing.status_code == 502
    assert missing.json()["code"] == "fetch_empty"
    assert missing.json()["message"] == "blocked"


def test_fetch_rejects_non_web_address():
    app = create_app(settings=_settings(parallel_api_key=DUMMY_PARALLEL))
    with TestClient(app) as client:
        response = client.post("/api/investigations/fetch", json={"url": "not a url"})
    assert response.status_code == 400
    assert response.json()["code"] == "bad_url"


def test_extract_claims_preserves_prompt_and_normalises():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = json.loads(request.content.decode())
        content = json.dumps({
            "hasFactualClaim": True,
            "primaryClaim": "",
            "verifiablePoints": ["a", "b", "c", "d", "e", "f", "g"],
            "excluded": [{"text": "opinion", "reason": "subjective"}],
            "searchQueries": ["q1", "q2", "q3", "q4", "q5", "q6"],
        })
        return _json_response({"choices": [{"message": {"content": content}}]})

    material = "Scientists discovered warm water cures diabetes. " + ("x" * 7000)
    app = create_app(
        settings=_settings(openai_api_key=DUMMY_OPENAI),
        openai_transport=httpx.MockTransport(handler),
    )
    with TestClient(app) as client:
        response = client.post("/api/investigations/extract-claims", json={"input": material, "kind": "claim"})
    assert response.status_code == 200
    prompt = seen["body"]["messages"][0]["content"]
    assert prompt.startswith("You are the claim-analysis stage of an evidence-investigation tool.\n")
    assert "Read the submitted text and identify only the factual assertions" in prompt
    assert "Opinions, predictions, questions and subjective statements are NOT factual claims." in prompt
    start = prompt.index('"""\n') + 4
    end = prompt.index('\n"""', start)
    assert end - start == 6000
    assert seen["body"]["model"] == "gpt-4.1-mini"
    assert seen["auth"] == "Bearer " + DUMMY_OPENAI
    body = response.json()
    assert body["hasFactualClaim"] is True
    assert body["primaryClaim"] == material[:300]
    assert len(body["verifiablePoints"]) == 6
    assert len(body["searchQueries"]) == 5
    assert DUMMY_OPENAI not in response.text


def test_extract_claims_unavailable_without_key():
    app = create_app(settings=_settings())
    with TestClient(app) as client:
        response = client.post("/api/investigations/extract-claims", json={"input": "A claim.", "kind": "claim"})
    assert response.status_code == 503
    assert response.json() == {
        "code": "no_model",
        "message": "Claim analysis is unavailable in this view.",
    }


def test_assess_preserves_prompt_validation_and_image_rules():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content.decode())
        content = json.dumps({
            "assessment": "VERIFIED",
            "findings": [
                {"type": "support", "text": "A real finding.", "sources": [0, 9, True]},
                {"type": "invented", "text": "  ", "sources": [0]},
                {"type": "nope", "text": "Downgraded.", "sources": [0]},
            ],
            "originalMaterial": {"established": True, "description": "Paper", "source": 4},
            "why": {"supporting": "Shown.", "contradicting": "", "sourceQuality": "High.", "timeline": "Dates.", "uncertain": "", "choice": "Because."},
            "uncertainty": ["  ", "Still open."],
        })
        return _json_response({"choices": [{"message": {"content": "```json\n" + content + "\n```"}}]})

    ctx = {
        "primaryClaim": "Warm water cures diabetes.",
        "verifiablePoints": ["Warm water cures diabetes."],
        "sources": [{
            "url": "https://www.cdc.gov/diabetes",
            "title": "Diabetes facts",
            "snippet": "According to the World Health Organization, warm water is not a cure.",
            "publishedAt": "2024-01-15",
            "quality": {"tier": "HIGH"},
        }],
        "independence": {
            "totalSources": 1,
            "uniqueHostCount": 1,
            "independentCount": 1,
            "note": "No two retrieved sources appear to share a publisher.",
            "hostGroups": [],
            "originGroups": [],
            "uncertainIndexes": [],
        },
        "timeline": {
            "entries": [{"date": "2024-01-15", "desc": "Diabetes facts", "certainty": "provider-reported"}],
            "missingCount": 0,
        },
        "imageEvidence": {
            "fileName": "photo.jpg",
            "fileType": "image/jpeg",
            "width": 10,
            "height": 20,
            "captureDate": None,
            "make": None,
            "model": None,
            "orientation": None,
            "software": "Adobe Photoshop",
            "gpsLat": 1.5,
            "gpsLon": 2,
            "sha256": "abc123",
        },
    }
    app = create_app(
        settings=_settings(openai_api_key=DUMMY_OPENAI),
        openai_transport=httpx.MockTransport(handler),
    )
    with TestClient(app) as client:
        response = client.post("/api/investigations/assess", json=ctx)
    assert response.status_code == 200
    prompt = seen["body"]["messages"][0]["content"]
    assert seen["body"]["model"] == "gpt-4.1"
    assert prompt.startswith("You are the assessment stage of an evidence-investigation tool.")
    assert "Never introduce a source, URL, date, study or organisation that is not in the list." in prompt
    assert "[0] host=cdc.gov | quality=HIGH | date=2024-01-15 | title=Diabetes facts" in prompt
    assert "IMAGE EVIDENCE (extracted locally from an uploaded file by the person" in prompt
    assert "file=photo.jpg | type=image/jpeg | dimensions=10x20" in prompt
    assert "GPS=1.500000,2.000000 | file hash (SHA-256)=abc123" in prompt
    assert "do not use POTENTIAL_MANIPULATION on this basis alone." in prompt
    assert "Choose exactly one assessment from: VERIFIED, PARTIALLY_VERIFIED, CONTRADICTED, INSUFFICIENT_EVIDENCE, POTENTIAL_MANIPULATION, UNRESOLVED." in prompt
    body = response.json()
    assert body["assessment"] == "VERIFIED"
    assert body["findings"] == [
        {"type": "support", "text": "A real finding.", "sources": [0]},
        {"type": "caution", "text": "Downgraded.", "sources": [0]},
    ]
    assert body["originalMaterial"]["established"] is False
    assert body["originalMaterial"]["source"] is None
    assert body["uncertainty"] == ["Still open."]
    assert DUMMY_OPENAI not in response.text


def test_assess_forces_insufficient_evidence_when_no_sources():
    def handler(_request: httpx.Request) -> httpx.Response:
        content = json.dumps({"assessment": "VERIFIED", "findings": [], "why": {}, "uncertainty": []})
        return _json_response({"choices": [{"message": {"content": content}}]})

    app = create_app(
        settings=_settings(openai_api_key=DUMMY_OPENAI),
        openai_transport=httpx.MockTransport(handler),
    )
    with TestClient(app) as client:
        response = client.post("/api/investigations/assess", json={
            "primaryClaim": "Nothing to check.",
            "verifiablePoints": [],
            "sources": [],
            "independence": {"totalSources": 0, "uniqueHostCount": 0, "independentCount": 0, "note": "None."},
            "timeline": {"entries": [], "missingCount": 0},
            "imageEvidence": None,
        })
    assert response.status_code == 200
    assert response.json()["assessment"] == "INSUFFICIENT_EVIDENCE"
