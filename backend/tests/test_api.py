"""Non-live tests. Parallel and OpenAI are replaced with in-process HTTP mocks."""

import json
from pathlib import Path
from secrets import token_hex

import httpx
from fastapi.testclient import TestClient

from app.config import Settings
from app.ledger import refuse_test_ledger
from app.main import create_app
from app.validation import UNESTABLISHED_FINDING_TEXT, controlled_explanation

DUMMY_PARALLEL = "test-parallel-key"
DUMMY_OPENAI = "test-openai-key"


def _ledger(directory: Path, name: str = "ledger.sqlite") -> str:
    """Return one temporary database path and reject the live ledger."""
    path = Path(directory) / name
    refuse_test_ledger(path)
    return str(path)


def _settings(**overrides) -> Settings:
    if "ledger_path" not in overrides:
        raise RuntimeError(
            "A test must pass ledger_path. The development ledger is not available to tests."
        )
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


def _ensure_auth(client: TestClient, email: str | None = None, password: str = "correct-horse-battery") -> dict:
    if client.cookies.get("rc_session"):
        return {"email": email or "", "csrfToken": client.headers.get("X-CSRF-Token", "")}
    email = email or f"user-{token_hex(4)}@example.com"
    registered = client.post("/api/auth/register", json={"email": email, "password": password})
    assert registered.status_code == 200, registered.text
    logged = client.post("/api/auth/login", json={"email": email, "password": password})
    assert logged.status_code == 200, logged.text
    client.headers["X-CSRF-Token"] = logged.json()["csrfToken"]
    return logged.json()


def _seal(client: TestClient, investigation_id: str) -> str:
    response = client.post(f"/api/investigations/{investigation_id}/seal")
    assert response.status_code == 200, response.text
    token = response.json()["assessmentToken"]
    assert token
    return token


def _create(client: TestClient, text: str = "A claim to check.", kind: str = "claim") -> str:
    _ensure_auth(client)
    response = client.post("/api/investigations", json={"input": text, "kind": kind})
    assert response.status_code == 200, response.text
    return response.json()["investigationId"]


def test_health_reports_configuration_without_secrets(tmp_path):
    app = create_app(settings=_settings(ledger_path=_ledger(tmp_path)))
    with TestClient(app) as client:
        response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body == {
        "status": "ok",
        "openaiConfigured": False,
        "parallelConfigured": False,
        "authReady": True,
        "videoIngestEnabled": False,
        "videoIngestAvailable": False,
    }
    assert DUMMY_OPENAI not in response.text
    assert DUMMY_PARALLEL not in response.text


def test_health_configured_flags_when_keys_present(tmp_path):
    app = create_app(settings=_settings(ledger_path=_ledger(tmp_path), openai_api_key=DUMMY_OPENAI, parallel_api_key=DUMMY_PARALLEL))
    with TestClient(app) as client:
        body = client.get("/api/health").json()
    assert body["openaiConfigured"] is True
    assert body["parallelConfigured"] is True
    assert DUMMY_OPENAI not in json.dumps(body)
    assert DUMMY_PARALLEL not in json.dumps(body)


def test_search_maps_parallel_results_and_clamps_queries(tmp_path):
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
        settings=_settings(ledger_path=_ledger(tmp_path), parallel_api_key=DUMMY_PARALLEL),
        parallel_transport=httpx.MockTransport(handler),
    )
    with TestClient(app) as client:
        investigation_id = _create(client)
        response = client.post(f"/api/investigations/{investigation_id}/search", json={
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
    assert body["investigationId"] == investigation_id
    stored = dict(body["sources"][0])
    assert stored.pop("id")
    assert stored == {
        "url": "https://www.cdc.gov/example",
        "title": "Published: Example finding",
        "snippet": "Posted on the agency site. Second excerpt.",
        "publishedAt": "2024-05-01",
        "dateCertainty": "provider-reported",
        "dateType": "published",
        "provider": "Parallel Search",
        "quality": {
            "tier": "HIGH",
            "reason": "Government domain — treated as an official primary source.",
        },
    }
    assert DUMMY_PARALLEL not in response.text


def test_search_retries_once_then_succeeds(tmp_path):
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(503, json={"error": {"message": "temporary"}})
        return _json_response({"results": [], "session_id": "s2"})

    app = create_app(
        settings=_settings(ledger_path=_ledger(tmp_path), parallel_api_key=DUMMY_PARALLEL),
        parallel_transport=httpx.MockTransport(handler),
    )
    with TestClient(app) as client:
        investigation_id = _create(client)
        response = client.post(f"/api/investigations/{investigation_id}/search", json={"queries": ["warm water claim"]})
    assert response.status_code == 200
    assert calls["n"] == 2
    assert response.json()["sources"] == []


def test_search_requires_server_key_and_hides_it(tmp_path):
    app = create_app(settings=_settings(ledger_path=_ledger(tmp_path)))
    with TestClient(app) as client:
        investigation_id = _create(client)
        response = client.post(f"/api/investigations/{investigation_id}/search", json={"queries": ["a claim"]})
    assert response.status_code == 503
    assert response.json()["code"] == "not_configured"
    assert "key" not in response.json()["message"].lower() or "configured" in response.json()["message"].lower()


def test_fetch_uses_full_content_and_reports_empty(tmp_path):
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
        settings=_settings(ledger_path=_ledger(tmp_path), parallel_api_key=DUMMY_PARALLEL),
        parallel_transport=httpx.MockTransport(ok),
    )
    with TestClient(app) as client:
        investigation_id = _create(client, "https://example.com/page", "url")
        response = client.post(f"/api/investigations/{investigation_id}/fetch")
    assert response.status_code == 200
    assert seen["body"]["objective"] == "Extract the page text needed to identify the factual claims it makes."
    assert seen["body"]["advanced_settings"] == {"full_content": True}
    page = response.json()
    assert page["text"] == "Last updated January. Full page text."
    assert page["dateType"] == "updated"
    assert page["publishedAt"] == "2020-01-02"
    assert page["quality"]["tier"] == "UNKNOWN"
    assert DUMMY_PARALLEL not in response.text

    def empty(_request: httpx.Request) -> httpx.Response:
        return _json_response({"results": [], "errors": [{"content": "blocked"}], "session_id": "e"})

    app_empty = create_app(
        settings=_settings(ledger_path=_ledger(tmp_path), parallel_api_key=DUMMY_PARALLEL),
        parallel_transport=httpx.MockTransport(empty),
    )
    with TestClient(app_empty) as client:
        investigation_id = _create(client, "https://example.com/missing", "url")
        missing = client.post(f"/api/investigations/{investigation_id}/fetch")
    assert missing.status_code == 502
    assert missing.json()["code"] == "fetch_empty"
    assert missing.json()["message"] == "blocked"


def test_fetch_rejects_non_web_address(tmp_path):
    app = create_app(settings=_settings(ledger_path=_ledger(tmp_path), parallel_api_key=DUMMY_PARALLEL))
    with TestClient(app) as client:
        investigation_id = _create(client, "not a url", "url")
        response = client.post(f"/api/investigations/{investigation_id}/fetch")
    assert response.status_code == 400
    assert response.json()["code"] == "bad_url"
    assert response.json()["message"] == "Only http and https URLs are allowed."


def test_fetch_rejects_non_public_urls_without_calling_provider(tmp_path):
    blocked = [
        ("file:///etc/passwd", "Only http and https URLs are allowed."),
        ("http://127.0.0.1/secret", "That address is not allowed."),
        ("http://localhost/secret", "That host is not allowed."),
        ("http://10.0.0.1/", "That address is not allowed."),
        ("http://169.254.1.1/", "That address is not allowed."),
        ("http://user:pass@example.com/", "URLs must not include credentials."),
        ("http://foo.local/", "That host is not allowed."),
    ]

    def handler(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("provider was called")

    app = create_app(
        settings=_settings(ledger_path=_ledger(tmp_path), parallel_api_key=DUMMY_PARALLEL),
        parallel_transport=httpx.MockTransport(handler),
    )
    with TestClient(app) as client:
        for url, message in blocked:
            investigation_id = _create(client, url, "url")
            response = client.post(f"/api/investigations/{investigation_id}/fetch")
            assert response.status_code == 400, url
            assert response.json()["code"] == "bad_url"
            assert response.json()["message"] == message


def test_frontend_is_served_beside_the_api(tmp_path):
    app = create_app(settings=_settings(ledger_path=_ledger(tmp_path)))
    with TestClient(app) as client:
        page = client.get("/")
        health = client.get("/api/health")
        script = client.get("/engine.js")
        style = client.get("/styles.css")
    assert page.status_code == 200
    assert "RealityCheck AI" in page.text
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert script.status_code == 200
    assert "RC.engine" in script.text
    assert style.status_code == 200


def test_extract_claims_preserves_prompt_and_normalises(tmp_path):
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
        settings=_settings(ledger_path=_ledger(tmp_path), openai_api_key=DUMMY_OPENAI),
        openai_transport=httpx.MockTransport(handler),
    )
    with TestClient(app) as client:
        investigation_id = _create(client, material, "claim")
        response = client.post(
            f"/api/investigations/{investigation_id}/extract-claims",
            json={"input": "FORGED INPUT", "kind": "claim"},
        )
    assert response.status_code == 200
    prompt = seen["body"]["messages"][0]["content"]
    assert prompt.startswith("You are the claim-analysis stage of an evidence-investigation tool.\n")
    assert "Read the submitted text and identify only the factual assertions" in prompt
    assert "Opinions, predictions, questions and subjective statements are NOT factual claims." in prompt
    start = prompt.index('"""\n') + 4
    end = prompt.index('\n"""', start)
    assert end - start == 6000
    assert "FORGED INPUT" not in prompt
    assert seen["body"]["model"] == "gpt-4.1-mini"
    assert seen["auth"] == "Bearer " + DUMMY_OPENAI
    body = response.json()
    assert body["hasFactualClaim"] is True
    assert body["primaryClaim"] == material[:300]
    assert len(body["verifiablePoints"]) == 6
    assert len(body["searchQueries"]) == 5
    assert DUMMY_OPENAI not in response.text


def test_extract_claims_unavailable_without_key(tmp_path):
    app = create_app(settings=_settings(ledger_path=_ledger(tmp_path)))
    with TestClient(app) as client:
        investigation_id = _create(client, "A claim.", "claim")
        response = client.post(f"/api/investigations/{investigation_id}/extract-claims", json={"kind": "claim"})
    assert response.status_code == 503
    assert response.json() == {
        "code": "no_model",
        "message": "Claim analysis is unavailable in this view.",
    }


def test_assess_preserves_prompt_validation_and_image_rules(tmp_path):
    seen = {}

    def parallel_handler(_request: httpx.Request) -> httpx.Response:
        return _json_response({
            "results": [{
                "url": "https://www.cdc.gov/diabetes",
                "title": "Diabetes facts",
                "publish_date": "2024-01-15",
                "excerpts": ["According to the World Health Organization, warm water is not a cure."],
            }],
            "session_id": "stored",
        })

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
        "primaryClaim": "FORGED-PRIMARY",
        "verifiablePoints": ["FORGED-POINT"],
        "sources": [{
            "url": "https://evil.example/injected",
            "title": "Injected source",
            "snippet": "This source must not be stored or assessed.",
            "publishedAt": "1999-01-01",
            "dateCertainty": "confirmed",
            "quality": {"tier": "LOW", "reason": "CLIENT-SUPPLIED-REASON"},
        }],
        "independence": {
            "totalSources": 99,
            "uniqueHostCount": 99,
            "independentCount": 99,
            "note": "CLIENT-SUPPLIED-NOTE",
            "hostGroups": [],
            "originGroups": [],
            "uncertainIndexes": [],
        },
        "timeline": {
            "entries": [{"date": "1999-01-01", "desc": "Forged date", "certainty": "confirmed"}],
            "missingCount": 8,
            "earliest": {"date": "1999-01-01", "certainty": "confirmed"},
        },
        "snapshot": {"primaryClaim": "SNAPSHOT-FORGED", "sources": [{"url": "https://evil.example/snap"}]},
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
        settings=_settings(ledger_path=_ledger(tmp_path), openai_api_key=DUMMY_OPENAI, parallel_api_key=DUMMY_PARALLEL),
        openai_transport=httpx.MockTransport(handler),
        parallel_transport=httpx.MockTransport(parallel_handler),
    )
    with TestClient(app) as client:
        investigation_id = _create(client, "Warm water cures diabetes.")
        stored = client.post(f"/api/investigations/{investigation_id}/search", json={"queries": ["warm water"]})
        assert stored.status_code == 200
        ctx["assessmentToken"] = _seal(client, investigation_id)
        response = client.post(f"/api/investigations/{investigation_id}/assess", json=ctx)
    assert response.status_code == 200
    prompt = seen["body"]["messages"][0]["content"]
    assert seen["body"]["model"] == "gpt-4.1"
    assert prompt.startswith("You are the assessment stage of an evidence-investigation tool.")
    assert "CLAIM: Warm water cures diabetes." in prompt
    assert "1. Warm water cures diabetes." in prompt
    assert "FORGED-PRIMARY" not in prompt
    assert "FORGED-POINT" not in prompt
    assert "SNAPSHOT-FORGED" not in prompt
    assert "Never introduce a source, URL, date, study or organisation that is not in the list." in prompt
    assert "[0] host=cdc.gov | quality=HIGH | date=2024-01-15 | title=Diabetes facts" in prompt
    assert "CLIENT-SUPPLIED-NOTE" not in prompt
    assert "CLIENT-SUPPLIED-REASON" not in prompt
    assert "1 source(s) retrieved, 1 distinct publisher(s), 1 counted as independent" in prompt
    assert "TIMELINE: 2024-01-15 — Diabetes facts (provider-reported)" in prompt
    assert "Sources with no publication date: 0" in prompt
    assert "1999-01-01" not in prompt
    assert "(confirmed)" not in prompt
    assert "https://evil.example/injected" not in prompt
    assert "IMAGE EVIDENCE" not in prompt
    assert "photo.jpg" not in prompt
    assert "GPS=" not in prompt
    assert "abc123" not in prompt
    assert "Adobe Photoshop" not in prompt
    assert "No image file was sealed for this investigation." in prompt
    assert "do not use POTENTIAL_MANIPULATION on this basis alone." in prompt
    assert "Choose exactly one assessment from: VERIFIED, PARTIALLY_VERIFIED, CONTRADICTED, INSUFFICIENT_EVIDENCE, POTENTIAL_MANIPULATION, UNRESOLVED." in prompt
    body = response.json()
    explanation = controlled_explanation("UNRESOLVED")
    assert body["assessment"] == "UNRESOLVED"
    assert body["findings"] == [
        {
            "type": "caution",
            "text": UNESTABLISHED_FINDING_TEXT,
            "sources": [0],
            "evidenceStatus": "not_established",
            "alignmentReason": "paraphrase_not_established",
        },
        {
            "type": "caution",
            "text": UNESTABLISHED_FINDING_TEXT,
            "sources": [0],
            "evidenceStatus": "not_established",
            "alignmentReason": "paraphrase_not_established",
        },
    ]
    assert body["originalMaterial"]["established"] is False
    assert body["originalMaterial"]["description"] == ""
    assert body["originalMaterial"]["source"] is None
    assert body["why"] == explanation["why"]
    assert body["uncertainty"] == explanation["uncertainty"]
    assert "Shown." not in response.text
    assert "Still open." not in response.text
    assert DUMMY_OPENAI not in response.text


def test_assess_forces_insufficient_evidence_when_no_sources(tmp_path):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content.decode())
        content = json.dumps({"assessment": "VERIFIED", "findings": [], "why": {}, "uncertainty": []})
        return _json_response({"choices": [{"message": {"content": content}}]})

    app = create_app(
        settings=_settings(ledger_path=_ledger(tmp_path), openai_api_key=DUMMY_OPENAI),
        openai_transport=httpx.MockTransport(handler),
    )
    with TestClient(app) as client:
        investigation_id = _create(client, "Nothing to check.")
        response = client.post(f"/api/investigations/{investigation_id}/assess", json={
            "assessmentToken": _seal(client, investigation_id),
            "primaryClaim": "Nothing to check.",
            "verifiablePoints": [],
            "sources": [{"url": "https://evil.example/injected", "title": "Injected", "snippet": "no"}],
            "independence": {"totalSources": 0, "uniqueHostCount": 0, "independentCount": 0, "note": "None."},
            "timeline": {"entries": [], "missingCount": 0},
            "imageEvidence": None,
        })
    assert "evil.example" not in seen["body"]["messages"][0]["content"]
    assert response.status_code == 200
    assert response.json()["assessment"] == "INSUFFICIENT_EVIDENCE"


NOT_FOUND = {"code": "not_found", "message": "That investigation was not found."}


def test_assess_uses_stored_claim_analysis_and_leaves_image_metadata_out_of_sources(tmp_path):
    seen = {}

    def openai_handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        prompt = body["messages"][0]["content"]
        seen["prompt"] = prompt
        if "claim-analysis stage" in prompt:
            content = {
                "hasFactualClaim": True,
                "primaryClaim": "Stored primary claim",
                "verifiablePoints": ["Stored point"],
                "excluded": [],
                "searchQueries": ["stored query"],
            }
        else:
            content = {"assessment": "UNRESOLVED", "findings": [], "why": {}, "uncertainty": []}
        return _json_response({"choices": [{"message": {"content": json.dumps(content)}}]})

    app = create_app(
        settings=_settings(ledger_path=_ledger(tmp_path), openai_api_key=DUMMY_OPENAI, parallel_api_key=DUMMY_PARALLEL),
        openai_transport=httpx.MockTransport(openai_handler),
        parallel_transport=httpx.MockTransport(lambda _request: _json_response({"results": [], "session_id": "s"})),
    )
    with TestClient(app) as client:
        investigation_id = _create(client, "Submitted claim text")
        extracted = client.post(f"/api/investigations/{investigation_id}/extract-claims", json={
            "input": "FORGED INPUT",
            "kind": "claim",
        })
        before = client.get(f"/api/investigations/{investigation_id}/evidence").json()
        response = client.post(f"/api/investigations/{investigation_id}/assess", json={
            "assessmentToken": _seal(client, investigation_id),
            "primaryClaim": "Browser primary",
            "verifiablePoints": ["Browser point"],
            "sources": [{"url": "https://evil.example/from-image", "title": "Injected"}],
            "imageEvidence": {"fileName": "photo.jpg", "sha256": "abc", "software": "Adobe Photoshop"},
        })
        after = client.get(f"/api/investigations/{investigation_id}/evidence").json()
    assert extracted.status_code == 200
    assert extracted.json()["primaryClaim"] == "Stored primary claim"
    assert response.status_code == 200
    assert "CLAIM: Stored primary claim" in seen["prompt"]
    assert "1. Stored point" in seen["prompt"]
    assert "Browser primary" not in seen["prompt"]
    assert "Browser point" not in seen["prompt"]
    assert "FORGED INPUT" not in seen["prompt"]
    assert "IMAGE EVIDENCE" not in seen["prompt"]
    assert "photo.jpg" not in seen["prompt"]
    assert "Adobe Photoshop" not in seen["prompt"]
    assert "No image file was sealed for this investigation." in seen["prompt"]
    assert before["sources"] == after["sources"] == []
    assert "evil.example" not in seen["prompt"]


def test_missing_and_other_owners_get_the_same_not_found_response(tmp_path):
    app = create_app(settings=_settings(ledger_path=_ledger(tmp_path)))
    with TestClient(app) as owner, TestClient(app) as stranger:
        investigation_id = _create(owner, "Private claim")
        _create(stranger, "Other claim")
        paths = [
            ("GET", f"/api/investigations/{investigation_id}/evidence", None),
            ("POST", f"/api/investigations/{investigation_id}/search", {"queries": ["x"]}),
            ("POST", f"/api/investigations/{investigation_id}/fetch", None),
            ("POST", f"/api/investigations/{investigation_id}/extract-claims", {"input": "nope"}),
            ("POST", f"/api/investigations/{investigation_id}/seal", {}),
            ("POST", f"/api/investigations/{investigation_id}/assess", {"primaryClaim": "nope", "sources": [{"url": "https://evil.example"}]}),
            ("DELETE", f"/api/investigations/{investigation_id}", None),
            ("GET", "/api/investigations/not-a-real-id/evidence", None),
            ("DELETE", "/api/investigations/not-a-real-id", None),
        ]
        for method, path, payload in paths:
            response = stranger.request(method, path, json=payload)
            assert response.status_code == 404, path
            assert response.json() == NOT_FOUND
        still = owner.get(f"/api/investigations/{investigation_id}/evidence")
    assert still.status_code == 200


def test_owner_delete_removes_the_investigation_and_a_stranger_cannot(tmp_path):
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
        owner.post(f"/api/investigations/{investigation_id}/search", json={"queries": ["claim"]})
        _create(stranger, "Other")
        denied = stranger.delete(f"/api/investigations/{investigation_id}")
        kept = owner.get(f"/api/investigations/{investigation_id}/evidence")
        removed = owner.delete(f"/api/investigations/{investigation_id}")
        gone = owner.get(f"/api/investigations/{investigation_id}/evidence")
        again = owner.delete(f"/api/investigations/{investigation_id}")
    assert denied.status_code == 404
    assert denied.json() == NOT_FOUND
    assert kept.status_code == 200
    assert kept.json()["sources"][0]["url"] == "https://www.cdc.gov/private"
    assert removed.status_code == 200
    assert removed.json() == {"deleted": True}
    assert gone.status_code == 404
    assert gone.json() == NOT_FOUND
    assert again.json() == NOT_FOUND


def test_session_cookie_flags_for_local_http_and_production_https(tmp_path):
    local = create_app(settings=_settings(ledger_path=_ledger(tmp_path)))
    with TestClient(local) as client:
        client.post("/api/auth/register", json={"email": "local@example.com", "password": "correct-horse-battery"})
        response = client.post("/api/auth/login", json={"email": "local@example.com", "password": "correct-horse-battery"})
    header = response.headers["set-cookie"]
    attributes = header.split(";", 1)[1].lower()
    assert header.startswith("rc_session=")
    assert "httponly" in attributes
    assert "samesite=lax" in attributes
    assert "secure" not in attributes
    assert "path=/" in attributes

    secret = "p" * 32
    production = create_app(settings=_settings(ledger_path=_ledger(tmp_path, "production.sqlite"), cookie_secure=True, auth_secret=secret))
    with TestClient(production) as client:
        client.post("/api/auth/register", json={"email": "prod@example.com", "password": "correct-horse-battery"})
        response = client.post("/api/auth/login", json={"email": "prod@example.com", "password": "correct-horse-battery"})
    header = response.headers["set-cookie"]
    value = header.split(";", 1)[0].split("=", 1)[1]
    csrf = response.json()["csrfToken"]
    assert header.startswith("__Host-rc_session=")
    assert "HttpOnly" in header
    assert "secure" in header.lower()
    assert "samesite=strict" in header.lower()
    assert "Path=/" in header
    assert "Domain=" not in header
    assert secret not in response.text
    with TestClient(production) as reader:
        listed = reader.get(
            "/api/auth/session",
            headers={"cookie": f"__Host-rc_session={value}"},
        )
        wrong_name = reader.get(
            "/api/auth/session",
            headers={"cookie": f"rc_session={value}", "x-csrf-token": csrf},
        )
    assert listed.status_code == 200
    assert wrong_name.status_code == 401
    assert wrong_name.json()["code"] == "unauthenticated"
