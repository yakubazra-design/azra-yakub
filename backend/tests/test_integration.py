"""Stage 3.13C coverage for outcomes, provider failures, and one full investigation.

These tests use the existing validation, prompts, and frontend behaviour.
They do not change those rules. OpenAI and Parallel are in-process mocks,
and every database is a temporary file outside data/.
"""

import json
import sqlite3
import subprocess
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app.evidence import build_timeline, independence
from app.main import create_app
from app.validation import UNESTABLISHED_FINDING_TEXT, controlled_explanation
from test_api import DUMMY_OPENAI, DUMMY_PARALLEL, _create, _json_response, _ledger, _seal, _settings

ROOT = Path(__file__).resolve().parents[2]
ENGINE = ROOT / "frontend" / "engine.js"
PASSWORD = "correct-horse-battery"

OUTCOMES = [
    "VERIFIED",
    "PARTIALLY_VERIFIED",
    "CONTRADICTED",
    "INSUFFICIENT_EVIDENCE",
    "POTENTIAL_MANIPULATION",
    "UNRESOLVED",
]

OUTCOME_TEXT = {
    "VERIFIED": "Verified",
    "PARTIALLY_VERIFIED": "Partially verified",
    "CONTRADICTED": "Contradicted",
    "INSUFFICIENT_EVIDENCE": "Insufficient evidence",
    "POTENTIAL_MANIPULATION": "Potential manipulation",
    "UNRESOLVED": "Unresolved",
}


def _app(tmp_path, *, openai=None, parallel=None, fetch_guard=None, name="ledger.sqlite"):
    return create_app(
        settings=_settings(
            ledger_path=_ledger(tmp_path, name),
            openai_api_key=DUMMY_OPENAI,
            parallel_api_key=DUMMY_PARALLEL,
        ),
        openai_transport=httpx.MockTransport(openai) if openai else None,
        parallel_transport=httpx.MockTransport(parallel) if parallel else None,
        fetch_guard=fetch_guard,
        retry_wait=0.0,
    )


def _chat(content: dict) -> httpx.Response:
    return _json_response({"choices": [{"message": {"content": json.dumps(content)}}]})


def _one_source(_request: httpx.Request) -> httpx.Response:
    return _json_response({
        "results": [{
            "url": "https://www.cdc.gov/diabetes",
            "title": "Diabetes facts",
            "publish_date": "2024-01-15",
            "excerpts": ["Published on the agency site. Warm water is not a cure."],
        }],
        "session_id": "stored-session",
    })


def _model_assessment(label: str) -> dict:
    return {
        "assessment": label,
        "findings": [
            {"type": "support", "text": "The source addresses the claim.", "sources": [0, 4]},
            {"type": "invented", "text": "Downgraded caution.", "sources": [0]},
            {"type": "support", "text": "   ", "sources": [0]},
        ],
        "originalMaterial": {"established": True, "description": "The agency page.", "source": 0},
        "why": {
            "supporting": "Shown.",
            "contradicting": "None recorded.",
            "sourceQuality": "High.",
            "timeline": "Dated.",
            "uncertain": "Some detail.",
            "choice": "Because of the source.",
        },
        "uncertainty": ["  ", "One open point."],
    }


def _surviving_outcome(label: str) -> str:
    if label in {"VERIFIED", "PARTIALLY_VERIFIED", "CONTRADICTED", "POTENTIAL_MANIPULATION"}:
        return "UNRESOLVED"
    return label


def _validated(label: str) -> dict:
    outcome = _surviving_outcome(label)
    explanation = controlled_explanation(outcome)
    return {
        "assessment": outcome,
        "findings": [
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
        ],
        "originalMaterial": {"established": False, "description": "", "source": 0},
        "why": explanation["why"],
        "uncertainty": explanation["uncertainty"],
        "imageEvidence": None,
    }


def _assert_not_an_outcome(response: httpx.Response) -> dict:
    body = response.json()
    assert "assessment" not in body
    assert body["code"] not in OUTCOMES
    for label in OUTCOMES:
        assert label not in response.text
    return body


@pytest.mark.parametrize("label", OUTCOMES)
def test_mocked_outcome_passes_existing_validation(tmp_path, label):
    def openai_handler(_request: httpx.Request) -> httpx.Response:
        return _chat(_model_assessment(label))

    app = _app(tmp_path, openai=openai_handler, parallel=_one_source)
    with TestClient(app) as client:
        investigation_id = _create(client, "Warm water cures the common cold.")
        searched = client.post(
            f"/api/investigations/{investigation_id}/search",
            json={"queries": ["warm water common cold"]},
        )
        assert searched.status_code == 200, searched.text
        assert len(searched.json()["sources"]) == 1
        token = _seal(client, investigation_id)
        assessed = client.post(
            f"/api/investigations/{investigation_id}/assess",
            json={
                "assessmentToken": token,
                "primaryClaim": "FORGED-PRIMARY",
                "sources": [{"url": "https://evil.example/injected", "quality": {"tier": "LOW"}}],
            },
        )
    assert assessed.status_code == 200, assessed.text
    body = assessed.json()
    expected = _validated(label)
    # Phase A adds durable identifiers; existing fields keep their meanings.
    for key, value in expected.items():
        assert body.get(key) == value
    assert body.get("assessmentResultId")
    assert body.get("snapshotId")
    assert body.get("assessedAt")
    assert "modelAssessment" not in body
    assert DUMMY_OPENAI not in assessed.text


def _timeout(_request: httpx.Request) -> httpx.Response:
    raise httpx.TimeoutException("timed out")


def test_openai_timeout_consumes_assessment_token(tmp_path):
    _assert_assessment_provider_failure(
        tmp_path,
        _timeout,
        "server_unavailable",
        "The analysis model did not respond in time.",
    )


def test_openai_http_500_consumes_assessment_token(tmp_path):
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": {"message": "SECRET-UPSTREAM-BODY"}})

    _assert_assessment_provider_failure(
        tmp_path,
        handler,
        "upstream_error",
        "The analysis model could not complete this request.",
        hidden="SECRET-UPSTREAM-BODY",
    )


def _assert_assessment_provider_failure(tmp_path, handler, code, message, hidden=None):
    calls = {"n": 0}
    path = _ledger(tmp_path)

    def openai_handler(request: httpx.Request):
        calls["n"] += 1
        return handler(request)

    app = _app(tmp_path, openai=openai_handler)
    with TestClient(app) as client:
        investigation_id = _create(client)
        token = _seal(client, investigation_id)
        failed = client.post(
            f"/api/investigations/{investigation_id}/assess",
            json={"assessmentToken": token, "primaryClaim": "FORGED-PRIMARY"},
        )
        assert failed.status_code == 502, failed.text
        assert _assert_not_an_outcome(failed) == {"code": code, "message": message}
        if hidden:
            assert hidden not in failed.text
        assert calls["n"] == 2
        consumed = sqlite3.connect(path).execute(
            "SELECT consumed_at FROM assessment_snapshots"
        ).fetchone()
        assert consumed[0]
        replay = client.post(
            f"/api/investigations/{investigation_id}/assess",
            json={"assessmentToken": token},
        )
        assert replay.status_code == 403, replay.text
        assert replay.json() == {
            "code": "assessment_token_used",
            "message": "The assessment token has already been used.",
        }
        assert "assessment" not in replay.json()
        assert calls["n"] == 2


@pytest.mark.parametrize(
    ("failure", "code", "message"),
    [
        ("http-500", "upstream_error", "Parallel Search could not be reached just now. This is usually temporary — try the check again."),
        ("timeout", "server_unavailable", "Parallel Search did not respond in time."),
    ],
)
def test_parallel_search_failure_is_not_an_assessment(tmp_path, failure, code, message):
    calls = {"n": 0}

    def parallel_handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if failure == "timeout":
            raise httpx.TimeoutException("timed out")
        return httpx.Response(500, json={"error": {"message": "SECRET-SEARCH-BODY"}})

    app = _app(tmp_path, parallel=parallel_handler)
    with TestClient(app) as client:
        investigation_id = _create(client)
        failed = client.post(
            f"/api/investigations/{investigation_id}/search",
            json={"queries": ["warm water common cold"]},
        )
    assert failed.status_code == 502, failed.text
    assert _assert_not_an_outcome(failed) == {"code": code, "message": message}
    assert "SECRET-SEARCH-BODY" not in failed.text
    assert calls["n"] == 2
    snapshots = sqlite3.connect(_ledger(tmp_path)).execute(
        "SELECT COUNT(*) FROM assessment_snapshots"
    ).fetchone()[0]
    assert snapshots == 0


def test_investigation_lifecycle_ends_with_account_erasure(tmp_path):
    path = _ledger(tmp_path)
    seen = {"prompts": []}

    def openai_handler(request: httpx.Request) -> httpx.Response:
        prompt = json.loads(request.content.decode())["messages"][0]["content"]
        seen["prompts"].append(prompt)
        if "claim-analysis stage" in prompt:
            return _chat({
                "hasFactualClaim": True,
                "primaryClaim": "Warm water cures the common cold.",
                "verifiablePoints": ["Warm water cures the common cold."],
                "excluded": [],
                "searchQueries": ["warm water common cold cure"],
            })
        return _chat(_model_assessment("PARTIALLY_VERIFIED"))

    def parallel_handler(_request: httpx.Request) -> httpx.Response:
        return _json_response({
            "results": [{
                "url": "https://www.cdc.gov/cold",
                "title": "Common cold facts",
                "publish_date": "2024-03-12",
                "excerpts": ["Published on the agency site. Warm water does not cure the common cold."],
            }],
            "session_id": "lifecycle-session",
        })

    email = "lifecycle@example.com"
    app = _app(tmp_path, openai=openai_handler, parallel=parallel_handler)
    with TestClient(app) as client:
        registered = client.post("/api/auth/register", json={"email": email, "password": PASSWORD})
        assert registered.status_code == 200, registered.text
        logged = client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
        assert logged.status_code == 200, logged.text
        client.headers["X-CSRF-Token"] = logged.json()["csrfToken"]

        opened = client.post("/api/investigations", json={
            "input": "Warm water cures the common cold.",
            "kind": "claim",
        })
        assert opened.status_code == 200, opened.text
        investigation_id = opened.json()["investigationId"]

        extracted = client.post(
            f"/api/investigations/{investigation_id}/extract-claims",
            json={"input": "FORGED-EXTRACT-TEXT", "kind": "url"},
        )
        assert extracted.status_code == 200, extracted.text
        assert extracted.json()["primaryClaim"] == "Warm water cures the common cold."
        assert "FORGED-EXTRACT-TEXT" not in seen["prompts"][0]
        assert "Warm water cures the common cold." in seen["prompts"][0]
        assert "Read the submitted text " in seen["prompts"][0]

        searched = client.post(
            f"/api/investigations/{investigation_id}/search",
            json={"queries": ["warm water common cold cure"]},
        )
        assert searched.status_code == 200, searched.text

        evidence = client.get(f"/api/investigations/{investigation_id}/evidence")
        assert evidence.status_code == 200, evidence.text
        stored = evidence.json()
        source = stored["sources"][0]
        assert source["quality"] == {
            "tier": "HIGH",
            "reason": "Government domain — treated as an official primary source.",
        }
        assert source["url"] == "https://www.cdc.gov/cold"
        assert stored["independence"] == independence(stored["sources"])
        assert stored["independence"]["totalSources"] == 1
        assert stored["independence"]["independentCount"] == 1
        assert stored["timeline"] == build_timeline(stored["sources"])
        assert stored["timeline"]["entries"][0]["date"] == "2024-03-12"
        assert stored["timeline"]["entries"][0]["certainty"] == "provider-reported"
        assert stored["timeline"]["missingCount"] == 0

        token = _seal(client, investigation_id)
        assessed = client.post(
            f"/api/investigations/{investigation_id}/assess",
            json={
                "assessmentToken": token,
                "primaryClaim": "FORGED-PRIMARY",
                "sources": [{"url": "https://evil.example/injected"}],
                "independence": {"totalSources": 99, "note": "CLIENT-SUPPLIED"},
                "timeline": {"entries": [{"date": "1999-01-01", "desc": "Forged"}]},
            },
        )
        assert assessed.status_code == 200, assessed.text
        assert assessed.json()["assessment"] == "UNRESOLVED"
        prompt = seen["prompts"][1]
        assert "CLAIM: Warm water cures the common cold." in prompt
        assert "host=cdc.gov | quality=HIGH | date=2024-03-12 | title=Common cold facts" in prompt
        assert "text: Published on the agency site. Warm water does not cure the common cold." in prompt
        assert "1 source(s) retrieved, 1 distinct publisher(s), 1 counted as independent" in prompt
        assert "2024-03-12 — Common cold facts (provider-reported)" in prompt
        assert "FORGED-PRIMARY" not in prompt
        assert "evil.example" not in prompt
        assert "CLIENT-SUPPLIED" not in prompt
        assert "1999-01-01" not in prompt

        owner_id = sqlite3.connect(path).execute(
            "SELECT owner_id FROM investigations WHERE id = ?",
            (investigation_id,),
        ).fetchone()[0]
        before = _counts(path, owner_id, investigation_id)
        assert before["users"] == 1
        assert before["investigations"] == 1
        assert before["sessions"] >= 1
        assert before["assessment_snapshots"] == 1
        assert before["evidence_sources"] == 1
        assert before["claim_analyses"] == 1
        assert before["page_fetches"] == 0
        assert before["rate_limits"] >= 1

        deleted = client.request("DELETE", "/api/auth/account", json={"password": PASSWORD})
        assert deleted.status_code == 200, deleted.text
        assert deleted.json() == {"ok": True}
        session = client.get("/api/auth/session")
        assert session.status_code == 401
        again = client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
        assert again.status_code == 401
        assert again.json()["code"] == "invalid_credentials"

    after = _counts(path, owner_id, investigation_id)
    assert after == {
        "users": 0,
        "investigations": 0,
        "sessions": 0,
        "assessment_snapshots": 0,
        "evidence_sources": 0,
        "claim_analyses": 0,
        "page_fetches": 0,
        "rate_limits": 0,
    }
    remaining = sqlite3.connect(path).execute("SELECT subject FROM rate_limits").fetchall()
    assert all(row[0] != owner_id for row in remaining)


def _counts(path: str, owner_id: str, investigation_id: str) -> dict:
    conn = sqlite3.connect(path)
    try:
        def count(sql: str, params: tuple) -> int:
            return conn.execute(sql, params).fetchone()[0]

        return {
            "users": count("SELECT COUNT(*) FROM users WHERE id = ?", (owner_id,)),
            "investigations": count("SELECT COUNT(*) FROM investigations WHERE owner_id = ?", (owner_id,)),
            "sessions": count("SELECT COUNT(*) FROM sessions WHERE user_id = ?", (owner_id,)),
            "assessment_snapshots": count(
                "SELECT COUNT(*) FROM assessment_snapshots WHERE owner_id = ? OR investigation_id = ?",
                (owner_id, investigation_id),
            ),
            "evidence_sources": count(
                "SELECT COUNT(*) FROM evidence_sources WHERE investigation_id = ?",
                (investigation_id,),
            ),
            "claim_analyses": count(
                "SELECT COUNT(*) FROM claim_analyses WHERE investigation_id = ?",
                (investigation_id,),
            ),
            "page_fetches": count(
                "SELECT COUNT(*) FROM page_fetches WHERE investigation_id = ?",
                (investigation_id,),
            ),
            "rate_limits": count("SELECT COUNT(*) FROM rate_limits WHERE subject = ?", (owner_id,)),
        }
    finally:
        conn.close()


def test_url_extraction_uses_stored_page_text(tmp_path):
    stored_url = "https://www.cdc.gov/flu/facts"
    stored_text = "STORED-PAGE-SENTENCE-9f3c: the recorded outbreak began in March 2020."
    seen = {}

    def guard(url: str) -> None:
        seen["guard"] = url

    def parallel_handler(request: httpx.Request) -> httpx.Response:
        seen["fetch"] = json.loads(request.content.decode())
        return _json_response({
            "results": [{
                "url": stored_url,
                "title": "Flu facts",
                "publish_date": "2024-02-02",
                "full_content": stored_text,
            }],
            "session_id": "fetch-session",
        })

    def openai_handler(request: httpx.Request) -> httpx.Response:
        seen["prompt"] = json.loads(request.content.decode())["messages"][0]["content"]
        return _chat({
            "hasFactualClaim": True,
            "verifiablePoints": ["The recorded outbreak began in March 2020."],
            "searchQueries": ["outbreak began march 2020"],
        })

    app = _app(tmp_path, openai=openai_handler, parallel=parallel_handler, fetch_guard=guard)
    with TestClient(app) as client:
        investigation_id = _create(client, stored_url, "url")
        fetched = client.post(
            f"/api/investigations/{investigation_id}/fetch",
            json={"url": "https://evil.example/override-9f3c", "sessionId": "browser-session"},
        )
        assert fetched.status_code == 200, fetched.text
        extracted = client.post(
            f"/api/investigations/{investigation_id}/extract-claims",
            json={
                "input": "FORGED-BROWSER-TEXT-9f3c",
                "kind": "claim",
                "url": "https://evil.example/other-9f3c",
            },
        )
    assert fetched.json()["url"] == stored_url
    assert seen["guard"] == stored_url
    assert seen["fetch"]["urls"] == [stored_url]
    assert "evil.example" not in json.dumps(seen["fetch"])
    assert stored_text in seen["prompt"]
    assert "web page text" in seen["prompt"]
    assert "FORGED-BROWSER-TEXT-9f3c" not in seen["prompt"]
    assert "evil.example" not in seen["prompt"]
    assert extracted.status_code == 200, extracted.text
    assert extracted.json()["primaryClaim"] == stored_text
    assert extracted.json()["hasFactualClaim"] is True


def test_browser_distinguishes_technical_failures_from_outcomes():
    completed = subprocess.run(
        ["node", "-e", _BROWSER_SCRIPT, str(ENGINE)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    body = json.loads(completed.stdout)
    labels = set(OUTCOME_TEXT.values())

    no_claim = body["noClaim"]
    assert no_claim["report"]["result"]["assessment"] == "INSUFFICIENT_EVIDENCE"
    assert no_claim["report"]["result"]["why"]["choice"] == (
        "Nothing in the submission can be checked against evidence, so no stronger assessment is possible."
    )
    assert no_claim["report"]["result"]["why"]["sourceQuality"] == "No sources were searched."
    assert no_claim["rendered"]["assessment"] == OUTCOME_TEXT["INSUFFICIENT_EVIDENCE"]
    assert not any("/search" in call["url"] or "/seal" in call["url"] or "/assess" in call["url"] for call in no_claim["calls"])
    assert no_claim["calls"][1]["body"] == {"kind": "claim"}

    empty = body["emptySearch"]
    assert empty["report"]["searchFailed"] is False
    assert empty["report"]["sources"] == []
    assert empty["report"]["result"]["assessment"] == "INSUFFICIENT_EVIDENCE"
    assert empty["report"]["result"]["why"]["choice"] == (
        "The search returned no usable sources, so there is no evidence to weigh."
    )
    assert empty["rendered"]["assessment"] == OUTCOME_TEXT["INSUFFICIENT_EVIDENCE"]
    assert any(call["url"].endswith("/search") and call["method"] == "POST" for call in empty["calls"])
    assert not any("/seal" in call["url"] or "/assess" in call["url"] for call in empty["calls"])

    failed = body["searchFailed"]
    assert failed["report"] is None
    assert failed["error"]["code"] == "search_failed"
    assert failed["error"]["code"] not in OUTCOMES
    assert "assessment" not in failed["error"]
    assert failed["error"]["message"] == (
        "Parallel Search could not be reached just now. This is usually temporary — try the check again."
    )
    assert "RAW-PROVIDER-DETAIL" not in failed["error"]["message"]
    assert failed["rendered"]["assessment"] == "Not completed"
    assert failed["rendered"]["assessment"] not in labels
    assert failed["rendered"]["basis"] == "Investigation stopped"
    assert failed["rendered"]["note"] == "No assessment was produced. Nothing below is a result."
    assert failed["error"]["message"] in failed["rendered"]["body"]
    assert not any(label in failed["rendered"]["assessment"] for label in labels)
    assert not any("/seal" in call["url"] or "/assess" in call["url"] for call in failed["calls"])


_BROWSER_SCRIPT = r"""
const fs = require('fs');
const vm = require('vm');

const byId = {};
const extras = {};

function makeEl() {
  const node = {
    children: [],
    style: {},
    className: '',
    id: '',
    hidden: false,
    textContent: '',
    setAttribute(name, value) { node[name] = value; },
    appendChild(child) { node.children.push(child); return child; },
    remove() {},
    focus() {}
  };
  node.classList = {
    add() {},
    remove() {},
    toggle() {}
  };
  return node;
}

function querySelector(sel) {
  if (typeof sel === 'string' && sel.charAt(0) === '#') {
    const id = sel.slice(1);
    if (!byId[id]) byId[id] = makeEl();
    return byId[id];
  }
  if (!extras[sel]) extras[sel] = makeEl();
  return extras[sel];
}

const sandbox = {
  console,
  URL,
  JSON,
  Math,
  Date,
  Promise,
  setTimeout,
  clearTimeout,
  scrollTo() {}
};
sandbox.window = sandbox;
sandbox.document = {
  readyState: 'loading',
  addEventListener() {},
  querySelector,
  querySelectorAll() { return []; },
  getElementById(id) { return querySelector('#' + id); },
  createElement() { return makeEl(); }
};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), sandbox);

function walk(node, acc) {
  if (!node) return acc;
  if (node.textContent) acc.push(node.textContent);
  (node.children || []).forEach(function (child) { walk(child, acc); });
  return acc;
}

function rendered() {
  return {
    assessment: byId['results-assessment'] ? byId['results-assessment'].textContent : '',
    basis: byId['results-basis'] ? byId['results-basis'].textContent : '',
    note: byId['results-mode-note'] ? byId['results-mode-note'].textContent : '',
    body: byId['results-body'] ? walk(byId['results-body'], []) : []
  };
}

const evidence = {
  sources: [],
  independence: {
    totalSources: 0,
    uniqueHostCount: 0,
    independentCount: 0,
    note: 'No sources were retrieved.',
    hostGroups: [],
    originGroups: [],
    repeatedIndexes: [],
    uncertainIndexes: [],
    repeatedReason: {},
    uncertainReason: {}
  },
  timeline: { entries: [], missingCount: 0, missingIndexes: [], earliest: null }
};

function install(scenario) {
  sandbox.RC.runtime.state.resolved = true;
  sandbox.RC.runtime.state.sample = { configured: true };
  sandbox.RC.runtime.state.mcp = { configured: true };
  sandbox.RC.retrieval.use('parallel');
  const calls = [];
  sandbox.fetch = function (url, opts) {
    const method = (opts && opts.method) || 'GET';
    const body = opts && opts.body ? JSON.parse(opts.body) : null;
    const path = String(url);
    calls.push({ method: method, url: path, body: body });
    if (method === 'POST' && path === '/api/investigations') {
      return jsonResponse(200, { investigationId: 'inv-' + scenario, kind: 'claim' });
    }
    if (path.indexOf('/extract-claims') >= 0) {
      if (scenario === 'noClaim') {
        return jsonResponse(200, {
          hasFactualClaim: false,
          primaryClaim: 'I think this topic is interesting.',
          verifiablePoints: [],
          excluded: [],
          searchQueries: []
        });
      }
      return jsonResponse(200, {
        hasFactualClaim: true,
        primaryClaim: 'Warm water cures the common cold.',
        verifiablePoints: ['Warm water cures the common cold.'],
        excluded: [],
        searchQueries: ['warm water common cold']
      });
    }
    if (path.indexOf('/search') >= 0) {
      if (scenario === 'searchFailed') {
        return jsonResponse(502, { code: 'upstream_error', message: 'RAW-PROVIDER-DETAIL' });
      }
      return jsonResponse(200, { sources: [], sessionId: 'empty', investigationId: 'inv-' + scenario });
    }
    if (path.indexOf('/evidence') >= 0) return jsonResponse(200, evidence);
    return jsonResponse(500, { code: 'unexpected', message: method + ' ' + path });
  };
  return calls;
}

function jsonResponse(status, payload) {
  const text = JSON.stringify(payload);
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status: status,
    text: function () { return Promise.resolve(text); },
    json: function () { return Promise.resolve(payload); }
  });
}

async function run(scenario, input) {
  const calls = install(scenario);
  let report = null;
  let error = null;
  try {
    report = await sandbox.RC.engine.investigate(input);
    sandbox.RC.ui.render(report);
  } catch (err) {
    error = { code: err && err.code, message: err && err.message };
    if (err && Object.prototype.hasOwnProperty.call(err, 'assessment')) error.assessment = err.assessment;
    sandbox.RC.ui.renderFailure(err, input);
  }
  return { calls: calls, report: report, error: error, rendered: rendered() };
}

(async function () {
  const result = {
    noClaim: await run('noClaim', 'I think this topic is interesting.'),
    emptySearch: await run('emptySearch', 'Warm water cures the common cold.'),
    searchFailed: await run('searchFailed', 'Warm water cures the common cold.')
  };
  process.stdout.write(JSON.stringify(result));
})().catch(function (err) {
  process.stderr.write(String(err && err.stack || err));
  process.exit(1);
});
"""
