"""Quality and independence stay aligned with the browser rules."""

import json
import subprocess
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from app.evidence import build_timeline, independence, prepare_sources
from app.main import create_app
from app.quality import classify
from test_api import _create, _ledger, _settings

ROOT = Path(__file__).resolve().parents[2]
ENGINE = ROOT / "frontend" / "engine.js"

URLS = [
    "https://www.cdc.gov/diabetes",
    "https://agency.gov.uk/report",
    "https://college.edu/paper",
    "https://www.who.int/news",
    "https://www.toureiffel.paris/en",
    "https://en.wikipedia.org/wiki/Diabetes",
    "https://arxiv.org/abs/1",
    "https://www.reuters.com/story",
    "https://www.facebook.com/post",
    "https://example.blog/post",
    "https://notgov.com/story",
    "https://example.com/story",
    "",
]

CASES = [
    [],
    [
        {"url": "https://www.cdc.gov/a", "title": "Alpha finding", "snippet": "Short note."},
        {"url": "https://cdc.gov/b", "title": "Beta finding", "snippet": "Different note."},
    ],
    [
        {"url": "https://www.reuters.com/a", "title": "Wire A", "snippet": "According to the World Health Organization, cases rose."},
        {"url": "https://www.bbc.com/b", "title": "Wire B", "snippet": "According to the World Health Organization, cases rose in several regions this year."},
    ],
    [
        {"url": "https://www.nature.com/a", "title": "Paper A", "snippet": "Identifier 10.1038/s41586-024-00001-x appears once."},
        {"url": "https://www.ncbi.nlm.nih.gov/pmc/b", "title": "Paper B", "snippet": "Mirror copy 10.1038/s41586-024-00001-x."},
    ],
    [
        {"url": "https://www.example.com/a", "title": "Shared wording title one", "snippet": "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu"},
        {"url": "https://www.other.test/b", "title": "Shared wording title two", "snippet": "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu extra"},
    ],
    [
        {"url": "https://journal.example/a", "title": "Coastal Erosion Study Results", "snippet": "by B Fernando alpha bravo charlie delta echo foxtrot"},
        {"url": "https://repository.example/b", "title": "Coastal Erosion Study Results - PMC", "snippet": "by B Fernando hotel india juliet kilo lima mike"},
    ],
    [
        {"url": "https://news.example/a", "title": "Coastal Erosion Study Results", "snippet": "alpha bravo charlie delta echo foxtrot golf"},
        {"url": "https://blog.example/b", "title": "Coastal Erosion Study Results", "snippet": "hotel india juliet kilo lima mike november"},
    ],
    [
        {"url": "https://www.reuters.com/a", "title": "Market close", "snippet": "Shares rose after the opening bell."},
        {"url": "https://www.bbc.com/b", "title": "Weather report", "snippet": "Rain is expected across the coast."},
    ],
]


def _browser_results():
    script = r"""
const fs = require('fs');
const vm = require('vm');
const sandbox = {
  console,
  URL,
  fetch() { return Promise.resolve({ ok: true, text() { return Promise.resolve('{}'); } }); }
};
sandbox.window = sandbox;
sandbox.document = {
  readyState: 'loading',
  addEventListener() {},
  querySelector() { return { addEventListener() {}, classList: { add() {}, remove() {}, toggle() {} }, setAttribute() {}, style: {}, focus() {}, textContent: '' }; },
  querySelectorAll() { return []; },
  getElementById() { return sandbox.document.querySelector(); },
  createElement() { return sandbox.document.querySelector(); }
};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), sandbox);
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const quality = input.urls.map((url) => sandbox.RC.quality.classify(url));
const prepared = input.cases.map((sources) => {
  const seen = {};
  const out = [];
  sources.forEach((source) => {
    if (!source || !source.url || seen[source.url]) return;
    seen[source.url] = true;
    out.push(source);
  });
  out.sort((a, b) => sandbox.RC.quality.rank(sandbox.RC.quality.classify(b.url).tier) - sandbox.RC.quality.rank(sandbox.RC.quality.classify(a.url).tier));
  return out.slice(0, 12);
});
const independence = prepared.map((sources) => sandbox.RC.evidence.independence(sources.map((source) => ({
  url: source.url,
  title: source.title,
  snippet: source.snippet,
  quality: sandbox.RC.quality.classify(source.url)
}))));
process.stdout.write(JSON.stringify({ quality, prepared, independence }));
"""
    payload = json.dumps({"urls": URLS, "cases": CASES})
    completed = subprocess.run(
        ["node", "-e", script, str(ENGINE)],
        input=payload,
        text=True,
        check=True,
        capture_output=True,
    )
    return json.loads(completed.stdout)


def test_quality_and_independence_match_the_browser_rules():
    expected = _browser_results()
    assert [classify(url) for url in URLS] == expected["quality"]
    for sources, browser_sources, browser_independence in zip(CASES, expected["prepared"], expected["independence"]):
        forged = []
        for source in sources:
            copy = dict(source)
            copy["quality"] = {"tier": "LOW", "reason": "forged"}
            forged.append(copy)
        prepared = prepare_sources(forged)
        comparable = [{key: source.get(key) for key in ("url", "title", "snippet")} for source in prepared]
        expected_sources = [{key: source.get(key) for key in ("url", "title", "snippet")} for source in browser_sources]
        assert comparable == expected_sources
        assert [source["quality"]["tier"] for source in prepared] == [
            classify(source["url"])["tier"] for source in prepared
        ]
        assert independence(prepared) == browser_independence


def test_prepare_sources_caps_at_twelve_and_ranks_high_first():
    sources = [{"url": f"https://example.com/{index}", "title": "Unknown", "snippet": "text"} for index in range(13)]
    sources.append({"url": "https://www.cdc.gov/late", "title": "Official", "snippet": "text"})
    prepared = prepare_sources(sources)
    assert len(prepared) == 12
    assert prepared[0]["url"] == "https://www.cdc.gov/late"
    assert prepared[0]["quality"]["tier"] == "HIGH"


def test_evidence_route_uses_stored_records_not_a_posted_list(tmp_path):
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "results": [
                {"url": "https://www.cdc.gov/a", "title": "One", "excerpts": ["alpha"]},
                {"url": "https://cdc.gov/b", "title": "Two", "excerpts": ["beta"]},
            ],
            "session_id": "s",
        })

    app = create_app(
        settings=_settings(ledger_path=_ledger(tmp_path), parallel_api_key="test-parallel-key"),
        parallel_transport=httpx.MockTransport(handler),
    )
    with TestClient(app) as client:
        investigation_id = _create(client, "A claim", "claim")
        client.post(f"/api/investigations/{investigation_id}/search", json={"queries": ["claim"]})
        response = client.post(f"/api/investigations/{investigation_id}/evidence", json={
            "sources": [{"url": "https://evil.example/injected", "title": "Injected", "snippet": "forged", "quality": {"tier": "LOW"}}]
        })
        listed = client.get(f"/api/investigations/{investigation_id}/evidence")
    assert response.status_code == 405
    body = listed.json()
    assert [source["quality"]["tier"] for source in body["sources"]] == ["HIGH", "HIGH"]
    assert body["independence"]["independentCount"] == 1
    assert "forged" not in listed.text
    assert "evil.example" not in listed.text


def test_timeline_keeps_valid_dates_and_sorts_them():
    sources = [
        {"url": "https://www.cdc.gov/late", "title": "Later page", "snippet": "Published on the agency site.", "publishedAt": "2024-05-01", "dateCertainty": "confirmed"},
        {"url": "https://www.reuters.com/early", "title": "Earlier page", "snippet": "No date label here.", "publishedAt": "2019-01-15"},
        {"url": "https://example.com/same", "title": "Same day", "snippet": "Last updated note.", "publishedAt": "2019-01-15"},
    ]
    timeline = build_timeline(prepare_sources(sources))
    assert [entry["date"] for entry in timeline["entries"]] == ["2019-01-15", "2019-01-15", "2024-05-01"]
    assert [entry["certainty"] for entry in timeline["entries"]] == ["provider-reported"] * 3
    assert timeline["entries"][0]["dateType"] == "unspecified"
    assert timeline["entries"][2]["dateType"] == "published"
    assert timeline["entries"][1]["desc"] == "Same day"
    assert timeline["earliest"]["date"] == "2019-01-15"
    assert timeline["missingCount"] == 0
    assert "confirmed" not in json.dumps(timeline)


def test_timeline_leaves_missing_and_invalid_dates_off_the_record():
    sources = [
        {"url": "https://example.com/none", "title": "Undated", "snippet": "No date.", "publishedAt": None},
        {"url": "https://example.com/blank", "title": "Blank", "snippet": "No date.", "publishedAt": "   "},
        {"url": "https://example.com/words", "title": "Words", "snippet": "No date.", "publishedAt": "yesterday"},
        {"url": "https://example.com/impossible", "title": "Impossible", "snippet": "No date.", "publishedAt": "2024-02-31"},
        {"url": "https://example.com/kept", "title": "Kept", "snippet": "No date.", "publishedAt": " 2020-12-01 "},
    ]
    prepared = prepare_sources(sources)
    assert [source["publishedAt"] for source in prepared] == [None, None, None, None, "2020-12-01"]
    timeline = build_timeline(prepared)
    assert [entry["date"] for entry in timeline["entries"]] == ["2020-12-01"]
    assert timeline["missingCount"] == 4
    assert timeline["missingIndexes"] == [0, 1, 2, 3]
    assert "yesterday" not in json.dumps(timeline)
    assert "2024-02-31" not in json.dumps(timeline)


def test_stored_page_date_stays_provider_reported(tmp_path):
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "results": [{
                "url": "https://www.cdc.gov/a",
                "title": "Agency page",
                "publish_date": "2024-03-12",
                "excerpts": ["The page gives no publish label."],
            }],
            "session_id": "s",
        })

    app = create_app(
        settings=_settings(ledger_path=_ledger(tmp_path), parallel_api_key="test-parallel-key"),
        parallel_transport=httpx.MockTransport(handler),
    )
    with TestClient(app) as client:
        investigation_id = _create(client, "A claim", "claim")
        client.post(f"/api/investigations/{investigation_id}/search", json={"queries": ["claim"]})
        listed = client.get(f"/api/investigations/{investigation_id}/evidence")
    body = listed.json()
    assert body["sources"][0]["dateCertainty"] == "provider-reported"
    assert body["sources"][0]["dateType"] == "unspecified"
    entry = body["timeline"]["entries"][0]
    assert entry["date"] == "2024-03-12"
    assert entry["certainty"] == "provider-reported"
    assert "confirmed" not in listed.text
