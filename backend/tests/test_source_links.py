"""Source URLs may be links only when they are http or https."""

import json
import subprocess
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from app.urls import source_http_url
from test_api import DUMMY_PARALLEL, _create, _json_response, _ledger, _settings
from app.main import create_app

ENGINE = Path(__file__).resolve().parents[2] / "frontend" / "engine.js"

SAFE = [
    "https://www.cdc.gov/kept",
    "http://example.com/page",
    "HTTPS://Example.COM/Path",
    "  https://www.reuters.com/story  ",
]
UNSAFE = [
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    " javascript:alert(1)",
    "java\tscript:alert(1)",
    "java\nscript:alert(1)",
    "javascript%3Aalert(1)",
    "data:text/html,<script>alert(1)</script>",
    "file:///etc/passwd",
    "FILE:///tmp/secret",
    "blob:https://example.com/11111111-1111-1111-1111-111111111111",
    "vbscript:msgbox(1)",
    "mailto:person@example.com",
    "https%3A%2F%2Fexample.com",
    "http:/example.com",
    "https://example.com/a b",
    "https://example.com\\@evil.com",
    "",
    "   ",
]


def test_only_http_and_https_urls_are_links():
    assert source_http_url("https://www.cdc.gov/kept") == "https://www.cdc.gov/kept"
    assert source_http_url("http://example.com/page") == "http://example.com/page"
    assert source_http_url("HTTPS://Example.COM/Path") == "HTTPS://Example.COM/Path"
    assert source_http_url("  https://www.reuters.com/story  ") == "https://www.reuters.com/story"
    assert source_http_url("https://example.com/%6Aavascript:alert(1)") == "https://example.com/%6Aavascript:alert(1)"
    for value in UNSAFE:
        assert source_http_url(value) is None
    assert source_http_url(None) is None
    assert source_http_url("https://example.com/" + ("a" * 2048)) is None


def test_search_stores_safe_urls_and_returns_unsafe_urls_as_text(tmp_path):
    def handler(_request: httpx.Request) -> httpx.Response:
        return _json_response({
            "results": [
                {"url": " HTTPS://www.cdc.gov/kept ", "title": "Kept", "excerpts": ["A real page."]},
                {"url": "javascript:alert(1)", "title": "Script", "excerpts": ["Not a page."]},
                {"url": "data:text/html,hi", "title": "Data", "excerpts": ["Not a page."]},
                {"url": "file:///etc/passwd", "title": "File", "excerpts": ["Not a page."]},
                {"url": "blob:https://example.com/uuid", "title": "Blob", "excerpts": ["Not a page."]},
                {"url": "JaVaScRiPt:alert(document.cookie)", "title": "Mixed", "excerpts": ["Not a page."]},
            ],
            "session_id": "s",
        })

    app = create_app(
        settings=_settings(ledger_path=_ledger(tmp_path), parallel_api_key=DUMMY_PARALLEL),
        parallel_transport=httpx.MockTransport(handler),
    )
    with TestClient(app) as client:
        investigation_id = _create(client)
        response = client.post(
            f"/api/investigations/{investigation_id}/search",
            json={"queries": ["warm water diabetes"]},
        )
        evidence = client.get(f"/api/investigations/{investigation_id}/evidence")
    assert response.status_code == 200, response.text
    stored = {source["title"]: source["url"] for source in response.json()["sources"]}
    assert stored["Kept"] == "HTTPS://www.cdc.gov/kept"
    assert stored["Script"] == "javascript:alert(1)"
    assert stored["Data"] == "data:text/html,hi"
    assert stored["File"] == "file:///etc/passwd"
    assert stored["Blob"] == "blob:https://example.com/uuid"
    assert stored["Mixed"] == "JaVaScRiPt:alert(document.cookie)"
    for title, url in stored.items():
        if title == "Kept":
            assert source_http_url(url) == url
        else:
            assert source_http_url(url) is None
    assert evidence.status_code == 200
    assert {source["title"]: source["url"] for source in evidence.json()["sources"]} == stored


def test_source_cards_do_not_link_unsafe_schemes():
    script = r"""
const fs = require('fs');
const vm = require('vm');
const links = [];
function element(tag) {
  const node = {
    tagName: String(tag).toUpperCase(),
    className: '',
    textContent: '',
    target: '',
    rel: '',
    hrefAssigned: null
  };
  Object.defineProperty(node, 'href', {
    get() { return this.hrefAssigned; },
    set(value) {
      this.hrefAssigned = String(value);
      links.push(this.hrefAssigned);
    }
  });
  return node;
}
const sandbox = { console, URL, links };
sandbox.window = sandbox;
sandbox.document = {
  readyState: 'loading',
  addEventListener() {},
  createElement: element
};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), sandbox);
const cases = JSON.parse(fs.readFileSync(0, 'utf8'));
const results = cases.map((entry) => {
  const before = links.length;
  const node = sandbox.RC.sourceAction(entry.url, entry.label);
  return {
    url: entry.url,
    tag: node.tagName,
    className: node.className,
    text: node.textContent,
    href: node.hrefAssigned,
    linked: links.slice(before)
  };
});
process.stdout.write(JSON.stringify(results));
"""
    cases = [{"url": url, "label": "Open source [0]"} for url in SAFE + UNSAFE]
    cases.append({"url": "https://example.com/%6Aavascript:alert(1)", "label": "Open source [1]"})
    completed = subprocess.run(
        ["node", "-e", script, str(ENGINE)],
        input=json.dumps(cases),
        text=True,
        check=True,
        capture_output=True,
    )
    results = json.loads(completed.stdout)
    by_url = {item["url"]: item for item in results}
    for url in (
        "https://www.cdc.gov/kept",
        "http://example.com/page",
        "HTTPS://Example.COM/Path",
        "https://example.com/%6Aavascript:alert(1)",
    ):
        card = by_url[url]
        assert card["tag"] == "A", url
        assert card["className"] == "source-view"
        assert card["text"] == "Open source [0]" or card["text"].startswith("Open source")
        assert card["href"] == url
        assert card["linked"] == [url]
    trimmed = by_url["  https://www.reuters.com/story  "]
    assert trimmed["tag"] == "A"
    assert trimmed["href"] == "https://www.reuters.com/story"
    for url in UNSAFE:
        card = by_url[url]
        assert card["tag"] == "SPAN", url
        assert card["className"] == "source-desc"
        assert card["href"] is None, url
        assert card["linked"] == [], url
        assert "<a" not in card["text"].lower()
    assert by_url["javascript:alert(1)"]["text"] == "javascript:alert(1)"
    assert by_url["data:text/html,<script>alert(1)</script>"]["text"].startswith("data:")
    assert by_url[" javascript:alert(1)"]["text"] == "javascript:alert(1)"
    assert not any(
        (item["href"] or "").lower().startswith(("javascript:", "data:", "file:", "blob:"))
        for item in results
    )


def test_open_submitted_page_uses_same_safe_link_rules():
    """Submitted-page card reuses sourceAction; safe http(s) links only."""
    script = r"""
const fs = require('fs');
const vm = require('vm');
const links = [];
function element(tag) {
  const node = {
    tagName: String(tag).toUpperCase(),
    className: '',
    textContent: '',
    target: '',
    rel: '',
    hrefAssigned: null
  };
  Object.defineProperty(node, 'href', {
    get() { return this.hrefAssigned; },
    set(value) {
      this.hrefAssigned = String(value);
      links.push(this.hrefAssigned);
    }
  });
  return node;
}
const sandbox = { console, URL, links };
sandbox.window = sandbox;
sandbox.document = {
  readyState: 'loading',
  addEventListener() {},
  createElement: element
};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), sandbox);
const cases = JSON.parse(fs.readFileSync(0, 'utf8'));
const results = cases.map((entry) => {
  const before = links.length;
  const node = sandbox.RC.sourceAction(entry.url, entry.label);
  return {
    url: entry.url,
    tag: node.tagName,
    className: node.className,
    text: node.textContent,
    href: node.hrefAssigned,
    target: node.target,
    rel: node.rel,
    linked: links.slice(before)
  };
});
process.stdout.write(JSON.stringify(results));
"""
    cases = [
        {"url": "https://example.com/article", "label": "Open submitted page"},
        {"url": "http://example.org/path", "label": "Open submitted page"},
        {"url": "javascript:alert(1)", "label": "Open submitted page"},
        {"url": "data:text/html,hi", "label": "Open submitted page"},
        {"url": "file:///etc/passwd", "label": "Open submitted page"},
    ]
    completed = subprocess.run(
        ["node", "-e", script, str(ENGINE)],
        input=json.dumps(cases),
        text=True,
        check=True,
        capture_output=True,
    )
    results = json.loads(completed.stdout)
    by_url = {item["url"]: item for item in results}
    for url in ("https://example.com/article", "http://example.org/path"):
        card = by_url[url]
        assert card["tag"] == "A"
        assert card["className"] == "source-view"
        assert card["text"] == "Open submitted page"
        assert card["href"] == url
        assert card["target"] == "_blank"
        assert card["rel"] == "noopener noreferrer"
        assert card["linked"] == [url]
    for url in ("javascript:alert(1)", "data:text/html,hi", "file:///etc/passwd"):
        card = by_url[url]
        assert card["tag"] == "SPAN"
        assert card["className"] == "source-desc"
        assert card["href"] is None
        assert card["linked"] == []
        assert card["text"] == url.strip() or card["text"].startswith(url.split(":")[0])
