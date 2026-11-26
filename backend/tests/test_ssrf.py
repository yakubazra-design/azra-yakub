"""SSRF controls for the fetch gate."""

import socket

import httpx
import pytest
from fastapi.testclient import TestClient

from app.ssrf import MAX_REDIRECTS, UrlRejected, assert_safe_to_fetch, pinned_exchange
from app.urls import public_http_url
from test_api import DUMMY_PARALLEL, _create, _ledger, _settings
from app.main import create_app


def test_text_rules_reject_local_metadata_and_disguised_addresses():
    with pytest.raises(ValueError, match="Only http and https"):
        public_http_url("file:///etc/passwd")
    with pytest.raises(ValueError, match="Only http and https"):
        public_http_url("gopher://example.com")
    with pytest.raises(ValueError, match="credentials"):
        public_http_url("http://user:pass@example.com/")
    with pytest.raises(ValueError, match="That host is not allowed"):
        public_http_url("http://localhost/secret")
    with pytest.raises(ValueError, match="That host is not allowed"):
        public_http_url("http://metadata.google.internal/")
    with pytest.raises(ValueError, match="That host is not allowed"):
        public_http_url("http://metadata.google.com/computeMetadata/v1/")
    with pytest.raises(ValueError, match="That host is not allowed"):
        public_http_url("http://foo.localhost/")
    for url in (
        "http://127.0.0.1/",
        "http://10.0.0.1/",
        "http://169.254.169.254/",
        "http://100.64.0.1/",
        "http://100.100.100.200/",
        "http://168.63.129.16/",
        "http://[::1]/",
        "http://2130706433/",
        "http://0177.0.0.1/",
        "http://0x7f000001/",
    ):
        with pytest.raises(ValueError, match="That address is not allowed"):
            public_http_url(url)


def test_dns_to_a_private_address_never_connects():
    connections = []

    def resolve(_host, _port):
        return ["10.1.2.3"]

    def exchange(target):
        connections.append(target["ip"])
        raise AssertionError("connected")

    with pytest.raises(UrlRejected, match="That address is not allowed"):
        assert_safe_to_fetch("https://example.com/page", resolve=resolve, exchange=exchange)
    assert connections == []


def test_rebinding_to_a_private_address_on_the_second_lookup_never_connects():
    answers = iter([["93.184.216.34"], ["127.0.0.1"]])

    def resolve(_host, _port):
        return next(answers)

    def exchange(_target):
        raise AssertionError("connected")

    with pytest.raises(UrlRejected, match="That address is not allowed"):
        assert_safe_to_fetch("https://example.com/page", resolve=resolve, exchange=exchange)


def test_redirects_are_rechecked_and_pinned():
    seen = []

    def resolve(host, _port):
        if host == "cdn.example":
            return ["93.184.216.34", "93.184.216.34"]
        if host == "metadata.google.internal":
            return ["169.254.169.254"]
        raise AssertionError(host)

    def exchange(target):
        seen.append((target["host"], target["ip"]))
        if target["host"] == "cdn.example":
            return 302, "http://metadata.google.internal/computeMetadata/v1/"
        raise AssertionError("followed the redirect")

    with pytest.raises(UrlRejected, match="That host is not allowed"):
        assert_safe_to_fetch("https://cdn.example/start", resolve=resolve, exchange=exchange)
    assert seen == [("cdn.example", "93.184.216.34")]


def test_redirect_limit_stops_the_chain():
    hops = {"n": 0}

    def resolve(_host, _port):
        return ["93.184.216.34"]

    def exchange(target):
        hops["n"] += 1
        return 302, target["url"] + "x"

    with pytest.raises(UrlRejected, match="Too many redirects"):
        assert_safe_to_fetch("https://example.com/a", resolve=resolve, exchange=exchange)
    assert hops["n"] == MAX_REDIRECTS + 1


def test_connection_failures_do_not_include_internal_error_text(monkeypatch):
    def fail(*_args, **_kwargs):
        raise TimeoutError("timed out talking to 169.254.169.254")

    monkeypatch.setattr(socket, "create_connection", fail)
    with pytest.raises(UrlRejected, match="That host is not allowed") as caught:
        pinned_exchange({
            "scheme": "http",
            "host": "example.com",
            "port": 80,
            "path": "/",
            "ip": "93.184.216.34",
        })
    assert "169.254.169.254" not in str(caught.value)


def test_fetch_route_does_not_call_parallel_when_dns_is_unsafe(tmp_path):
    called = {"parallel": False, "connected": False}

    def resolve(_host, _port):
        return ["10.0.0.8"]

    def exchange(target):
        called["connected"] = target["ip"]
        raise AssertionError("connected")

    def guard(url):
        return assert_safe_to_fetch(url, resolve=resolve, exchange=exchange)

    def handler(_request: httpx.Request) -> httpx.Response:
        called["parallel"] = True
        return httpx.Response(200, json={"results": [], "session_id": "s"})

    app = create_app(
        settings=_settings(ledger_path=_ledger(tmp_path), parallel_api_key=DUMMY_PARALLEL),
        parallel_transport=httpx.MockTransport(handler),
        fetch_guard=guard,
    )
    with TestClient(app) as client:
        investigation_id = _create(client, "https://example.com/page", "url")
        response = client.post(f"/api/investigations/{investigation_id}/fetch")
    assert response.status_code == 400
    assert response.json()["code"] == "bad_url"
    assert response.json()["message"] == "That address is not allowed."
    assert called == {"parallel": False, "connected": False}
