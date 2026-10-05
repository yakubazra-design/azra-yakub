"""Parallel Search Streamable HTTP MCP client.

Confirmed against https://search.parallel.ai/mcp on 2026-10-02:
- POST JSON-RPC, Accept: application/json, text/event-stream
- initialize protocolVersion 2025-03-26
- Mcp-Session-Id on later requests
- notifications/initialized
- tools/call names web_search and web_fetch
- tool results are JSON in result.structuredContent and result.content[].text

Anonymous access works. PARALLEL_API_KEY is sent only after a 401.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any

import httpx

from backend.app.config import Settings
from backend.app.errors import AppError, RetryableUpstream, exhausted

PROTOCOL_VERSION = "2025-03-26"


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _clean_source(item: Any, include_full_content: bool) -> dict | None:
    if not isinstance(item, dict):
        return None
    url = item.get("url")
    if not isinstance(url, str) or not url.strip():
        return None
    title = item.get("title")
    if not isinstance(title, str):
        title = None
    publish_date = item.get("publish_date") if "publish_date" in item else None
    if not isinstance(publish_date, str):
        publish_date = None
    excerpts = item.get("excerpts")
    if not isinstance(excerpts, list):
        excerpts = []
    excerpts = [part for part in excerpts if isinstance(part, str)]
    source = {
        "url": url,
        "title": title,
        "publish_date": publish_date,
        "excerpts": excerpts,
    }
    if include_full_content:
        full_content = item.get("full_content")
        source["full_content"] = full_content if isinstance(full_content, str) else None
    return source


def normalize_tool_payload(data: dict, include_full_content: bool) -> dict:
    results = []
    for item in _as_list(data.get("results")):
        cleaned = _clean_source(item, include_full_content)
        if cleaned is not None:
            results.append(cleaned)
    payload = {
        "results": results,
        "errors": _as_list(data.get("errors")),
        "warnings": _as_list(data.get("warnings")),
    }
    session_id = data.get("session_id")
    if isinstance(session_id, str):
        payload["session_id"] = session_id
    return payload


def has_usable_fetch_content(payload: dict) -> bool:
    for item in payload.get("results") or []:
        full_content = item.get("full_content")
        if isinstance(full_content, str) and full_content.strip():
            return True
        for excerpt in item.get("excerpts") or []:
            if isinstance(excerpt, str) and excerpt.strip():
                return True
    return False


def _parse_body(response: httpx.Response) -> dict | None:
    if response.status_code == 202 or not response.content:
        return None
    text = response.text.lstrip()
    content_type = response.headers.get("content-type", "")
    if "text/event-stream" in content_type or text.startswith("event:") or text.startswith("data:"):
        last = None
        for line in response.text.splitlines():
            if not line.startswith("data:"):
                continue
            raw = line[5:].strip()
            if not raw or raw == "[DONE]":
                continue
            last = json.loads(raw)
        if not isinstance(last, dict):
            raise AppError(502, "invalid_upstream", "Parallel MCP returned an event stream with no JSON-RPC message.", False)
        return last
    try:
        body = response.json()
    except json.JSONDecodeError as exc:
        raise AppError(502, "invalid_upstream", "Parallel MCP returned a response that was not JSON.", False) from exc
    if not isinstance(body, dict):
        raise AppError(502, "invalid_upstream", "Parallel MCP returned an unexpected JSON value.", False)
    return body


def _tool_data(message: dict) -> dict:
    if "error" in message and message["error"]:
        err = message["error"] if isinstance(message["error"], dict) else {}
        detail = err.get("message") if isinstance(err, dict) else None
        raise AppError(502, "upstream_error", detail or "Parallel MCP rejected the tool call.", False)
    result = message.get("result")
    if not isinstance(result, dict):
        raise AppError(502, "invalid_upstream", "Parallel MCP tool call did not return a result object.", False)
    if result.get("isError") is True:
        detail = "Parallel Search reported a tool error."
        content = result.get("content")
        if isinstance(content, list) and content:
            text = content[0].get("text") if isinstance(content[0], dict) else None
            if isinstance(text, str) and text.strip():
                detail = text.strip()[:500]
        raise AppError(502, "tool_error", detail, False)
    structured = result.get("structuredContent")
    if isinstance(structured, dict) and "results" in structured:
        return structured
    content = result.get("content")
    if isinstance(content, list):
        for block in content:
            if not isinstance(block, dict) or block.get("type") != "text":
                continue
            text = block.get("text")
            if not isinstance(text, str) or not text.strip():
                continue
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError as exc:
                raise AppError(502, "invalid_upstream", "Parallel MCP tool text was not JSON.", False) from exc
            if isinstance(parsed, dict):
                return parsed
    raise AppError(502, "invalid_upstream", "Parallel MCP tool call did not include a result payload.", False)


class ParallelMcpClient:
    def __init__(self, settings: Settings):
        self._settings = settings
        self._lock = threading.RLock()
        self._session_id: str | None = None
        self._rpc_id = 0
        self._use_auth = False
        self._client = httpx.Client(timeout=httpx.Timeout(60.0, connect=10.0))

    def close(self) -> None:
        self._client.close()

    def search(self, arguments: dict, timeout: float) -> dict:
        self._require_configured()
        data = self._call_tool("web_search", arguments, timeout)
        return normalize_tool_payload(data, include_full_content=False)

    def fetch(self, arguments: dict, timeout: float) -> dict:
        self._require_configured()
        data = self._call_tool("web_fetch", arguments, timeout)
        return normalize_tool_payload(data, include_full_content=True)

    def _require_configured(self) -> None:
        if not self._settings.parallel_configured:
            raise AppError(
                503,
                "not_configured",
                "Parallel Search MCP is not configured. Set PARALLEL_MCP_URL.",
                False,
            )

    def _call_tool(self, name: str, arguments: dict, timeout: float) -> dict:
        try:
            return self._call_tool_once(name, arguments, timeout)
        except RetryableUpstream:
            time.sleep(max(0.0, self._settings.retry_backoff_seconds))
            try:
                return self._call_tool_once(name, arguments, timeout)
            except RetryableUpstream as exc:
                raise exhausted(exc) from exc

    def _call_tool_once(self, name: str, arguments: dict, timeout: float) -> dict:
        self._ensure_session(timeout)
        message = self._post(
            {
                "jsonrpc": "2.0",
                "id": self._next_id(),
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            },
            timeout,
        )
        if not isinstance(message, dict):
            raise AppError(502, "invalid_upstream", "Parallel MCP returned an empty tool response.", False)
        return _tool_data(message)

    def _ensure_session(self, timeout: float) -> None:
        with self._lock:
            if self._session_id:
                return
            message = self._post(
                {
                    "jsonrpc": "2.0",
                    "id": self._next_id(),
                    "method": "initialize",
                    "params": {
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": {"name": "realitycheck-backend", "version": "0.1.0"},
                    },
                },
                min(timeout, 15.0),
                include_session=False,
            )
            if not isinstance(message, dict):
                raise AppError(502, "invalid_upstream", "Parallel MCP initialize returned no body.", False)
            result = message.get("result") if isinstance(message.get("result"), dict) else None
            version = result.get("protocolVersion") if result else None
            if version != PROTOCOL_VERSION:
                raise AppError(
                    502,
                    "protocol_mismatch",
                    "Parallel MCP did not accept protocol version 2025-03-26. "
                    "The backend will not invent a different handshake.",
                    False,
                )
            session_id = message.get("_session_id") or self._session_id
            if not session_id:
                raise AppError(502, "invalid_upstream", "Parallel MCP did not return an Mcp-Session-Id.", False)
            self._session_id = session_id
            self._post(
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                min(timeout, 15.0),
            )

    def _next_id(self) -> int:
        with self._lock:
            self._rpc_id += 1
            return self._rpc_id

    def _headers(self, include_session: bool) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": PROTOCOL_VERSION,
        }
        if include_session and self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        if self._use_auth and self._settings.parallel_api_key.strip():
            headers["Authorization"] = "Bearer " + self._settings.parallel_api_key.strip()
        return headers

    def _post(self, payload: dict, timeout: float, include_session: bool = True) -> dict | None:
        if not self._settings.parallel_mcp_url.strip():
            raise AppError(503, "not_configured", "Parallel Search MCP is not configured. Set PARALLEL_MCP_URL.", False)
        try:
            response = self._client.post(
                self._settings.parallel_mcp_url.strip(),
                headers=self._headers(include_session),
                json=payload,
                timeout=timeout,
            )
        except httpx.TimeoutException as exc:
            raise RetryableUpstream("Parallel Search did not respond in time.") from exc
        except httpx.TransportError as exc:
            raise RetryableUpstream("Parallel Search could not be reached.") from exc

        if response.status_code == 401 and not self._use_auth:
            if not self._settings.parallel_api_key.strip():
                raise AppError(
                    503,
                    "not_configured",
                    "Parallel Search MCP required authentication and PARALLEL_API_KEY is not set.",
                    False,
                )
            self._use_auth = True
            raise RetryableUpstream("Parallel Search asked for authentication.")

        if response.status_code == 404 and include_session:
            self._session_id = None
            raise RetryableUpstream("Parallel MCP session expired.")

        if response.status_code in (429, 500, 502, 503, 504):
            raise RetryableUpstream("Parallel Search returned a temporary error.")

        if response.status_code >= 400:
            raise AppError(502, "upstream_error", "Parallel Search rejected the request.", False)

        try:
            message = _parse_body(response)
        except AppError:
            raise
        except json.JSONDecodeError as exc:
            raise AppError(502, "invalid_upstream", "Parallel MCP returned malformed JSON.", False) from exc

        session_header = response.headers.get("mcp-session-id")
        if session_header:
            self._session_id = session_header
            if isinstance(message, dict):
                message["_session_id"] = session_header
        return message
