"""Server-side Parallel Search and Extract calls.

Request fields match the web_search / web_fetch inputs in frontend/engine.js.
The HTTP API is Parallel's REST Search and Extract endpoints. PARALLEL_MCP_URL
is retained in configuration and is not called from the browser.
"""

import time
from secrets import token_hex

import httpx

from app.errors import ProviderError
from app.textutil import clamp_query, detect_date_type

SEARCH_OBJECTIVE = (
    "Find sources that confirm, contradict, or provide context for the claim being investigated."
)
FETCH_OBJECTIVE = "Extract the page text needed to identify the factual claims it makes."
RETRYABLE = {429, 500, 502, 503, 504}


class ParallelClient:
    def __init__(self, api_key: str, base_url: str, transport: httpx.BaseTransport | None = None, retry_wait: float = 0.4):
        self.api_key = api_key.strip()
        self.retry_wait = retry_wait
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            transport=transport,
            timeout=httpx.Timeout(45.0),
        )

    def close(self) -> None:
        self._client.close()

    def _headers(self) -> dict:
        return {"x-api-key": self.api_key, "Content-Type": "application/json"}

    def _require_key(self) -> None:
        if not self.api_key:
            raise ProviderError(
                "not_configured",
                "Parallel Search is not configured on the server.",
                status_code=503,
            )

    def _post(self, path: str, payload: dict) -> dict:
        for attempt in range(2):
            try:
                response = self._client.post(path, json=payload, headers=self._headers())
            except httpx.TimeoutException:
                if attempt == 0:
                    time.sleep(self.retry_wait)
                    continue
                raise ProviderError("server_unavailable", "Parallel Search did not respond in time.")
            if response.status_code in RETRYABLE and attempt == 0:
                time.sleep(self.retry_wait)
                continue
            if response.status_code >= 400:
                raise self._http_error(response)
            try:
                body = response.json()
            except ValueError as exc:
                raise ProviderError("upstream_error", "Parallel Search returned a response that could not be read.") from exc
            if not isinstance(body, dict):
                raise ProviderError("upstream_error", "Parallel Search returned a response that could not be read.")
            return body
        raise ProviderError(
            "upstream_error",
            "Parallel Search could not be reached just now. This is usually temporary — try the check again.",
        )

    def _http_error(self, response: httpx.Response) -> ProviderError:
        if response.status_code in (401, 403):
            return ProviderError(
                "not_granted",
                "Parallel Search rejected the server credentials.",
                status_code=502,
            )
        if response.status_code in (408, 504):
            return ProviderError("server_unavailable", "Parallel Search did not respond in time.")
        if response.status_code >= 500 or response.status_code == 429:
            return ProviderError(
                "upstream_error",
                "Parallel Search could not be reached just now. This is usually temporary — try the check again.",
            )
        return ProviderError("tool_error", "Parallel Search reported an error and gave no further usable detail.")

    def search(self, queries: list, session_id: str | None = None) -> dict:
        self._require_key()
        session = session_id or ("rc-" + token_hex(16))
        clamped = []
        for query in queries or []:
            shaped = clamp_query(query)
            if shaped:
                clamped.append(shaped)
            if len(clamped) == 5:
                break
        if not clamped:
            return {"sources": [], "sessionId": session}

        payload = self._post("/v1/search", {
            "objective": SEARCH_OBJECTIVE,
            "search_queries": clamped,
            "session_id": session,
        })
        results = payload.get("results") if isinstance(payload.get("results"), list) else []
        sources = []
        for item in results:
            if not isinstance(item, dict) or not item.get("url"):
                continue
            excerpts = item.get("excerpts") if isinstance(item.get("excerpts"), list) else []
            text = " ".join(str(part) for part in excerpts).strip()
            published = item.get("publish_date") or None
            sources.append({
                "url": item.get("url"),
                "title": item.get("title") or None,
                "snippet": text,
                "publishedAt": published,
                "dateCertainty": "provider-reported",
                "dateType": detect_date_type(text + " " + str(item.get("title") or "")) if published else None,
                "provider": "Parallel Search",
            })
        return {"sources": sources, "sessionId": payload.get("session_id") or session}

    def fetch(self, url: str, session_id: str | None = None) -> dict:
        self._require_key()
        session = session_id or ("rc-" + token_hex(16))
        payload = self._post("/v1/extract", {
            "urls": [url],
            "objective": FETCH_OBJECTIVE,
            "session_id": session,
            "advanced_settings": {"full_content": True},
        })
        results = payload.get("results") if isinstance(payload.get("results"), list) else []
        errors = payload.get("errors") if isinstance(payload.get("errors"), list) else []
        if not results:
            message = "The page returned no usable content."
            if errors:
                first = errors[0]
                if isinstance(first, str) and first.strip():
                    message = first.strip()
                elif isinstance(first, dict):
                    content = first.get("content")
                    if isinstance(content, str) and content.strip():
                        message = content.strip()
            raise ProviderError("fetch_empty", message)
        item = results[0] if isinstance(results[0], dict) else {}
        excerpts = item.get("excerpts") if isinstance(item.get("excerpts"), list) else []
        text = item.get("full_content") or "\n\n".join(str(part) for part in excerpts)
        if not text:
            raise ProviderError("fetch_empty", "The page returned no usable content.")
        published = item.get("publish_date") or None
        return {
            "url": item.get("url") or url,
            "title": item.get("title") or None,
            "text": text,
            "publishedAt": published,
            "dateCertainty": "provider-reported",
            "dateType": detect_date_type(str(text)[:2000] + " " + str(item.get("title") or "")) if published else None,
            "sessionId": payload.get("session_id") or session,
        }
