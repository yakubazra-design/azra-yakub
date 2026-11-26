"""Server-side OpenAI calls. The prompt text is supplied by the caller unchanged."""

import json
import re
import time

import httpx

from app.errors import ProviderError

RETRYABLE = {429, 500, 502, 503, 504}
_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE)


class OpenAIClient:
    def __init__(self, api_key: str, base_url: str, transport: httpx.BaseTransport | None = None, retry_wait: float = 0.4):
        self.api_key = api_key.strip()
        self.retry_wait = retry_wait
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            transport=transport,
            timeout=httpx.Timeout(60.0),
        )

    def close(self) -> None:
        self._client.close()

    def _require_key(self, message: str) -> None:
        if not self.api_key:
            raise ProviderError("no_model", message, status_code=503)

    def complete_json(self, prompt: str, model: str, missing_message: str) -> dict:
        self._require_key(missing_message)
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "response_format": {"type": "json_object"},
        }
        headers = {"Authorization": "Bearer " + self.api_key, "Content-Type": "application/json"}
        for attempt in range(2):
            try:
                response = self._client.post("/v1/chat/completions", json=payload, headers=headers)
            except httpx.TimeoutException:
                if attempt == 0:
                    time.sleep(self.retry_wait)
                    continue
                raise ProviderError("server_unavailable", "The analysis model did not respond in time.")
            if response.status_code in RETRYABLE and attempt == 0:
                time.sleep(self.retry_wait)
                continue
            if response.status_code in (401, 403):
                raise ProviderError("no_model", missing_message, status_code=502)
            if response.status_code >= 400:
                raise ProviderError("upstream_error", "The analysis model could not complete this request.")
            return self._parse(response)
        raise ProviderError("upstream_error", "The analysis model could not complete this request.")

    def _parse(self, response: httpx.Response) -> dict:
        try:
            body = response.json()
            content = body["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise ProviderError("upstream_error", "The analysis model returned a response that could not be read.") from exc
        if not isinstance(content, str):
            raise ProviderError("upstream_error", "The analysis model returned a response that could not be read.")
        text = content.strip()
        if text.startswith("```"):
            text = _FENCE.sub("", text).strip()
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ProviderError("upstream_error", "The analysis model did not return JSON.") from exc
        if not isinstance(parsed, dict):
            raise ProviderError("upstream_error", "The analysis model did not return a JSON object.")
        return parsed
