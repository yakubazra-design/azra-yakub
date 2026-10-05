"""OpenAI JSON transport. Prompts are forwarded unchanged."""

from __future__ import annotations

import json
import time
from typing import Any

import httpx

from backend.app.config import Settings
from backend.app.errors import AppError, RetryableUpstream, exhausted

OPENAI_URL = "https://api.openai.com/v1/chat/completions"

EXTRACT_CLAIMS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "hasFactualClaim": {"type": "boolean"},
        "primaryClaim": {"type": "string"},
        "verifiablePoints": {"type": "array", "items": {"type": "string"}},
        "excluded": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "text": {"type": "string"},
                    "reason": {"type": "string"},
                },
                "required": ["text", "reason"],
            },
        },
        "searchQueries": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["hasFactualClaim", "primaryClaim", "verifiablePoints", "excluded", "searchQueries"],
}

ASSESS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "assessment": {"type": "string"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "type": {"type": "string"},
                    "text": {"type": "string"},
                    "sources": {"type": "array", "items": {"type": "integer"}},
                },
                "required": ["type", "text", "sources"],
            },
        },
        "originalMaterial": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "established": {"type": "boolean"},
                "description": {"type": "string"},
                "source": {"anyOf": [{"type": "integer"}, {"type": "null"}]},
            },
            "required": ["established", "description", "source"],
        },
        "why": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "supporting": {"type": "string"},
                "contradicting": {"type": "string"},
                "sourceQuality": {"type": "string"},
                "timeline": {"type": "string"},
                "uncertain": {"type": "string"},
                "choice": {"type": "string"},
            },
            "required": ["supporting", "contradicting", "sourceQuality", "timeline", "uncertain", "choice"],
        },
        "uncertainty": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["assessment", "findings", "originalMaterial", "why", "uncertainty"],
}


class OpenAIClient:
    def __init__(self, settings: Settings):
        self._settings = settings
        self._client = httpx.Client(timeout=httpx.Timeout(60.0, connect=10.0))

    def close(self) -> None:
        self._client.close()

    def extract_claims(self, prompt: str, timeout: float) -> dict:
        self._require_configured()
        return self._complete(prompt, self._settings.openai_model_default.strip(), "extract_claims", EXTRACT_CLAIMS_SCHEMA, timeout)

    def assess(self, prompt: str, timeout: float) -> dict:
        self._require_configured()
        return self._complete(prompt, self._settings.openai_model_complex.strip(), "assess", ASSESS_SCHEMA, timeout)

    def _require_configured(self) -> None:
        if not self._settings.openai_configured:
            raise AppError(
                503,
                "not_configured",
                "OpenAI is not configured. Set OPENAI_API_KEY, OPENAI_MODEL_DEFAULT, and OPENAI_MODEL_COMPLEX.",
                False,
            )

    def _complete(self, prompt: str, model: str, schema_name: str, schema: dict, timeout: float) -> dict:
        try:
            return self._complete_once(prompt, model, schema_name, schema, timeout)
        except RetryableUpstream:
            time.sleep(max(0.0, self._settings.retry_backoff_seconds))
            try:
                return self._complete_once(prompt, model, schema_name, schema, timeout)
            except RetryableUpstream as exc:
                raise exhausted(exc) from exc

    def _complete_once(self, prompt: str, model: str, schema_name: str, schema: dict, timeout: float) -> dict:
        # The investigation prompt is the only message. It is not rewritten.
        body = {
            "model": model,
            "temperature": 0,
            "messages": [{"role": "user", "content": prompt}],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": schema_name, "strict": True, "schema": schema},
            },
        }
        try:
            response = self._client.post(
                OPENAI_URL,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + self._settings.openai_api_key.strip(),
                },
                json=body,
                timeout=timeout,
            )
        except httpx.TimeoutException as exc:
            raise RetryableUpstream("OpenAI did not respond in time.") from exc
        except httpx.TransportError as exc:
            raise RetryableUpstream("OpenAI could not be reached.") from exc

        if response.status_code in (401, 403):
            raise AppError(503, "not_configured", "OpenAI rejected the server credentials.", False)
        if response.status_code in (429, 500, 502, 503, 504):
            raise RetryableUpstream("OpenAI returned a temporary error.")
        if response.status_code >= 400:
            raise AppError(502, "invalid_upstream", "OpenAI rejected the reasoning request.", False)

        try:
            payload = response.json()
        except json.JSONDecodeError as exc:
            raise AppError(502, "invalid_model_output", "OpenAI returned a response that was not JSON.", False) from exc

        try:
            message = payload["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise AppError(502, "invalid_model_output", "OpenAI returned no message.", False) from exc
        if isinstance(message, dict) and message.get("refusal"):
            raise AppError(502, "invalid_model_output", "OpenAI refused the reasoning request.", False)
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str) or not content.strip():
            raise AppError(502, "invalid_model_output", "OpenAI returned empty structured output.", False)
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError as exc:
            raise AppError(502, "invalid_model_output", "OpenAI structured output was not valid JSON.", False) from exc
        if not isinstance(parsed, dict):
            raise AppError(502, "invalid_model_output", "OpenAI structured output was not a JSON object.", False)
        missing = [key for key in schema["required"] if key not in parsed]
        if missing:
            raise AppError(502, "invalid_model_output", "OpenAI structured output was missing required fields.", False)
        return parsed
