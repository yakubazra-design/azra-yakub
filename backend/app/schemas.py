"""Request bodies for the four transport endpoints."""

import ipaddress
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator


def _public_http_url(value: str) -> str:
    raw = value.strip()
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http and https URLs are allowed.")
    if parsed.username or parsed.password:
        raise ValueError("URLs must not include credentials.")
    host = parsed.hostname
    if not host:
        raise ValueError("URL must include a host.")
    normalized = host.lower().rstrip(".")
    if normalized in {"localhost", "localhost.localdomain"} or normalized.endswith(".local") or normalized.endswith(".internal"):
        raise ValueError("That host is not allowed.")
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        address = None
    if address is not None and (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    ):
        raise ValueError("That address is not allowed.")
    return raw


class SearchRequest(BaseModel):
    objective: str = Field(min_length=1, max_length=4000)
    search_queries: list[str] = Field(min_length=1, max_length=5)
    session_id: str = Field(min_length=1, max_length=100)

    @field_validator("objective", "session_id")
    @classmethod
    def strip_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be blank")
        return text

    @field_validator("search_queries")
    @classmethod
    def queries(cls, value: list[str]) -> list[str]:
        cleaned = []
        for item in value:
            text = item.strip()
            if not text:
                raise ValueError("search queries must not be blank")
            if len(text) > 400:
                raise ValueError("search query is too long")
            cleaned.append(text)
        return cleaned


class FetchRequest(BaseModel):
    urls: list[str] = Field(min_length=1, max_length=20)
    objective: str = Field(min_length=1, max_length=4000)
    full_content: bool
    session_id: str = Field(min_length=1, max_length=100)

    @field_validator("objective", "session_id")
    @classmethod
    def strip_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be blank")
        return text

    @field_validator("urls")
    @classmethod
    def urls_are_public_http(cls, value: list[str]) -> list[str]:
        return [_public_http_url(item) for item in value]


class PromptRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=120000)
    modelTier: str

    @field_validator("prompt")
    @classmethod
    def strip_prompt(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be blank")
        return text
