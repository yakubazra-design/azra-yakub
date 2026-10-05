"""Date-label detection copied from frontend/engine.js detectDateType."""

import re

_UPDATED = re.compile(
    r"\blast\s+updated\b|\bupdated\s+on\b|\bupdated:\s*\w",
    re.IGNORECASE,
)
_PUBLISHED = re.compile(
    r"\bpublished\s+(on|:)?\s*\w|\bpublication\s+date\b|\bposted\s+on\b",
    re.IGNORECASE,
)


def detect_date_type(text: str) -> str:
    s = str(text or "")
    if _UPDATED.search(s):
        return "updated"
    if _PUBLISHED.search(s):
        return "published"
    return "unspecified"


def clamp_query(query: str) -> str:
    """Provider constraint: at most 6 words. Never invented — only reshaped."""
    words = [w for w in str(query or "").split() if w]
    if len(words) > 6:
        words = words[:6]
    return " ".join(words)


def host_of(url: str) -> str:
    try:
        from urllib.parse import urlparse

        host = urlparse(url).hostname or ""
        return host.removeprefix("www.").lower()
    except Exception:
        return ""
