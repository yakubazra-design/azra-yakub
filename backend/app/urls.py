"""Text checks for URLs before a fetch is attempted.

DNS answers and redirects are checked in app.ssrf. A URL that passes this
function can still be rejected there.
"""

import ipaddress
import re
from urllib.parse import urlparse

BLOCKED_HOSTS = {
    "localhost",
    "localhost.localdomain",
    "metadata",
    "metadata.google.internal",
    "metadata.google.com",
    "metadata.internal",
    "instance-data",
    "instance-data.ec2.internal",
}

# Cloud metadata addresses. Link-local and non-global ranges are rejected too.
METADATA_IPS = {
    "169.254.169.254",
    "169.254.170.2",
    "100.100.100.200",
    "168.63.129.16",
    "fd00:ec2::254",
}


def address_is_blocked(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address_is_blocked(address.ipv4_mapped)
    if address.compressed in METADATA_IPS or str(address) in METADATA_IPS:
        return True
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
        or not address.is_global
    )


def _literal_address(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    if re.fullmatch(r"\d{1,10}", host):
        number = int(host)
        if number > 0xFFFFFFFF:
            raise ValueError("That address is not allowed.")
        return ipaddress.ip_address(number)
    if re.fullmatch(r"0x[0-9a-f]+", host) or re.fullmatch(r"[0-9.]+", host):
        raise ValueError("That address is not allowed.")
    return None


_MAX_SOURCE_URL = 2048
_ABSOLUTE_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)://")


def source_http_url(value: str) -> str | None:
    """Return a source URL that may be used as a link, or None.

    Only http and https are accepted. Mixed-case schemes are kept as written
    after surrounding whitespace is removed. Any other scheme, including
    javascript, data, file, and blob, is not a link. This does not decide
    whether the host is safe to fetch.
    """
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw or len(raw) > _MAX_SOURCE_URL:
        return None
    if any(ord(char) < 33 or ord(char) == 127 or char == "\\" for char in raw):
        return None
    match = _ABSOLUTE_SCHEME.match(raw)
    if match is None:
        return None
    scheme = match.group(1).lower()
    if scheme not in ("http", "https"):
        return None
    try:
        parsed = urlparse(raw)
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme.lower() != scheme or not parsed.hostname or port == 0:
        return None
    return raw


def stored_source_url(value) -> str | None:
    """Keep a safe http(s) URL, or the text of an unsafe one.

    An unsafe value is still returned so a card can show it. It is not a
    link. The text is capped so a provider payload cannot fill the ledger.
    """
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if not stripped:
        return None
    safe = source_http_url(stripped)
    if safe is not None:
        return safe
    return stripped[:_MAX_SOURCE_URL]


def public_http_url(value: str) -> str:
    raw = value.strip()
    if any(ord(char) < 32 or char.isspace() for char in raw):
        raise ValueError("Only http and https URLs are allowed.")
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http and https URLs are allowed.")
    if parsed.username or parsed.password:
        raise ValueError("URLs must not include credentials.")
    host = parsed.hostname
    if not host:
        raise ValueError("URL must include a host.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("That address is not allowed.") from exc
    if port == 0:
        raise ValueError("That address is not allowed.")
    normalized = host.lower().rstrip(".")
    if (
        normalized in BLOCKED_HOSTS
        or normalized.endswith(".local")
        or normalized.endswith(".internal")
        or normalized.endswith(".localhost")
    ):
        raise ValueError("That host is not allowed.")
    address = _literal_address(normalized)
    if address is not None and address_is_blocked(address):
        raise ValueError("That address is not allowed.")
    return raw
