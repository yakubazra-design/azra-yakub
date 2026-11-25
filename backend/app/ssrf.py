"""DNS and redirect checks before a user URL is fetched.

Each hop is limited to http or https. Hostnames are resolved twice. A blocked
address in either answer rejects the hop. The connection is pinned to an
address from those answers, with a connect timeout, a read timeout, a response
read cap, and a redirect cap. Every redirect is checked the same way.

Parallel still opens its own connection after this gate. A name can change
addresses between this check and that connection, so this is not complete SSRF
protection for the provider fetch.
"""

import http.client
import ipaddress
import socket
import ssl
from urllib.parse import urljoin, urlparse

from app.urls import address_is_blocked, public_http_url

MAX_REDIRECTS = 5
CONNECT_TIMEOUT_SECONDS = 5.0
READ_TIMEOUT_SECONDS = 8.0
MAX_RESPONSE_BYTES = 1024 * 1024


class UrlRejected(ValueError):
    """The URL must not be fetched."""


def _public_answers(answers: list[str]) -> list[str]:
    if not answers:
        raise UrlRejected("That host is not allowed.")
    approved = []
    for raw in answers:
        ip = raw.split("%", 1)[0]
        try:
            address = ipaddress.ip_address(ip)
        except ValueError as exc:
            raise UrlRejected("That address is not allowed.") from exc
        if address_is_blocked(address):
            raise UrlRejected("That address is not allowed.")
        rendered = address.compressed
        if rendered not in approved:
            approved.append(rendered)
    return approved


def default_resolve(host: str, port: int) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UrlRejected("That host is not allowed.") from exc
    return [info[4][0] for info in infos]


def _pinned_ips(host: str, port: int, resolve) -> list[str]:
    first = _public_answers(resolve(host, port))
    second = _public_answers(resolve(host, port))
    shared = [ip for ip in first if ip in second]
    return shared or first


def _target(url: str, resolve) -> dict:
    checked = public_http_url(url)
    parsed = urlparse(checked)
    host = (parsed.hostname or "").lower().rstrip(".")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        ips = _public_answers([host])
    else:
        ips = _pinned_ips(host, port, resolve)
    path = parsed.path or "/"
    if parsed.query:
        path = path + "?" + parsed.query
    return {
        "url": checked,
        "scheme": parsed.scheme,
        "host": host,
        "port": port,
        "path": path,
        "ips": ips,
    }


def pinned_exchange(target: dict, connect_timeout: float = CONNECT_TIMEOUT_SECONDS, read_timeout: float = READ_TIMEOUT_SECONDS) -> tuple[int, str | None]:
    """GET one pinned address. Redirects are not followed here."""
    host = target["host"]
    port = int(target["port"])
    ip = target["ip"]
    scheme = target["scheme"]
    path = target["path"] or "/"
    raw = None
    try:
        raw = socket.create_connection((ip, port), timeout=connect_timeout)
        raw.settimeout(read_timeout)
        if scheme == "https":
            context = ssl.create_default_context()
            sock = context.wrap_socket(raw, server_hostname=host)
            conn = http.client.HTTPSConnection(host, port, timeout=read_timeout, context=context)
        else:
            sock = raw
            conn = http.client.HTTPConnection(host, port, timeout=read_timeout)
        conn.sock = sock
        default_port = 443 if scheme == "https" else 80
        host_header = host if port == default_port else f"{host}:{port}"
        conn.request(
            "GET",
            path,
            headers={
                "Host": host_header,
                "User-Agent": "RealityCheckAI",
                "Accept": "*/*",
                "Connection": "close",
            },
        )
        response = conn.getresponse()
        remaining = MAX_RESPONSE_BYTES
        while remaining > 0:
            chunk = response.read(min(65536, remaining))
            if not chunk:
                break
            remaining -= len(chunk)
        location = response.getheader("Location")
        status = response.status
        response.close()
        conn.close()
        return status, location
    except UrlRejected:
        raise
    except Exception as exc:
        raise UrlRejected("That host is not allowed.") from exc
    finally:
        if raw is not None:
            try:
                raw.close()
            except Exception:
                pass


def assert_safe_to_fetch(url: str, *, resolve=None, exchange=None) -> str:
    """Check the URL and each redirect. Return the final hop URL."""
    resolve = resolve or default_resolve
    exchange = exchange or pinned_exchange
    try:
        current = public_http_url(url)
    except ValueError as exc:
        raise UrlRejected(str(exc)) from exc
    seen = set()
    for hop in range(MAX_REDIRECTS + 1):
        if current in seen or len(current) > 2048:
            raise UrlRejected("That address is not allowed.")
        seen.add(current)
        try:
            target = _target(current, resolve)
        except ValueError as exc:
            raise UrlRejected(str(exc)) from exc
        status = None
        location = None
        error = None
        for ip in target["ips"]:
            try:
                status, location = exchange({**target, "ip": ip})
                error = None
                break
            except UrlRejected as exc:
                error = exc
        if error is not None or status is None:
            raise error or UrlRejected("That host is not allowed.")
        if status not in {301, 302, 303, 307, 308}:
            return current
        if hop == MAX_REDIRECTS or not location:
            raise UrlRejected("Too many redirects.")
        current = urljoin(current, location)
    raise UrlRejected("Too many redirects.")
