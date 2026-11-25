"""Security headers differ for local HTTP and production HTTPS."""

import hashlib
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import CONTENT_SECURITY_POLICY, HSTS_VALUE, REFERRER_POLICY, create_app
from test_api import _ledger, _settings
from test_production import _production

EXIFR = Path(__file__).resolve().parents[2] / "frontend" / "vendor" / "exifr-7.1.3.umd.js"
EXIFR_SHA256 = "2bd05117781c12ddd965dee846de3b3f986b5ecb4c7f6a78f2d2ec1db7c65ae7"
INDEX = Path(__file__).resolve().parents[2] / "frontend" / "index.html"


def _assert_common(headers) -> None:
    policy = headers["content-security-policy"]
    assert policy == CONTENT_SECURITY_POLICY
    assert "script-src 'self'" in policy
    assert "unsafe-eval" not in policy
    assert "script-src 'self' 'unsafe-inline'" not in policy
    assert "style-src-attr 'unsafe-inline'" in policy
    assert "frame-ancestors 'none'" in policy
    assert "https://fonts.googleapis.com" in policy
    assert "blob:" in policy
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == REFERRER_POLICY


def test_local_responses_omit_strict_transport_security(tmp_path):
    app = create_app(settings=_settings(ledger_path=_ledger(tmp_path)))
    with TestClient(app) as client:
        health = client.get("/api/health")
        page = client.get("/")
    assert health.status_code == page.status_code == 200
    _assert_common(health.headers)
    _assert_common(page.headers)
    assert "strict-transport-security" not in health.headers
    assert "strict-transport-security" not in page.headers
    assert "jsdelivr" not in page.text
    assert "vendor/exifr-7.1.3.umd.js" in page.text
    secure_cookie_app = create_app(settings=_settings(ledger_path=_ledger(tmp_path, "secure.sqlite"), cookie_secure=True, auth_secret=""))
    with TestClient(secure_cookie_app) as client:
        local_secure = client.get("/api/health")
    assert "strict-transport-security" not in local_secure.headers


def test_production_responses_include_strict_transport_security(tmp_path):
    app = create_app(settings=_production(tmp_path))
    with TestClient(app) as client:
        health = client.get("/api/health")
        page = client.get("/")
    assert health.status_code == page.status_code == 200
    _assert_common(health.headers)
    _assert_common(page.headers)
    assert health.headers["strict-transport-security"] == HSTS_VALUE
    assert page.headers["strict-transport-security"] == HSTS_VALUE
    assert "includeSubDomains" not in health.headers["strict-transport-security"]
    assert "preload" not in health.headers["strict-transport-security"]


def test_vendored_exifr_matches_the_pinned_release():
    data = EXIFR.read_bytes()
    assert hashlib.sha256(data).hexdigest() == EXIFR_SHA256
    assert b"eval(" not in data
    assert b"new Function" not in data
    text = INDEX.read_text(encoding="utf-8")
    assert "cdn.jsdelivr.net" not in text
    assert "vendor/exifr-7.1.3.umd.js" in text
