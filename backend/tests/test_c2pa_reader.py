"""C2PA reader adapter. Local fixtures only.

Signing in this file creates the fixtures. The adapter under test does not
import a builder or a signer, and it does not open the ledger.
"""

import datetime
import io
import json
import socket
import struct
import subprocess
import tempfile
import threading
import time
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import c2pa
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID

import app.c2pa_reader as reader_module
from app.c2pa_reader import (
    MAX_MANIFEST_BYTES,
    MAX_TRUST_ANCHOR_BYTES,
    NATIVE_LIBRARY_VERSION,
    TECHNICAL_FAILURE_CODES,
    VERIFICATION_SETTINGS,
    ProvenanceSettingsError,
    _manifest_exceeds_limit,
    _map_store,
    _result_from_store_json,
    native_library_version,
    read_image_provenance,
    run_bounded,
)
from app.validation import VALID_ASSESSMENTS
from app.image_evidence import build_image_evidence
from app.images import detect_image
from app.prompts import assess_prompt

SIGNER_NAME = "RC-PROMPT-SIGNER-9f3a"
AGENT_NAME = "RC-PROMPT-AGENT-9f3a"
GPS_TOKEN = "RC-GPS-37.808333-122.271111"
REMOTE_TOKEN = "rc-remote-9f3a"


def _jpeg() -> bytes:
    frame = b"\x08" + struct.pack(">HH", 1, 1) + b"\x01\x01\x11\x00"
    return b"\xff\xd8\xff\xc0" + struct.pack(">H", len(frame) + 2) + frame + b"\xff\xd9"


def _png() -> bytes:
    def chunk(tag: bytes, payload: bytes) -> bytes:
        crc = zlib.crc32(tag + payload) & 0xFFFFFFFF
        return struct.pack(">I", len(payload)) + tag + payload + struct.pack(">I", crc)

    header = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    pixels = zlib.compress(b"\x00\xff\x00\x00")
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", pixels) + chunk(b"IEND", b"")


def _certificate(
    common_name: str,
    *,
    ocsp_url: str | None = None,
    not_before: datetime.datetime | None = None,
    not_after: datetime.datetime | None = None,
    ca: bool = False,
    issuer_name: x509.Name | None = None,
    issuer_key=None,
):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, GPS_TOKEN),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_name or name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or (now - datetime.timedelta(days=1)))
        .not_valid_after(not_after or (now + datetime.timedelta(days=30)))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=not ca,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                (issuer_key or key).public_key()
            ),
            critical=False,
        )
    )
    if not ca:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=False,
        )
    if ocsp_url is not None:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier(ocsp_url),
                )
            ]),
            critical=False,
        )
    certificate = builder.sign(issuer_key or key, hashes.SHA256())
    return key, certificate


def _sign_jpeg(image: bytes, key, certificate, *, remote_url: str | None = None, embed: bool = True, extra_certificates=(), tsa_url: str | None = None) -> bytes:
    pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    pem += "".join(_pem(item) for item in extra_certificates)

    def _callback(payload: bytes) -> bytes:
        return key.sign(payload, ec.ECDSA(hashes.SHA256()))

    if tsa_url is None:
        signer = c2pa.Signer.from_callback(_callback, c2pa.C2paSigningAlg.ES256, pem)
    else:
        signer = c2pa.Signer.from_callback(_callback, c2pa.C2paSigningAlg.ES256, pem, tsa_url)
    builder = c2pa.Builder.from_json({
        "claim_generator": AGENT_NAME + "/9.9",
        "claim_generator_info": [{"name": AGENT_NAME, "version": "9.9"}],
    })
    builder.set_intent(c2pa.C2paBuilderIntent.CREATE, c2pa.C2paDigitalSourceType.DIGITAL_CAPTURE)
    if remote_url is not None:
        builder.set_remote_url(remote_url)
    if not embed:
        builder.set_no_embed()
    output = io.BytesIO()
    builder.sign(signer, "image/jpeg", io.BytesIO(image), output)
    return output.getvalue()


def _pem(certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode()


def _sign_over(image, key, certificate, ingredient, *, relationship, intent):
    pem = _pem(certificate)

    def _callback(payload: bytes) -> bytes:
        return key.sign(payload, ec.ECDSA(hashes.SHA256()))

    signer = c2pa.Signer.from_callback(_callback, c2pa.C2paSigningAlg.ES256, pem)
    builder = c2pa.Builder.from_json({
        "claim_generator": AGENT_NAME + "/9.9",
        "claim_generator_info": [{"name": AGENT_NAME, "version": "9.9"}],
    })
    builder.add_ingredient(
        {"title": GPS_TOKEN, "relationship": relationship},
        "image/jpeg",
        io.BytesIO(ingredient),
    )
    if intent == "edit":
        builder.set_intent(c2pa.C2paBuilderIntent.EDIT)
    else:
        builder.set_intent(c2pa.C2paBuilderIntent.UPDATE)
    output = io.BytesIO()
    builder.sign(signer, "image/jpeg", io.BytesIO(image), output)
    return output.getvalue()


def _code(code: str, label: str) -> dict:
    return {"code": code, "url": "self#jumbf=/c2pa/" + label + "/c2pa.signature"}


def _passing_items(label: str) -> list[dict]:
    return [_code(code, label) for code in _PASSING]


def _proven_items(label: str) -> list[dict]:
    return _passing_items(label) + [_code("signingCredential.ocsp.notRevoked", label)]


def _library_state(blob: bytes, trust: str) -> str | None:
    settings = c2pa.Settings.from_dict({
        "verify": {
            "remote_manifest_fetch": False,
            "ocsp_fetch": False,
            "ocsp_fetch_should_override": False,
            "verify_after_reading": True,
            "verify_trust": True,
            "verify_timestamp_trust": True,
        },
        "trust": {"trust_anchors": trust},
    })
    context = c2pa.Context.builder().with_settings(settings).build()
    reader = c2pa.Reader.try_create(io.BytesIO(blob), context=context)
    try:
        return json.loads(reader.json()).get("validation_state")
    finally:
        reader.close()


def _listener():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(5)
    server.settimeout(0.2)
    accepted = []
    stop = threading.Event()

    def _accept() -> None:
        while not stop.is_set():
            try:
                connection, address = server.accept()
            except socket.timeout:
                continue
            accepted.append(address)
            try:
                connection.recv(128)
            except Exception:
                pass
            connection.close()

    thread = threading.Thread(target=_accept, daemon=True)
    thread.start()
    return server, accepted, stop, thread


def _secrets_absent(text: str) -> None:
    assert SIGNER_NAME not in text
    assert AGENT_NAME not in text
    assert GPS_TOKEN not in text
    assert "BEGIN CERTIFICATE" not in text
    assert "c2pa.created" not in text
    assert "c2pa.actions" not in text


def test_native_library_is_the_pinned_c2pa_rs_build():
    assert c2pa.__version__ == "0.39.0"
    assert native_library_version() == NATIVE_LIBRARY_VERSION == "0.92.0"


def test_jpeg_and_png_without_a_manifest_have_no_credentials():
    jpeg = read_image_provenance(_jpeg())
    png = read_image_provenance(_png())
    assert jpeg["status"] == "no_credentials"
    assert png["status"] == "no_credentials"
    assert jpeg["checks"] is None
    assert png["checks"] is None
    assert jpeg["manifests"] == []
    assert jpeg["version"] == "c2pa-reader-2"
    assert jpeg["actions"] == []
    assert jpeg["actionsWithheld"] is True


def test_unsupported_container_is_not_reported_as_absent():
    result = read_image_provenance(b"\xff\xd8\xff\xd9")
    assert result["status"] == "credentials_malformed"
    assert result["status"] != "no_credentials"
    assert result["checks"]["signature"] == "not_checked"
    assert result["actions"] == []


def test_self_signed_certificate_is_not_trusted_and_tamper_hides_actions():
    key, certificate = _certificate(SIGNER_NAME)
    signed = _sign_jpeg(_jpeg(), key, certificate)
    untrusted = read_image_provenance(signed)
    assert untrusted["status"] == "credentials_untrusted"
    assert untrusted["checks"]["signature"] == "valid"
    assert untrusted["checks"]["assetBinding"] == "bound"
    assert untrusted["checks"]["certificateTrust"] == "untrusted"
    assert untrusted["checks"]["revocation"] == "skipped"
    assert untrusted["actions"] == []
    assert untrusted["actionsWithheld"] is True
    _secrets_absent(str(untrusted))

    start = signed.find(b"\xff\xc0")
    assert start > 0
    tampered = bytearray(signed)
    tampered[start + 5] ^= 0x01
    invalid = read_image_provenance(bytes(tampered))
    assert invalid["status"] == "credentials_invalid"
    assert invalid["checks"]["assetBinding"] == "mismatch"
    assert invalid["actions"] == []
    assert invalid["actionsWithheld"] is True
    _secrets_absent(str(invalid))

    pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    anchored = _read_anchored(signed, pem)
    assert anchored["status"] == "credentials_malformed"
    assert anchored["status"] != "credentials_trusted"
    assert anchored["checks"] == {
        "signature": "valid",
        "assetBinding": "bound",
        "certificateTrust": "trusted",
        "certificateValidity": "inside_at_asserted_time",
        "revocation": "skipped",
        "timestamp": "absent",
    }
    assert anchored["actions"] == []
    assert anchored["version"] == "c2pa-reader-2"
    assert len(anchored["manifests"]) == 1
    assert anchored["manifests"][0]["role"] == "active"
    assert anchored["manifests"][0]["status"] == "credentials_malformed"
    assert anchored["manifests"][0]["checks"] == anchored["checks"]
    _secrets_absent(str(anchored))


def test_unknown_verification_setting_is_rejected():
    image = _jpeg()
    with pytest.raises(ProvenanceSettingsError):
        read_image_provenance(image, settings={"verify": {"not_a_real_setting": False}})
    with pytest.raises(ProvenanceSettingsError):
        read_image_provenance(image, settings={"verify.remote_manifest_fetch": True})
    with pytest.raises(ProvenanceSettingsError):
        read_image_provenance(image, settings={"trust": {"trust_anchors": "local"}})
    assert VERIFICATION_SETTINGS["verify.remote_manifest_fetch"] is False
    assert VERIFICATION_SETTINGS["verify.ocsp_fetch"] is False
    assert VERIFICATION_SETTINGS["verify.ocsp_fetch_should_override"] is False
    assert VERIFICATION_SETTINGS["verify.verify_after_reading"] is True
    assert VERIFICATION_SETTINGS["verify.verify_trust"] is True
    assert VERIFICATION_SETTINGS["verify.verify_timestamp_trust"] is True


def test_remote_manifest_and_ocsp_urls_are_not_contacted():
    server, accepted, stop, thread = _listener()
    host, port = server.getsockname()
    remote_url = "http://" + host + ":" + str(port) + "/" + REMOTE_TOKEN
    ocsp_url = "http://" + host + ":" + str(port) + "/ocsp"
    try:
        key, certificate = _certificate(SIGNER_NAME, ocsp_url=ocsp_url)
        remote = _sign_jpeg(_jpeg(), key, certificate, remote_url=remote_url, embed=False)
        embedded = _sign_jpeg(_jpeg(), key, certificate, remote_url=remote_url, embed=True)
        remote_result = read_image_provenance(remote)
        embedded_result = read_image_provenance(embedded)
    finally:
        time.sleep(0.3)
        stop.set()
        thread.join(1)
        server.close()
    assert accepted == []
    assert remote_result["status"] == "credentials_malformed"
    assert remote_result["status"] != "no_credentials"
    assert embedded_result["checks"]["revocation"] == "skipped"
    assert embedded_result["status"] == "credentials_untrusted"
    rendered = str(remote_result) + str(embedded_result)
    assert REMOTE_TOKEN not in rendered
    assert str(port) not in rendered
    _secrets_absent(rendered)


def test_malformed_and_oversized_inputs_fail_closed():
    _not_scanned(b"this is not an image")
    oversized = b"\x89PNG\r\n\x1a\n" + struct.pack(">I", MAX_MANIFEST_BYTES + 1) + b"caBX"
    result = read_image_provenance(oversized)
    assert result["status"] == "credentials_malformed"
    assert result["checks"]["signature"] == "not_checked"
    assert read_image_provenance(b"")["status"] == "credentials_malformed"
    assert read_image_provenance(None)["status"] == "credentials_malformed"


def test_reader_timeout_kills_the_child_process():
    started = time.monotonic()
    kind, value = run_bounded(time.sleep, (5,), 0.4)
    elapsed = time.monotonic() - started
    assert kind == "timeout"
    assert value is None
    assert elapsed < 2


def test_fixture_secrets_are_not_in_the_assessment_prompt():
    key, certificate = _certificate(SIGNER_NAME)
    signed = _sign_jpeg(_jpeg(), key, certificate)
    result = read_image_provenance(signed)
    ctx = {
        "primaryClaim": "A local fixture was sealed.",
        "verifiablePoints": ["The fixture exists."],
        "sources": [],
        "independence": {},
        "timeline": {},
        "sealedImage": True,
    }
    prompt = assess_prompt(ctx)
    _secrets_absent(prompt)
    _secrets_absent(str(result))
    evidence = build_image_evidence(
        {"sha256": "ab" * 32, "byteLength": len(signed), "mediaType": "image/jpeg"},
        "INSUFFICIENT_EVIDENCE",
        availability="retained",
        checked_at="2026-11-18T00:00:00+00:00",
    )
    assert evidence["provenance"]["status"] == "not_examined"
    assert evidence["provenance"]["version"] == "absent"
    _secrets_absent(str(evidence))
    application = Path(__file__).resolve().parents[1] / "app"
    assert "read_image_provenance" not in (application / "main.py").read_text()
    assert "read_image_provenance" not in (application / "prompts.py").read_text()
    adapter = (application / "c2pa_reader.py").read_text()
    assert "Builder" not in adapter
    assert "Signer" not in adapter


def _png_chunk(tag: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + tag + payload + b"xxxx"


def _png_with(chunks: list[tuple[bytes, bytes]]) -> bytes:
    body = b"".join(_png_chunk(tag, payload) for tag, payload in chunks)
    return b"\x89PNG\r\n\x1a\n" + body


def _webp_chunk(tag: bytes, payload: bytes) -> bytes:
    pad = b"\x00" if len(payload) & 1 else b""
    return tag + struct.pack("<I", len(payload)) + payload + pad


def _webp_with(chunks: list[tuple[bytes, bytes]]) -> bytes:
    body = b"WEBP" + b"".join(_webp_chunk(tag, payload) for tag, payload in chunks)
    return b"RIFF" + struct.pack("<I", len(body)) + body


def _app11(payload: bytes) -> bytes:
    return b"\xff\xeb" + struct.pack(">H", len(payload) + 2) + payload


def _blocked(data: bytes) -> dict:
    called = []
    original = reader_module.run_bounded

    def wrap(target, args, timeout):
        called.append(len(args[0]))
        return original(target, args, timeout)

    reader_module.run_bounded = wrap
    try:
        result = read_image_provenance(data)
    finally:
        reader_module.run_bounded = original
    assert called == []
    assert result["status"] == "credentials_malformed"
    assert result["checks"]["signature"] == "not_checked"
    assert result["actions"] == []
    return result


def _store(success, failure=(), informational=("signingCredential.ocsp.skipped",), *, failure_url=None, success_url=None):
    label = "urn:c2pa:active"
    active_url = "self#jumbf=/c2pa/" + label + "/c2pa.signature"

    def item(code, url):
        return {"code": code, "url": url}

    return {
        "active_manifest": label,
        "manifests": {label: {}},
        "validation_results": {
            "activeManifest": {
                "success": [item(code, success_url or active_url) for code in success],
                "informational": [item(code, active_url) for code in informational],
                "failure": [item(code, failure_url or active_url) for code in failure],
            }
        },
    }


_PASSING = (
    "claimSignature.validated",
    "claimSignature.insideValidity",
    "assertion.dataHash.match",
    "signingCredential.trusted",
)


def test_many_chunks_without_c2pa_are_not_rejected_as_oversized():
    texts = [(b"tEXt", b"x") for _ in range(70)]
    header = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    pixels = zlib.compress(b"\x00\xff\x00\x00")
    png = _png_with([(b"IHDR", header), *texts, (b"IDAT", pixels), (b"IEND", b"")])
    assert _manifest_exceeds_limit(png) is False
    assert read_image_provenance(png)["status"] == "no_credentials"
    frame = b"\x08" + struct.pack(">HH", 1, 1) + b"\x01\x01\x11\x00"
    sof = b"\xff\xc0" + struct.pack(">H", len(frame) + 2) + frame
    entropy = b"\x00\xff\x00\x11\x22"
    jpeg = b"\xff\xd8" + sof + b"\xff\xda" + struct.pack(">H", 2) + entropy + b"\xff\xd9"
    assert _manifest_exceeds_limit(jpeg) is False
    webp_chunks = [(b"xxxx", b"") for _ in range(70)]
    webp_chunks.append((b"VP8 ", b"\x00"))
    webp = _webp_with(webp_chunks)
    assert _manifest_exceeds_limit(webp) is False


def test_oversized_manifest_layouts_never_reach_the_reader():
    oversized = b"\x00" * (MAX_MANIFEST_BYTES + 1)
    texts = [(b"tEXt", b"x") for _ in range(64)]
    png = _png_with([*texts, (b"caBX", oversized), (b"IEND", b"")])
    assert _manifest_exceeds_limit(png) is True
    _blocked(png)

    small = [(b"xxxx", b"") for _ in range(64)]
    webp = _webp_with([*small, (b"C2PA", oversized)])
    assert _manifest_exceeds_limit(webp) is True
    _blocked(webp)

    payload = b"A" * 65533
    frame = b"\x08" + struct.pack(">HH", 1, 1) + b"\x01\x01\x11\x00"
    sof = b"\xff\xc0" + struct.pack(">H", len(frame) + 2) + frame
    ordered = b"\xff\xd8" + b"".join(_app11(payload) for _ in range(17)) + sof + b"\xff\xd9"
    assert _manifest_exceeds_limit(ordered) is True
    _blocked(ordered)

    after_sos = (
        b"\xff\xd8" + sof + b"\xff\xda" + struct.pack(">H", 2)
        + b"".join(_app11(payload) for _ in range(17))
        + b"\xff\xd9"
    )
    assert _manifest_exceeds_limit(after_sos) is True
    _blocked(after_sos)

    half = b"\x00" * 600_000
    aggregate = _png_with([(b"caBX", half), (b"c2pa", half), (b"IEND", b"")])
    assert _manifest_exceeds_limit(aggregate) is True
    _blocked(aggregate)


def test_incomplete_container_walks_fail_closed():
    truncated = b"\x89PNG\r\n\x1a\n" + struct.pack(">I", MAX_MANIFEST_BYTES + 1) + b"caBX"
    assert _manifest_exceeds_limit(truncated) is True
    _blocked(truncated)
    broken = b"\xff\xd8\x00" + _app11(b"A" * 65533) * 17
    assert _manifest_exceeds_limit(broken) is True
    _blocked(broken)
    short_webp = b"RIFF" + struct.pack("<I", 4) + b"WEBP" + b"C2PA" + struct.pack("<I", MAX_MANIFEST_BYTES + 1)
    assert _manifest_exceeds_limit(short_webp) is True
    _blocked(short_webp)


def test_failure_for_another_manifest_is_not_discarded():
    other = "self#jumbf=/c2pa/urn:c2pa:other/c2pa.assertions/c2pa.hash.data"
    mapped = _map_store(_store(_PASSING, ("assertion.dataHash.mismatch",), failure_url=other))
    assert mapped["status"] == "credentials_invalid"
    assert mapped["checks"]["assetBinding"] == "mismatch"
    assert mapped["status"] != "credentials_trusted"


def test_revocation_in_informational_results_fails_closed():
    mapped = _map_store(_store(
        _PASSING,
        informational=("signingCredential.ocsp.skipped", "signingCredential.ocsp.revoked"),
    ))
    assert mapped["status"] == "credentials_invalid"
    assert mapped["checks"]["revocation"] == "revoked"
    unexpected = _map_store(_store(
        _PASSING + ("signingCredential.ocsp.revoked",),
        informational=("signingCredential.ocsp.skipped",),
    ))
    assert unexpected["status"] == "credentials_invalid"
    assert unexpected["checks"]["revocation"] == "revoked"


def test_unknown_and_conflicting_codes_are_not_trusted():
    unknown = _map_store(_store(_PASSING, ("general.error",)))
    assert unknown["status"] == "credentials_malformed"
    assert unknown["status"] != "credentials_trusted"
    conflict = _map_store(_store(_PASSING, ("assertion.dataHash.mismatch",)))
    assert conflict["status"] == "credentials_invalid"
    assert conflict["checks"]["assetBinding"] == "mismatch"
    foreign_success = _map_store(_store(
        _PASSING,
        success_url="self#jumbf=/c2pa/urn:c2pa:other/c2pa.signature",
    ))
    assert foreign_success["status"] != "credentials_trusted"
    foreign_timestamp = _store(
        _PASSING,
        informational=("timeStamp.malformed",),
    )
    foreign_timestamp["validation_results"]["activeManifest"]["informational"][0]["url"] = (
        "self#jumbf=/c2pa/urn:c2pa:other/c2pa.signature"
    )
    mapped_timestamp = _map_store(foreign_timestamp)
    assert mapped_timestamp["status"] == "credentials_invalid"
    assert mapped_timestamp["checks"]["timestamp"] == "malformed"
    untrusted = _map_store(_store(
        (
            "claimSignature.validated",
            "claimSignature.insideValidity",
            "assertion.dataHash.match",
        ),
        ("signingCredential.untrusted",),
    ))
    assert untrusted["status"] == "credentials_untrusted"
    assert untrusted["checks"]["certificateTrust"] == "untrusted"


def _segment(marker: int, payload: bytes) -> bytes:
    return bytes((0xFF, marker)) + struct.pack(">H", len(payload) + 2) + payload


def _camera_jpeg(*, before=(), after=(), entropy=b"\x10\x11\xff\x00\x22") -> bytes:
    """A baseline JPEG with a restart interval, tables, and optional APP11."""
    app0 = _segment(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")
    dqt = _segment(0xDB, bytes(65))
    dht = _segment(0xC4, bytes(19))
    dri = _segment(0xDD, b"\x00\x01")
    frame = b"\x08" + struct.pack(">HH", 16, 16) + b"\x03\x01\x22\x00\x02\x11\x01\x03\x11\x01"
    sof = _segment(0xC0, frame)
    sos = _segment(0xDA, b"\x03\x01\x00\x02\x11\x03\x11\x00\x3f\x00")
    return (
        b"\xff\xd8" + app0 + b"".join(before)
        + dqt + dht + dri + sof + sos
        + entropy + b"\xff\xd0" + b"\x33\xff\x00\x44"
        + b"\xff\xd7" + b"\x55"
        + b"".join(after) + b"\xff\xd9"
    )


def _progressive_jpeg() -> bytes:
    frame = b"\x08" + struct.pack(">HH", 8, 8) + b"\x03\x01\x22\x00\x02\x11\x01\x03\x11\x01"
    sof = _segment(0xC2, frame)
    dht = _segment(0xC4, bytes(19))
    sos = _segment(0xDA, b"\x01\x01\x00\x00\x3f\x00")
    return (
        b"\xff\xd8" + sof + dht + sos + b"\x00\xff\x00\x7f"
        + dht + sos + b"\x11\xff\xff\xd9"
    )


def _not_scanned(data: bytes) -> dict:
    called = []
    original = reader_module.run_bounded

    def wrap(target, args, timeout):
        called.append(1)
        return original(target, args, timeout)

    reader_module.run_bounded = wrap
    try:
        result = read_image_provenance(data)
    finally:
        reader_module.run_bounded = original
    assert called == []
    assert result["status"] == "not_performed"
    assert result["checks"] is None
    assert result["actions"] == []
    return result


def _probe_refused_address_limit(data: bytes):
    import resource

    calls = []
    original = reader_module.Reader.try_create

    def spy(stream, context=None):
        calls.append(1)
        return original(stream, context=context)

    def refuse(*_args, **_kwargs):
        raise OSError("refused")

    reader_module.Reader.try_create = spy
    resource.setrlimit = refuse
    try:
        result = reader_module._read_in_child(data, "", "", dict(reader_module.VERIFICATION_SETTINGS))
    finally:
        reader_module.Reader.try_create = original
    return result["status"], result.get("failureCode"), calls


def _probe_unavailable_address_limit(data: bytes):
    import builtins
    import sys

    calls = []
    original = reader_module.Reader.try_create
    real_import = builtins.__import__

    def spy(stream, context=None):
        calls.append(1)
        return original(stream, context=context)

    def guarded(name, *args, **kwargs):
        if name == "resource":
            raise ImportError("unavailable")
        return real_import(name, *args, **kwargs)

    reader_module.Reader.try_create = spy
    sys.modules.pop("resource", None)
    builtins.__import__ = guarded
    try:
        result = reader_module._read_in_child(data, "", "", dict(reader_module.VERIFICATION_SETTINGS))
    finally:
        builtins.__import__ = real_import
        reader_module.Reader.try_create = original
    return result["status"], result.get("failureCode"), calls


def test_restart_interval_jpeg_is_scanned_and_app11_is_counted():
    small = _app11(b"JP" + b"A" * 32)
    camera = _camera_jpeg(before=(small,), after=(small,))
    assert _manifest_exceeds_limit(camera) is False
    assert read_image_provenance(camera)["status"] == "no_credentials"
    oversized = _camera_jpeg(after=(_app11(b"B" * 65533),) * 17)
    assert _manifest_exceeds_limit(oversized) is True
    _blocked(oversized)
    before = _camera_jpeg(before=(_app11(b"C" * 65533),) * 17)
    assert _manifest_exceeds_limit(before) is True
    _blocked(before)


def test_progressive_jpeg_with_multiple_scans_is_not_rejected():
    image = _progressive_jpeg()
    assert _manifest_exceeds_limit(image) is False
    assert read_image_provenance(image)["status"] == "no_credentials"


def test_weakening_and_ambiguous_codes_are_not_trusted():
    exclusions = _map_store(_store(
        _PASSING,
        informational=(
            "signingCredential.ocsp.skipped",
            "assertion.dataHash.additionalExclusionsPresent",
        ),
    ))
    assert exclusions["status"] == "credentials_malformed"
    assert exclusions["status"] != "credentials_trusted"
    assert exclusions["checks"]["assetBinding"] == "not_checked"
    for code in (
        "assertion.bmffHash.additionalExclusionsPresent",
        "assertion.boxesHash.additionalExclusionsPresent",
        "manifest.unknownProvenance",
        "ingredient.unknownProvenance",
        "algorithm.deprecated",
        "future.assurance.code",
    ):
        mapped = _map_store(_store(
            _PASSING,
            informational=("signingCredential.ocsp.skipped", code),
        ))
        assert mapped["status"] != "credentials_trusted", code
        assert mapped["status"] == "credentials_malformed", code
    invalid_credential = _map_store(_store(_PASSING, ("signingCredential.invalid",)))
    assert invalid_credential["status"] == "credentials_invalid"
    collection = _map_store(_store(_PASSING, ("assertion.collectionHash.mismatch",)))
    assert collection["status"] == "credentials_invalid"
    assert collection["checks"]["assetBinding"] == "mismatch"
    supportive = _map_store(_store(
        _PASSING,
        informational=(
            "signingCredential.ocsp.skipped",
            "timeOfSigning.insideValidity",
            "cawg.ica.untrusted_issuer",
        ),
    ))
    assert supportive["status"] == "credentials_malformed"
    assert supportive["status"] != "credentials_trusted"
    assert supportive["checks"]["revocation"] == "skipped"
    assert supportive["checks"]["timestamp"] == "absent"
    proven = _map_store(_store(
        _PASSING + ("signingCredential.ocsp.notRevoked",),
        informational=("timeOfSigning.insideValidity", "cawg.ica.untrusted_issuer"),
    ))
    assert proven["status"] == "credentials_trusted"
    assert proven["checks"]["revocation"] == "not_revoked"
    assert proven["checks"]["timestamp"] == "absent"
    foreign_skip = _store(_PASSING, informational=("signingCredential.ocsp.skipped",))
    foreign_skip["validation_results"]["activeManifest"]["informational"][0]["url"] = (
        "self#jumbf=/c2pa/urn:c2pa:other/c2pa.signature"
    )
    skipped = _map_store(foreign_skip)
    assert skipped["status"] != "credentials_trusted"
    assert skipped["checks"]["revocation"] == "not_checked"


def test_gif_and_tiff_do_not_call_the_reader():
    gif = (
        b"GIF89a"
        + b"\x01\x00\x01\x00\x80\x00\x00\xff\x00\x00\x00\x00\x00"
        + b"!\xf9\x04\x00\x00\x00\x00\x00"
        + b",\x00\x00\x00\x00\x01\x00\x01\x00\x00"
        + b"\x02\x02D\x01\x00;"
    )
    assert detect_image(gif) == "image/gif"
    _not_scanned(gif)
    _not_scanned(b"II*\x00" + b"\x00" * 32)
    _not_scanned(b"MM\x00*" + b"\x00" * 32)
    assert detect_image(b"II*\x00" + b"\x00" * 32) is None


def test_only_jpeg_png_and_webp_reach_the_reader():
    webp = _webp_with([(b"VP8 ", b"\x00")])
    for blob in (_jpeg(), _png(), webp):
        called = []
        original = reader_module.run_bounded

        def wrap(target, args, timeout, _called=called):
            _called.append(1)
            return original(target, args, timeout)

        reader_module.run_bounded = wrap
        try:
            result = read_image_provenance(blob)
        finally:
            reader_module.run_bounded = original
        assert called == [1]
        assert result["status"] == "no_credentials"

    def box(tag, payload):
        return struct.pack(">I", 8 + len(payload)) + tag + payload

    unsupported = (
        b"GIF87a" + b"\x01\x00\x01\x00\x00\x00\x00;",
        b"GIF89a" + b"\x00" * 16,
        b"II*\x00" + b"\x00" * 32,
        b"MM\x00*" + b"\x00" * 32,
        b"%PDF-1.7\n",
        box(b"ftyp", b"heic\x00\x00\x00\x00heic"),
        b"\x00\x00\x00\x0cJXL \x0d\x0a\x87\x0a",
        b"<svg xmlns='http://www.w3.org/2000/svg'/>",
        b"BM" + b"\x00" * 32,
        b"RIFF" + struct.pack("<I", 12) + b"WAVEfmt ",
        b"PK\x03\x04" + b"\x00" * 16,
        b"this is not an image",
        b"\x00\x01\x02\x03unknown",
    )
    for blob in unsupported:
        _not_scanned(blob)


def test_malformed_validation_entries_cannot_be_trusted():
    active = "self#jumbf=/c2pa/urn:c2pa:active/c2pa.signature"
    entries = (
        {"url": active},
        {"code": ""},
        {"code": None},
        {"code": 12},
        "not-an-object",
        None,
    )
    for entry in entries:
        for name in ("success", "informational", "failure"):
            payload = _store(_PASSING)
            payload["validation_results"]["activeManifest"][name].append(entry)
            mapped = _map_store(payload)
            assert mapped["status"] != "credentials_trusted"
            assert mapped["status"] == "credentials_malformed"
            assert mapped["checks"]["signature"] == "valid"
    unlabeled = _store(())
    unlabeled["validation_results"]["activeManifest"]["success"] = [{"code": ""}]
    mapped = _map_store(unlabeled)
    assert mapped["status"] != "credentials_trusted"
    assert mapped["checks"]["signature"] == "not_checked"
    not_a_list = _store(_PASSING)
    not_a_list["validation_results"]["activeManifest"]["failure"] = {"code": "general.error"}
    mapped = _map_store(not_a_list)
    assert mapped["status"] == "credentials_malformed"
    assert mapped["status"] != "credentials_trusted"


def _assert_technical(result, code):
    assert result["status"] == "verification_failed"
    assert result["failureCode"] == code
    assert result["failureCode"] in TECHNICAL_FAILURE_CODES
    assert result["checks"] is None
    assert result["manifests"] == []
    assert result["actions"] == []
    assert result["actionsWithheld"] is True
    assert result["status"] not in {
        "credentials_malformed",
        "credentials_invalid",
        "credentials_untrusted",
        "credentials_trusted",
        "no_credentials",
        "not_performed",
    }
    assert result["status"] not in VALID_ASSESSMENTS
    assert result["failureCode"] not in VALID_ASSESSMENTS
    assert "POTENTIAL_MANIPULATION" not in {result["status"], result["failureCode"]}


def test_reader_does_not_start_without_an_address_limit():
    image = _jpeg()
    kind, refused = run_bounded(_probe_refused_address_limit, (image,), 2)
    assert kind == "ok"
    assert refused[0] == "verification_failed"
    assert refused[1] == "memory_limit"
    assert refused[0] != "credentials_malformed"
    assert refused[0] != "credentials_trusted"
    assert refused[2] == []
    kind, unavailable = run_bounded(_probe_unavailable_address_limit, (image,), 2)
    assert kind == "ok"
    assert unavailable[0] == "verification_failed"
    assert unavailable[1] == "memory_limit"
    assert unavailable[0] != "credentials_malformed"
    assert unavailable[0] != "credentials_trusted"
    assert unavailable[2] == []


def _bundle(*certificates) -> str:
    return "\n".join(_pem(certificate) for certificate in certificates)


def _read_anchored(data, pem, timestamp_pem=None):
    """Supply one validated bundle to each purpose.

    Existing manifest fixtures have no timestamp token. Passing the same
    certificate text as the timestamp bundle is an explicit caller choice.
    The adapter does not copy it.
    """
    if timestamp_pem is None:
        timestamp_pem = pem
    return read_image_provenance(
        data,
        manifest_trust_pem=pem,
        timestamp_trust_pem=timestamp_pem,
    )


def _entries(result) -> dict:
    return {item["label"]: item for item in result["manifests"]}


def _assert_private(result) -> None:
    rendered = str(result)
    _secrets_absent(rendered)
    assert "signature_info" not in rendered
    assert "crjson" not in rendered
    assert "validation_state" not in result
    assert result["actions"] == []
    assert result["actionsWithheld"] is True


def test_create_replaces_an_earlier_manifest():
    key, certificate = _certificate(SIGNER_NAME)
    trust = _pem(certificate)
    first = _sign_jpeg(_jpeg(), key, certificate)
    first_label = _read_anchored(first, trust)["manifests"][0]["label"]
    replaced = _sign_jpeg(first, key, certificate)
    result = _read_anchored(replaced, trust)
    assert result["status"] == "credentials_malformed"
    assert result["status"] != "credentials_trusted"
    assert result["checks"]["certificateTrust"] == "trusted"
    assert result["checks"]["revocation"] == "skipped"
    assert len(result["manifests"]) == 1
    assert result["manifests"][0]["label"] != first_label
    assert result["checks"] == result["manifests"][0]["checks"]
    _assert_private(result)


def test_two_and_three_manifest_chains_aggregate_by_worst_status():
    key_a, cert_a = _certificate(SIGNER_NAME)
    key_b, cert_b = _certificate(SIGNER_NAME + "-b")
    trust_a = _pem(cert_a)
    trust_b = _pem(cert_b)
    both = _bundle(cert_a, cert_b)
    first = _sign_jpeg(_jpeg(), key_a, cert_a)
    parent_label = _read_anchored(first, trust_a)["manifests"][0]["label"]
    second = _sign_over(first, key_b, cert_b, first, relationship="parentOf", intent="edit")
    anchored = _read_anchored(second, both)
    assert anchored["status"] == "credentials_malformed"
    assert anchored["status"] != "credentials_trusted"
    assert anchored["checks"] is None
    assert len(anchored["manifests"]) == 2
    assert anchored["manifests"][0]["role"] == "active"
    assert anchored["manifests"][0]["checks"]["certificateTrust"] == "trusted"
    assert anchored["manifests"][0]["checks"]["revocation"] == "skipped"
    assert anchored["manifests"][0]["status"] == "credentials_malformed"
    assert _entries(anchored)[parent_label]["role"] == "ingredient"
    assert _entries(anchored)[parent_label]["checks"]["certificateTrust"] == "trusted"
    assert _entries(anchored)[parent_label]["status"] == "credentials_malformed"
    _assert_private(anchored)

    parent_only = _read_anchored(second, trust_a)
    assert parent_only["status"] == "credentials_malformed"
    assert parent_only["manifests"][0]["status"] == "credentials_untrusted"
    assert parent_only["manifests"][0]["checks"]["certificateTrust"] == "untrusted"
    assert _entries(parent_only)[parent_label]["checks"]["certificateTrust"] == "trusted"
    assert _entries(parent_only)[parent_label]["status"] == "credentials_malformed"
    assert _entries(parent_only)[parent_label]["status"] != "credentials_trusted"

    active_only = _read_anchored(second, trust_b)
    assert active_only["status"] == "credentials_malformed"
    assert active_only["manifests"][0]["checks"]["certificateTrust"] == "trusted"
    assert active_only["manifests"][0]["status"] == "credentials_malformed"
    assert _entries(active_only)[parent_label]["status"] == "credentials_untrusted"
    assert _entries(active_only)[parent_label]["checks"]["certificateTrust"] == "untrusted"

    third = _sign_over(second, key_a, cert_a, second, relationship="parentOf", intent="edit")
    chain = _read_anchored(third, both)
    assert chain["status"] == "credentials_malformed"
    assert chain["status"] != "credentials_trusted"
    assert chain["checks"] is None
    assert len(chain["manifests"]) == 3
    assert {item["role"] for item in chain["manifests"]} == {"active", "ingredient"}
    assert {item["checks"]["certificateTrust"] for item in chain["manifests"]} == {"trusted"}
    assert {item["checks"]["revocation"] for item in chain["manifests"]} == {"skipped"}
    _assert_private(chain)
    outer_only = _read_anchored(third, trust_a)
    assert outer_only["status"] == "credentials_malformed"
    assert outer_only["manifests"][0]["checks"]["certificateTrust"] == "trusted"
    assert outer_only["manifests"][0]["status"] == "credentials_malformed"
    assert any(item["checks"]["certificateTrust"] == "untrusted" for item in outer_only["manifests"])

    updated = _sign_over(first, key_b, cert_b, first, relationship="parentOf", intent="update")
    update_result = _read_anchored(updated, both)
    assert update_result["status"] == "credentials_malformed"
    assert update_result["manifests"][0]["checks"]["assetBinding"] == "not_checked"
    assert update_result["manifests"][0]["status"] != "credentials_trusted"


def test_tampered_parent_stays_invalid_when_the_library_says_trusted():
    key_a, cert_a = _certificate(SIGNER_NAME)
    key_b, cert_b = _certificate(SIGNER_NAME + "-b")
    both = _bundle(cert_a, cert_b)
    first = _sign_jpeg(_jpeg(), key_a, cert_a)
    parent_label = _read_anchored(first, _pem(cert_a))["manifests"][0]["label"]
    broken = bytearray(first)
    broken[broken.find(b"\xff\xc0") + 5] ^= 0x01
    resigned = _sign_over(bytes(broken), key_b, cert_b, bytes(broken), relationship="parentOf", intent="edit")
    result = _read_anchored(resigned, both)
    assert _library_state(resigned, both) == "Trusted"
    assert result["status"] == "credentials_malformed"
    assert result["status"] != "credentials_trusted"
    assert result["checks"] is None
    parent = _entries(result)[parent_label]
    assert parent["status"] == "credentials_invalid"
    assert parent["checks"]["assetBinding"] == "mismatch"
    assert result["manifests"][0]["status"] == "credentials_malformed"
    assert result["manifests"][0]["checks"]["revocation"] == "skipped"
    assert result["manifests"][0]["checks"]["certificateTrust"] == "trusted"
    _assert_private(result)

    outer = bytearray(resigned)
    outer[outer.rfind(b"\xff\xc0") + 5] ^= 0x01
    tampered_outer = _read_anchored(bytes(outer), both)
    assert tampered_outer["status"] == "credentials_invalid"
    assert tampered_outer["manifests"][0]["checks"]["assetBinding"] == "mismatch"


def test_component_of_ingredient_is_validated_with_the_active_manifest():
    key_a, cert_a = _certificate(SIGNER_NAME)
    key_b, cert_b = _certificate(SIGNER_NAME + "-b")
    both = _bundle(cert_a, cert_b)
    first = _sign_jpeg(_jpeg(), key_a, cert_a)
    parent_label = _read_anchored(first, _pem(cert_a))["manifests"][0]["label"]
    combined = _sign_over(first, key_b, cert_b, first, relationship="componentOf", intent="edit")
    result = _read_anchored(combined, both)
    assert result["status"] == "credentials_malformed"
    assert result["status"] != "credentials_trusted"
    assert parent_label in _entries(result)
    assert _entries(result)[parent_label]["role"] == "ingredient"
    assert _entries(result)[parent_label]["checks"]["certificateTrust"] == "trusted"
    assert _entries(result)[parent_label]["checks"]["revocation"] == "skipped"
    assert _entries(result)[parent_label]["status"] == "credentials_malformed"
    _assert_private(result)


def test_forged_snapshot_cannot_hide_a_fresh_hard_failure():
    active = "urn:c2pa:active"
    parent = "urn:c2pa:parent"
    snapshot = [
        _code("claimSignature.validated", parent),
        _code("claimSignature.insideValidity", parent),
        _code("signingCredential.ocsp.skipped", parent),
    ]
    payload = {
        "active_manifest": active,
        "manifests": {
            active: {
                "ingredients": [{
                    "relationship": "parentOf",
                    "active_manifest": parent,
                    "validation_results": {
                        "activeManifest": {
                            "success": snapshot[:2],
                            "informational": snapshot[2:],
                            "failure": [_code("signingCredential.untrusted", parent)],
                        }
                    },
                }]
            },
            parent: {},
        },
        "validation_results": {
            "activeManifest": {
                "success": _proven_items(active),
                "informational": [],
                "failure": [],
            },
            "ingredientDeltas": [{
                "ingredientAssertionURI": "self#jumbf=/c2pa/" + active + "/c2pa.assertions/c2pa.ingredient.v3",
                "validationDeltas": {
                    "success": [_code("signingCredential.trusted", parent)],
                    "informational": [],
                    "failure": [_code("assertion.dataHash.mismatch", parent)],
                },
            }],
        },
    }
    mapped = _map_store(payload)
    assert mapped["status"] == "credentials_invalid"
    assert _entries(mapped)[parent]["checks"]["assetBinding"] == "mismatch"
    assert _entries(mapped)[active]["status"] == "credentials_trusted"
    disagreement = _map_store({
        "active_manifest": active,
        "manifests": {
            active: {
                "ingredients": [{
                    "relationship": "parentOf",
                    "active_manifest": parent,
                    "validation_results": {
                        "activeManifest": {
                            "success": _passing_items(parent),
                            "informational": [_code("signingCredential.ocsp.skipped", parent)],
                            "failure": [_code("signingCredential.untrusted", parent)],
                        }
                    },
                }]
            },
            parent: {},
        },
        "validation_results": {
            "activeManifest": {
                "success": _passing_items(active),
                "informational": [_code("signingCredential.ocsp.skipped", active)],
                "failure": [],
            },
            "ingredientDeltas": [{
                "ingredientAssertionURI": "self#jumbf=/c2pa/" + active + "/c2pa.assertions/c2pa.ingredient.v3",
                "validationDeltas": {
                    "success": [_code("assertion.dataHash.match", parent)],
                    "failure": [_code("assertion.dataHash.mismatch", parent)],
                },
            }],
        },
    })
    assert disagreement["status"] == "credentials_malformed"
    assert _entries(disagreement)[parent]["status"] == "credentials_malformed"
    assert _entries(disagreement)[parent]["checks"]["assetBinding"] == "not_checked"


def test_missing_unreferenced_and_unassociated_manifests_fail_closed():
    active = "urn:c2pa:active"
    missing = {
        "active_manifest": active,
        "manifests": {
            active: {"ingredients": [{"relationship": "parentOf", "active_manifest": "urn:c2pa:missing"}]}
        },
        "validation_results": {
            "activeManifest": {
                "success": _proven_items(active),
                "informational": [],
                "failure": [],
            }
        },
    }
    mapped = _map_store(missing)
    assert mapped["status"] == "credentials_malformed"
    assert mapped["checks"] is None
    assert _entries(mapped)["urn:c2pa:missing"]["status"] == "credentials_malformed"
    assert _entries(mapped)["urn:c2pa:missing"]["role"] == "ingredient"
    assert _entries(mapped)[active]["status"] == "credentials_trusted"
    assert _entries(mapped)[active]["status"] != mapped["status"]

    extra = "urn:c2pa:extra"
    unreferenced = _map_store({
        "active_manifest": active,
        "manifests": {active: {}, extra: {}},
        "validation_results": {
            "activeManifest": {
                "success": _passing_items(active),
                "informational": [_code("signingCredential.ocsp.skipped", active)],
                "failure": [],
            }
        },
    })
    assert unreferenced["status"] == "credentials_malformed"
    assert _entries(unreferenced)[extra]["role"] == "unreferenced"
    assert _entries(unreferenced)[extra]["status"] == "credentials_malformed"

    unassociated = _map_store({
        "active_manifest": active,
        "manifests": {active: {}, "urn:c2pa:other": {}},
        "validation_results": {
            "activeManifest": {
                "success": _passing_items(active),
                "informational": [_code("signingCredential.ocsp.skipped", active)],
                "failure": [],
            },
            "ingredientDeltas": [{
                "ingredientAssertionURI": "self#jumbf=/c2pa/" + active + "/c2pa.assertions/c2pa.ingredient.v3",
                "validationDeltas": {
                    "failure": [_code("assertion.dataHash.mismatch", "urn:c2pa:unknown")],
                },
            }],
        },
    })
    single_delta = _store(_PASSING)
    single_delta["validation_results"]["ingredientDeltas"] = [{
        "validationDeltas": {"failure": [_code("assertion.dataHash.mismatch", "urn:c2pa:active")]},
    }]
    kept = _map_store(single_delta)
    assert kept["status"] == "credentials_malformed"
    assert len(kept["manifests"]) == 1
    assert kept["checks"]["signature"] == "not_checked"
    assert unassociated["status"] == "credentials_malformed"
    assert unassociated["manifests"] == []
    assert unassociated["checks"]["signature"] == "not_checked"
    two_labels = _map_store({
        "active_manifest": active,
        "manifests": {active: {}, "urn:c2pa:other": {}},
        "validation_results": {
            "activeManifest": {
                "success": _passing_items(active),
                "informational": [_code("signingCredential.ocsp.skipped", active)],
                "failure": [],
            },
            "ingredientDeltas": [{
                "ingredientAssertionURI": "self#jumbf=/c2pa/" + active + "/c2pa.assertions/c2pa.ingredient.v3",
                "validationDeltas": {
                    "success": [_code("signingCredential.trusted", "urn:c2pa:other")],
                    "failure": [_code("assertion.dataHash.mismatch", active)],
                },
            }],
        },
    })
    assert two_labels["status"] == "credentials_malformed"
    assert two_labels["manifests"] == []


def test_duplicate_manifest_keys_and_the_count_limit_return_no_partial_list():
    raw = (
        '{"active_manifest":"urn:c2pa:dup","manifests":'
        '{"urn:c2pa:dup":{},"urn:c2pa:dup":{"label":"second"}},'
        '"validation_results":{"activeManifest":{"success":[],"informational":[],"failure":[]}}}'
    )
    duplicate = _result_from_store_json(raw)
    assert duplicate["status"] == "credentials_malformed"
    assert duplicate["manifests"] == []
    assert duplicate["checks"]["signature"] == "not_checked"
    collapsed = json.loads(raw)
    assert len(collapsed["manifests"]) == 1

    labels = {"urn:c2pa:m" + str(index).zfill(2): {} for index in range(17)}
    overflow = _map_store({
        "active_manifest": "urn:c2pa:m00",
        "manifests": labels,
        "validation_results": {
            "activeManifest": {
                "success": _passing_items("urn:c2pa:m00"),
                "informational": [_code("signingCredential.ocsp.skipped", "urn:c2pa:m00")],
                "failure": [],
            }
        },
    })
    assert overflow["status"] == "credentials_malformed"
    assert overflow["manifests"] == []
    assert overflow["status"] != "credentials_trusted"
    assert overflow["checks"]["assetBinding"] == "not_checked"
    sixteen = {"urn:c2pa:m" + str(index).zfill(2): {} for index in range(16)}
    sixteen["urn:c2pa:m00"] = {
        "ingredients": [{"relationship": "parentOf", "active_manifest": "urn:c2pa:missing"}]
    }
    over_reference = _map_store({
        "active_manifest": "urn:c2pa:m00",
        "manifests": sixteen,
        "validation_results": {
            "activeManifest": {
                "success": _passing_items("urn:c2pa:m00"),
                "informational": [_code("signingCredential.ocsp.skipped", "urn:c2pa:m00")],
                "failure": [],
            }
        },
    })
    assert over_reference["status"] == "credentials_malformed"
    assert over_reference["manifests"] == []


def _wait_past(moment: datetime.datetime) -> None:
    remaining = (moment - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
    if remaining > 0:
        time.sleep(remaining + 1.5)


def test_certificate_valid_at_signing_can_be_expired_when_read():
    now = datetime.datetime.now(datetime.timezone.utc)
    deadline = now + datetime.timedelta(seconds=8)
    key, certificate = _certificate(
        SIGNER_NAME,
        not_before=now - datetime.timedelta(hours=1),
        not_after=deadline,
    )
    signed = _sign_jpeg(_jpeg(), key, certificate)
    trust = _pem(certificate)
    fresh = _read_anchored(signed, trust)
    assert fresh["checks"]["certificateValidity"] == "inside_at_asserted_time"
    assert fresh["checks"]["signature"] == "valid"
    assert fresh["checks"]["timestamp"] == "absent"
    assert fresh["status"] == "credentials_malformed"
    assert fresh["status"] != "credentials_trusted"
    _wait_past(deadline)
    later = _read_anchored(signed, trust)
    assert later["checks"]["certificateValidity"] == "expired"
    assert later["checks"]["signature"] == "not_checked"
    assert later["checks"]["certificateTrust"] == "untrusted"
    assert later["checks"]["timestamp"] == "absent"
    assert later["checks"]["revocation"] == "skipped"
    assert later["status"] == "credentials_invalid"
    assert later["manifests"][0]["checks"]["certificateValidity"] == "expired"
    _secrets_absent(str(later))


def test_signer_rejects_a_certificate_already_outside_its_window():
    now = datetime.datetime.now(datetime.timezone.utc)
    end = now - datetime.timedelta(minutes=5)
    key, certificate = _certificate(
        SIGNER_NAME,
        not_before=end - datetime.timedelta(days=2),
        not_after=end,
    )
    with pytest.raises(Exception) as caught:
        _sign_jpeg(_jpeg(), key, certificate)
    message = str(caught.value).lower()
    assert "certificate" in message
    assert "valid" in message


def test_expired_issuing_ca_is_outside_validity_not_leaf_expiry():
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_end = now + datetime.timedelta(seconds=8)
    ca_key, ca_certificate = _certificate(
        "issuer-ca",
        ca=True,
        not_before=now - datetime.timedelta(days=2),
        not_after=ca_end,
    )
    ee_key, ee_certificate = _certificate(
        SIGNER_NAME,
        not_before=now - datetime.timedelta(hours=1),
        not_after=now + datetime.timedelta(days=20),
        issuer_name=ca_certificate.subject,
        issuer_key=ca_key,
    )
    signed = _sign_jpeg(_jpeg(), ee_key, ee_certificate, extra_certificates=(ca_certificate,))
    fresh = _read_anchored(signed, _pem(ca_certificate))
    assert fresh["checks"]["certificateTrust"] == "trusted"
    assert fresh["checks"]["certificateValidity"] == "inside_at_asserted_time"
    assert fresh["status"] == "credentials_malformed"
    _wait_past(ca_end)
    later = _read_anchored(signed, _pem(ca_certificate))
    assert later["checks"]["certificateValidity"] == "outside"
    assert later["checks"]["certificateValidity"] != "expired"
    assert later["status"] == "credentials_invalid"
    assert later["checks"]["timestamp"] == "absent"
    _secrets_absent(str(later))


def test_manifests_keep_different_certificate_validity_states():
    now = datetime.datetime.now(datetime.timezone.utc)
    short_end = now + datetime.timedelta(seconds=8)
    short_key, short_certificate = _certificate(
        SIGNER_NAME,
        not_before=now - datetime.timedelta(hours=1),
        not_after=short_end,
    )
    long_key, long_certificate = _certificate(
        SIGNER_NAME + "-b",
        not_before=now - datetime.timedelta(hours=1),
        not_after=now + datetime.timedelta(days=20),
    )
    first = _sign_jpeg(_jpeg(), short_key, short_certificate)
    parent_label = _read_anchored(
        first, _pem(short_certificate)
    )["manifests"][0]["label"]
    _wait_past(short_end)
    second = _sign_over(
        first, long_key, long_certificate, first, relationship="parentOf", intent="edit"
    )
    trust = _bundle(short_certificate, long_certificate)
    result = _read_anchored(second, trust)
    parent = _entries(result)[parent_label]
    active = result["manifests"][0]
    assert _library_state(second, trust) == "Trusted"
    assert parent["checks"]["certificateValidity"] == "expired"
    assert parent["checks"]["signature"] == "not_checked"
    assert parent["status"] == "credentials_invalid"
    assert active["label"] != parent_label
    assert active["checks"]["certificateValidity"] == "inside_at_asserted_time"
    assert active["checks"]["revocation"] == "skipped"
    assert active["status"] == "credentials_malformed"
    assert result["checks"] is None
    assert result["status"] == "credentials_malformed"
    assert result["status"] != "credentials_trusted"
    _assert_private(result)


def test_validity_timestamp_and_revocation_codes_follow_the_approved_matrix():
    expired = _map_store(_store(
        _PASSING + ("signingCredential.ocsp.notRevoked",),
        ("signingCredential.expired",),
    ))
    assert expired["checks"]["certificateValidity"] == "expired"
    assert expired["checks"]["signature"] == "valid"
    assert expired["status"] == "credentials_invalid"
    both_windows = _map_store(_store(
        _PASSING,
        ("signingCredential.expired", "claimSignature.outsideValidity"),
    ))
    assert both_windows["checks"]["certificateValidity"] == "expired"
    outside = _map_store(_store(_PASSING, ("claimSignature.outsideValidity",)))
    assert outside["checks"]["certificateValidity"] == "outside"
    assert outside["status"] == "credentials_invalid"
    missing_window = _map_store(_store(
        ("claimSignature.validated", "assertion.dataHash.match", "signingCredential.trusted", "signingCredential.ocsp.notRevoked"),
    ))
    assert missing_window["checks"]["certificateValidity"] == "not_checked"
    assert missing_window["status"] == "credentials_malformed"

    trusted_time = _map_store(_store(
        _PASSING + ("signingCredential.ocsp.notRevoked", "timeStamp.trusted", "timeStamp.validated"),
    ))
    assert trusted_time["checks"]["timestamp"] == "trusted"
    assert trusted_time["status"] == "credentials_trusted"
    for lone in ("timeStamp.trusted", "timeStamp.validated"):
        partial = _map_store(_store(_PASSING + ("signingCredential.ocsp.notRevoked", lone)))
        assert partial["checks"]["timestamp"] == "not_checked"
        assert partial["status"] == "credentials_malformed"
    absent = _map_store(_store(
        _PASSING + ("signingCredential.ocsp.notRevoked",),
        informational=("timeOfSigning.insideValidity",),
    ))
    assert absent["checks"]["timestamp"] == "absent"
    assert absent["status"] == "credentials_trusted"
    for code, expected in (
        ("timeStamp.untrusted", "untrusted"),
        ("timeStamp.malformed", "malformed"),
        ("timeStamp.mismatch", "malformed"),
        ("timeStamp.outsideValidity", "outside_validity"),
        ("assertion.timestamp.malformed", "malformed"),
    ):
        mapped = _map_store(_store(
            _PASSING + ("signingCredential.ocsp.notRevoked", "timeStamp.trusted", "timeStamp.validated"),
            (code,),
        ))
        assert mapped["checks"]["timestamp"] == expected
        assert mapped["status"] == "credentials_invalid"
    foreign = _store(
        _PASSING + ("signingCredential.ocsp.notRevoked",),
        ("assertion.timestamp.malformed",),
        failure_url="self#jumbf=/c2pa/urn:c2pa:other/c2pa.signature",
    )
    foreign_mapped = _map_store(foreign)
    assert foreign_mapped["checks"]["timestamp"] == "malformed"
    assert foreign_mapped["status"] == "credentials_invalid"

    for code, expected in (
        ("signingCredential.ocsp.revoked", "revoked"),
        ("signingCredential.ocsp.unknown", "unknown"),
        ("signingCredential.ocsp.inaccessible", "inaccessible"),
    ):
        for placement in ("failure", "informational", "success"):
            if placement == "failure":
                mapped = _map_store(_store(_PASSING + ("signingCredential.ocsp.notRevoked",), (code,)))
            elif placement == "informational":
                mapped = _map_store(_store(
                    _PASSING + ("signingCredential.ocsp.notRevoked",),
                    informational=(code,),
                ))
            else:
                mapped = _map_store(_store(_PASSING + ("signingCredential.ocsp.notRevoked", code)))
            assert mapped["checks"]["revocation"] == expected
            assert mapped["status"] == "credentials_invalid"
    skipped = _map_store(_store(_PASSING, informational=("signingCredential.ocsp.skipped",)))
    assert skipped["checks"]["revocation"] == "skipped"
    assert skipped["checks"]["certificateTrust"] == "trusted"
    assert skipped["status"] == "credentials_malformed"
    unanchored = _map_store(_store(
        ("claimSignature.validated", "claimSignature.insideValidity", "assertion.dataHash.match"),
        ("signingCredential.untrusted",),
        informational=("signingCredential.ocsp.skipped",),
    ))
    assert unanchored["checks"]["revocation"] == "skipped"
    assert unanchored["checks"]["certificateTrust"] == "untrusted"
    assert unanchored["status"] == "credentials_untrusted"
    unchecked = _map_store(_store(
        _PASSING + ("signingCredential.ocsp.notRevoked",),
        informational=(),
    ))
    # notRevoked is in success above; a store with no OCSP code is separate.
    no_ocsp = _map_store(_store(_PASSING, informational=()))
    assert no_ocsp["checks"]["revocation"] == "not_checked"
    assert no_ocsp["status"] == "credentials_malformed"
    assert unchecked["checks"]["revocation"] == "not_revoked"
    informational_only = _map_store(_store(
        _PASSING,
        informational=("signingCredential.ocsp.notRevoked",),
    ))
    assert informational_only["checks"]["revocation"] == "not_checked"
    assert informational_only["status"] == "credentials_malformed"


def test_fresh_trust_does_not_clear_expiration_or_revocation():
    active = "urn:c2pa:active"
    parent = "urn:c2pa:parent"

    def payload(parent_failure):
        return {
            "active_manifest": active,
            "manifests": {
                active: {
                    "ingredients": [{
                        "relationship": "parentOf",
                        "active_manifest": parent,
                        "validation_results": {
                            "activeManifest": {
                                "success": [
                                    _code("claimSignature.validated", parent),
                                    _code("claimSignature.insideValidity", parent),
                                ],
                                "informational": [],
                                "failure": [
                                    _code("signingCredential.untrusted", parent),
                                    _code(parent_failure, parent),
                                ],
                            }
                        },
                    }]
                },
                parent: {},
            },
            "validation_results": {
                "activeManifest": {
                    "success": _proven_items(active),
                    "informational": [],
                    "failure": [],
                },
                "ingredientDeltas": [{
                    "ingredientAssertionURI": "self#jumbf=/c2pa/" + active + "/c2pa.assertions/c2pa.ingredient.v3",
                    "validationDeltas": {
                        "success": [_code("signingCredential.trusted", parent)],
                        "informational": [],
                        "failure": [],
                    },
                }],
            },
        }

    expired = _map_store(payload("signingCredential.expired"))
    assert _entries(expired)[parent]["checks"]["certificateValidity"] == "expired"
    assert _entries(expired)[parent]["checks"]["certificateTrust"] == "trusted"
    assert _entries(expired)[parent]["status"] == "credentials_invalid"
    assert _entries(expired)[active]["status"] == "credentials_trusted"
    assert expired["status"] == "credentials_invalid"
    revoked = _map_store(payload("signingCredential.ocsp.revoked"))
    assert _entries(revoked)[parent]["checks"]["revocation"] == "revoked"
    assert _entries(revoked)[parent]["checks"]["certificateTrust"] == "trusted"
    assert _entries(revoked)[parent]["status"] == "credentials_invalid"
    assert revoked["status"] == "credentials_invalid"
    assert revoked["status"] != "credentials_trusted"


class _TimestampResponder(BaseHTTPRequestHandler):
    directory: Path | None = None
    hits: list | None = None

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        phase = "read" if self.server.reading else "sign"
        self.hits.append(phase)
        query = self.directory / "query.tsq"
        reply = self.directory / "reply.tsr"
        query.write_bytes(body)
        completed = subprocess.run(
            [
                "openssl", "ts", "-reply",
                "-config", str(self.directory / "openssl.cnf"),
                "-queryfile", str(query),
                "-out", str(reply),
            ],
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            self.server.reply_error = completed.stderr
            self.send_response(500)
            self.end_headers()
            return
        payload = reply.read_bytes()
        self.server.last_reply = payload
        self.send_response(200)
        self.send_header("Content-Type", "application/timestamp-reply")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        return


def _local_timestamp_authority(directory: Path) -> tuple[ThreadingHTTPServer, str]:
    ca_key = directory / "ca.key"
    ca_cert = directory / "ca.crt"
    key = directory / "tsa.key"
    cert = directory / "tsa.crt"
    subject = "/CN=" + SIGNER_NAME + "-tsa"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:P-256",
            "-keyout", str(ca_key), "-out", str(ca_cert),
            "-days", "2", "-nodes",
            "-subj", "/CN=" + SIGNER_NAME + "-tsa-ca",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl", "req", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:P-256",
            "-keyout", str(key), "-out", str(directory / "tsa.csr"),
            "-nodes", "-subj", subject,
            "-addext", "extendedKeyUsage=critical,timeStamping",
            "-addext", "keyUsage=critical,digitalSignature",
            "-addext", "basicConstraints=critical,CA:FALSE",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl", "x509", "-req",
            "-in", str(directory / "tsa.csr"),
            "-CA", str(ca_cert), "-CAkey", str(ca_key),
            "-CAcreateserial", "-out", str(cert),
            "-days", "2", "-copy_extensions", "copy",
        ],
        check=True,
        capture_output=True,
    )
    chain = directory / "chain.pem"
    chain.write_bytes(cert.read_bytes() + b"\n" + ca_cert.read_bytes())
    serial = directory / "tsa.srl"
    serial.write_text("01\n")
    (directory / "openssl.cnf").write_text(
        "\n".join([
            "[tsa]",
            "default_tsa = tsa_config",
            "[tsa_config]",
            "serial = " + str(serial),
            "crypto_device = builtin",
            "signer_cert = " + str(cert),
            "certs = " + str(chain),
            "signer_key = " + str(key),
            "signer_digest = sha256",
            "default_policy = 1.2.3.4.1",
            "digests = sha256",
            "accuracy = secs:1",
            "ordering = yes",
            "tsa_name = yes",
            "ess_cert_id_chain = no",
            "",
        ])
    )
    _TimestampResponder.directory = directory
    _TimestampResponder.hits = []
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = ThreadingHTTPServer(("127.0.0.1", port), _TimestampResponder)
    server.reading = False
    server.last_reply = b""
    server.reply_error = ""
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, "http://127.0.0.1:" + str(port) + "/tsa"


def test_local_rfc3161_timestamp_is_checked_without_a_network_read():
    with tempfile.TemporaryDirectory(prefix="c2pa-tsa-") as temporary:
        directory = Path(temporary)
        server, tsa_url = _local_timestamp_authority(directory)
        try:
            key, certificate = _certificate(SIGNER_NAME)
            signed = _sign_jpeg(_jpeg(), key, certificate, tsa_url=tsa_url)
            assert _TimestampResponder.hits == ["sign"]
            assert server.reply_error == ""
            assert server.last_reply.startswith(b"\x30")
            authority = (directory / "ca.crt").read_text()
            signer = _pem(certificate)
            server.reading = True
            trusted = read_image_provenance(
                signed,
                manifest_trust_pem=signer,
                timestamp_trust_pem=authority,
            )
            assert _TimestampResponder.hits == ["sign"]
            assert trusted["checks"]["timestamp"] == "trusted"
            assert trusted["checks"]["signature"] == "valid"
            assert trusted["checks"]["assetBinding"] == "bound"
            assert trusted["checks"]["certificateTrust"] == "trusted"
            assert trusted["checks"]["certificateValidity"] == "inside_at_asserted_time"
            assert trusted["checks"]["revocation"] == "skipped"
            assert trusted["status"] == "credentials_malformed"
            assert trusted["status"] != "credentials_trusted"
            _secrets_absent(str(trusted))

            untrusted = read_image_provenance(
                signed,
                manifest_trust_pem=signer,
                timestamp_trust_pem=signer,
            )
            assert _TimestampResponder.hits == ["sign"]
            assert untrusted["checks"]["timestamp"] == "untrusted"
            assert untrusted["checks"]["certificateTrust"] == "trusted"
            assert untrusted["status"] == "credentials_invalid"

            token_file = directory / "token.der"
            subprocess.run(
                [
                    "openssl", "ts", "-reply",
                    "-in", str(directory / "reply.tsr"),
                    "-token_out", "-out", str(token_file),
                ],
                check=True,
                capture_output=True,
            )
            token = token_file.read_bytes()
            start = signed.find(token)
            if start < 0:
                needle = token[40:56]
                assert signed.count(needle) == 1
                start = signed.find(needle)
            flipped = bytearray(signed)
            flipped[start + 8] ^= 0x01
            damaged = read_image_provenance(
                bytes(flipped),
                manifest_trust_pem=signer,
                timestamp_trust_pem=authority,
            )
            assert _TimestampResponder.hits == ["sign"]
            assert damaged["checks"]["timestamp"] == "malformed"
            assert damaged["checks"]["signature"] == "valid"
            assert damaged["status"] == "credentials_invalid"
            _secrets_absent(str(damaged))
        finally:
            server.shutdown()


def _unchecked_failure(result) -> None:
    _assert_technical(result, "trust_configuration")


def test_manifest_and_timestamp_bundles_stay_separate():
    with tempfile.TemporaryDirectory(prefix="c2pa-trust-split-") as temporary:
        directory = Path(temporary)
        server, tsa_url = _local_timestamp_authority(directory)
        try:
            key, certificate = _certificate(SIGNER_NAME)
            _other_key, other = _certificate("other-anchor", ca=True)
            signed = _sign_jpeg(_jpeg(), key, certificate, tsa_url=tsa_url)
            signer = _pem(certificate)
            authority = (directory / "ca.crt").read_text()
            other_pem = _pem(other)
            copies = 1
            oversized = signer.strip() + "\n"
            while len(oversized.encode("utf-8")) <= MAX_TRUST_ANCHOR_BYTES:
                copies += 1
                oversized = (signer.strip() + "\n") * copies
            private = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode()
            server.reading = True
            before = list(_TimestampResponder.hits)

            split = read_image_provenance(
                signed,
                manifest_trust_pem=signer,
                timestamp_trust_pem=authority,
            )
            assert split["checks"]["certificateTrust"] == "trusted"
            assert split["checks"]["timestamp"] == "trusted"
            assert split["checks"]["signature"] == "valid"
            assert split["status"] == "credentials_malformed"
            assert split["status"] != "credentials_trusted"

            manifest_only = read_image_provenance(
                signed,
                manifest_trust_pem=signer,
                timestamp_trust_pem=other_pem,
            )
            assert manifest_only["checks"]["certificateTrust"] == "trusted"
            assert manifest_only["checks"]["timestamp"] == "untrusted"
            assert manifest_only["status"] == "credentials_invalid"

            timestamp_only = read_image_provenance(
                signed,
                manifest_trust_pem=other_pem,
                timestamp_trust_pem=authority,
            )
            assert timestamp_only["checks"]["certificateTrust"] == "untrusted"
            assert timestamp_only["checks"]["timestamp"] == "trusted"
            assert timestamp_only["status"] == "credentials_untrusted"

            swapped = read_image_provenance(
                signed,
                manifest_trust_pem=authority,
                timestamp_trust_pem=signer,
            )
            assert swapped["checks"]["certificateTrust"] == "untrusted"
            assert swapped["checks"]["timestamp"] == "untrusted"
            assert swapped["status"] != "credentials_trusted"

            embedded = read_image_provenance(signed)
            assert embedded["checks"]["certificateTrust"] == "untrusted"
            assert embedded["checks"]["timestamp"] == "untrusted"

            for kwargs in (
                {"manifest_trust_pem": signer},
                {"timestamp_trust_pem": authority},
                {"manifest_trust_pem": "", "timestamp_trust_pem": authority},
                {"manifest_trust_pem": signer, "timestamp_trust_pem": ""},
                {"manifest_trust_pem": "not a certificate\n", "timestamp_trust_pem": authority},
                {"manifest_trust_pem": signer, "timestamp_trust_pem": signer[:80]},
                {"manifest_trust_pem": signer + private, "timestamp_trust_pem": authority},
                {"manifest_trust_pem": oversized, "timestamp_trust_pem": authority},
                {"manifest_trust_pem": 1, "timestamp_trust_pem": authority},
            ):
                _unchecked_failure(read_image_provenance(signed, **kwargs))
            assert len(oversized.encode("utf-8")) > MAX_TRUST_ANCHOR_BYTES
            assert VERIFICATION_SETTINGS["verify.remote_manifest_fetch"] is False
            assert VERIFICATION_SETTINGS["verify.ocsp_fetch"] is False
            assert VERIFICATION_SETTINGS["verify.ocsp_fetch_should_override"] is False
            assert _TimestampResponder.hits == before
            rendered = str(split) + str(manifest_only) + str(timestamp_only) + str(swapped)
            assert "BEGIN CERTIFICATE" not in rendered
            assert "PRIVATE KEY" not in rendered
        finally:
            server.shutdown()


def _raise_in_child(_data):
    raise RuntimeError("reader child crashed")


def test_child_crash_and_missing_result_are_technical_failures(monkeypatch):
    kind, value = run_bounded(_raise_in_child, (b"image",), 2)
    assert kind == "exception"
    assert value is None

    image = _jpeg()
    for label, code in (
        (("timeout", None), "reader_timeout"),
        (("exception", None), "reader_crash"),
        (("no_result", None), "reader_crash"),
    ):
        monkeypatch.setattr(
            reader_module,
            "run_bounded",
            lambda _target, _args, _timeout, label=label: label,
        )
        _assert_technical(read_image_provenance(image), code)


def test_reader_exception_is_not_a_credential_finding():
    kind, value = run_bounded(_raise_in_child, (_jpeg(),), 2)
    assert kind == "exception"
    assert value is None


def test_version_mismatch_is_reader_unavailable(monkeypatch):
    monkeypatch.setattr(reader_module, "native_library_version", lambda: "not-the-pinned-version")
    _assert_technical(read_image_provenance(_jpeg()), "reader_unavailable")


def test_unrecognized_child_status_is_not_rewritten_as_malformed():
    foreign = {
        "version": reader_module.READER_VERSION,
        "status": "POTENTIAL_MANIPULATION",
        "actions": [],
        "actionsWithheld": True,
    }
    _assert_technical(reader_module._accept(foreign), "reader_crash")
    timeout = {
        "version": reader_module.READER_VERSION,
        "status": "verification_failed",
        "failureCode": "reader_timeout",
        "checks": None,
        "manifests": [],
        "actions": [],
        "actionsWithheld": True,
    }
    _assert_technical(reader_module._accept(timeout), "reader_crash")
    accepted = reader_module._accept(reader_module._technical("memory_limit"))
    _assert_technical(accepted, "memory_limit")
