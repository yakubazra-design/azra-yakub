"""Server metadata extraction. Temporary databases only.

The live ledger is not opened. Precise coordinates are asserted against the
sealed snapshot and the owner reveal response, and against their absence
everywhere else.
"""

import json
import random
import sqlite3
import struct
import zlib
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from app.ledger import Ledger
from app.metadata_extract import (
    decimal_from_dms,
    extract_embedded_metadata,
    precise_gps_points,
    public_embedded_metadata,
)
from test_api import DUMMY_OPENAI, _create, _ensure_auth, _ledger, _seal, _settings
from test_assets import _gif, _jpeg, _png

FRONTEND = Path(__file__).resolve().parents[2] / "frontend"
PRECISE = "37.808333"
ROUNDED = "37.81"


def _entry(tag, typ, count, value):
    if isinstance(value, int):
        value = struct.pack("<I", value)
    return struct.pack("<HHI", tag, typ, count) + value[:4]


def _tiff(entries, extra=b"", next_offset=0, ifd_offset=8):
    header = b"II" + struct.pack("<H", 42) + struct.pack("<I", ifd_offset)
    directory = struct.pack("<H", len(entries)) + b"".join(entries) + struct.pack("<I", next_offset)
    pad = b"\x00" * max(ifd_offset - 8, 0)
    return header + pad + directory + extra


def _jpeg_exif(*tiffs):
    parts = [b"\xff\xd8"]
    for tiff in tiffs:
        payload = b"Exif\x00\x00" + tiff
        parts.append(b"\xff\xe1" + struct.pack(">H", len(payload) + 2) + payload)
    frame = b"\x08" + struct.pack(">HH", 1, 1) + b"\x01\x01\x11\x00"
    parts.append(b"\xff\xc0" + struct.pack(">H", len(frame) + 2) + frame + b"\xff\xd9")
    return b"".join(parts)


def _png_chunks(chunks):
    def chunk(tag, payload):
        crc = zlib.crc32(tag + payload) & 0xFFFFFFFF
        return struct.pack(">I", len(payload)) + tag + payload + struct.pack(">I", crc)

    header = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    pixels = zlib.compress(b"\x00\xff\x00\x00")
    parts = [b"\x89PNG\r\n\x1a\n", chunk(b"IHDR", header)]
    for tag, payload in chunks:
        parts.append(chunk(tag, payload))
    parts.extend((chunk(b"IDAT", pixels), chunk(b"IEND", b"")))
    return b"".join(parts)


def _webp_exif(tiff, prefix=False):
    payload = b"Exif\x00\x00" + tiff if prefix else tiff
    image = b"VP8 " + struct.pack("<I", 1) + b"\x00" + (b"\x00" if 1 & 1 else b"")
    exif = b"EXIF" + struct.pack("<I", len(payload)) + payload
    if len(payload) & 1:
        exif += b"\x00"
    body = b"WEBP" + image + exif
    return b"RIFF" + struct.pack("<I", len(body)) + body


def _make_tiff(text=b"ABCD"):
    return _tiff([_entry(271, 2, len(text), text.ljust(4, b"\x00"))])


def _gps_tiff(lat=(37, 1, 48, 1, 30, 1), lon=(10, 1, 0, 1, 0, 1), lat_ref=b"N\x00", lon_ref=b"E\x00", altitude=None):
    count = 6 if altitude is not None else 4
    directory_end = 26 + 2 + count * 12 + 4
    lat_at = directory_end
    lon_at = lat_at + 24
    alt_at = lon_at + 24
    entries = [
        _entry(1, 2, 2, lat_ref.ljust(4, b"\x00")),
        _entry(2, 5, 3, lat_at),
        _entry(3, 2, 2, lon_ref.ljust(4, b"\x00")),
        _entry(4, 5, 3, lon_at),
    ]
    extra = struct.pack("<6I", *lat) + struct.pack("<6I", *lon)
    if altitude is not None:
        entries.extend((
            _entry(5, 1, 1, struct.pack("<I", altitude[1])),
            _entry(6, 5, 1, alt_at),
        ))
        extra += struct.pack("<II", altitude[0], altitude[2] if len(altitude) > 2 else 1)
    gps = struct.pack("<H", len(entries)) + b"".join(entries) + struct.pack("<I", 0) + extra
    pointer = _entry(34853, 4, 1, 26)
    return _tiff([pointer]) + gps


def _openai(_request: httpx.Request) -> httpx.Response:
    content = json.dumps({"assessment": "UNRESOLVED", "findings": [], "why": {}, "uncertainty": []})
    return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})


def _app(tmp_path, **overrides):
    path = _ledger(tmp_path)
    app = __import__("app.main", fromlist=["create_app"]).create_app(
        settings=_settings(ledger_path=path, openai_api_key=DUMMY_OPENAI),
        openai_transport=httpx.MockTransport(_openai),
        **overrides,
    )
    return path, app


def _upload(client, investigation_id, data, metadata=None):
    headers = {"Content-Type": "application/octet-stream", "X-Image-Consent": "image-upload-1"}
    if metadata is not None:
        headers["X-Image-Metadata-Consent"] = metadata
    return client.post(f"/api/investigations/{investigation_id}/asset", content=data, headers=headers)


def _rows(path, query, params=()):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(query, params).fetchall()
    finally:
        conn.close()


def test_dms_boundaries_reject_before_rounding_and_do_not_clamp():
    assert decimal_from_dms((37, 1), (48, 1), (30, 1), 90) == PRECISE
    assert decimal_from_dms((90, 1), (0, 1), (0, 1), 90) == "90.000000"
    assert decimal_from_dms((180, 1), (0, 1), (0, 1), 180) == "180.000000"
    for bad in (
        ((90, 1), (0, 1), (1, 1), 90),
        ((90, 1), (1, 1), (0, 1), 90),
        ((180, 1), (0, 1), (1, 1), 180),
        ((91, 1), (0, 1), (0, 1), 90),
        ((37, 1), (60, 1), (0, 1), 90),
        ((37, 1), (0, 0), (0, 1), 90),
    ):
        assert decimal_from_dms(*bad) is None
    rng = random.Random(314159)
    for _ in range(400):
        degrees = (rng.randrange(0, 2**32), rng.randrange(0, 2**32))
        minutes = (rng.randrange(0, 2**32), rng.randrange(0, 2**32))
        seconds = (rng.randrange(0, 2**32), rng.randrange(0, 2**32))
        result = decimal_from_dms(degrees, minutes, seconds, 90)
        if degrees[1] and degrees[0] == 90 * degrees[1] and (minutes[0] or seconds[0]):
            assert result is None
        if result is not None:
            assert abs(float(result)) <= 90


def test_random_bytes_stay_inside_the_status_set():
    rng = random.Random(17)
    allowed = {
        "extraction_failed",
        "malformed",
        "unsupported_format",
        "unsupported_structure",
        "no_supported_metadata",
        "extracted",
    }
    for _ in range(80):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 300)))
        for media in ("image/jpeg", "image/png", "image/webp", "image/gif"):
            result = extract_embedded_metadata(blob, media)
            assert result["status"] in allowed
            if result["status"] in {"malformed", "extraction_failed", "unsupported_format", "unsupported_structure"}:
                assert result["fields"] == {}


def test_formats_layouts_and_failures():
    make = _make_tiff()
    assert extract_embedded_metadata(_jpeg_exif(make), "image/jpeg")["fields"]["make"]["values"][0]["value"] == "ABCD"
    assert extract_embedded_metadata(_png_chunks([(b"eXIf", make)]), "image/png")["status"] == "extracted"
    assert extract_embedded_metadata(_webp_exif(make), "image/webp")["status"] == "extracted"
    assert extract_embedded_metadata(_webp_exif(make, prefix=True), "image/webp")["status"] == "extracted"
    assert extract_embedded_metadata(_gif(), "image/gif")["status"] == "unsupported_format"
    assert extract_embedded_metadata(_jpeg(), "image/jpeg")["status"] == "no_supported_metadata"
    xmp = b"http://ns.adobe.com/xap/1.0/\x00<x/>"
    xmp_jpeg = b"\xff\xd8\xff\xe1" + struct.pack(">H", len(xmp) + 2) + xmp + _jpeg()[2:]
    assert extract_embedded_metadata(xmp_jpeg, "image/jpeg")["status"] == "unsupported_structure"
    text = _png_chunks([(b"tEXt", b"Comment\x00hello")])
    assert extract_embedded_metadata(text, "image/png")["status"] == "unsupported_structure"

    orientation = _tiff([_entry(274, 3, 1, 1)])
    assert extract_embedded_metadata(_jpeg_exif(orientation), "image/jpeg")["fields"]["orientation"]["values"][0]["value"] == "1"
    inline = _tiff([_entry(271, 2, 4, b"\x02ABC")])
    inline_result = extract_embedded_metadata(_jpeg_exif(inline), "image/jpeg")
    assert inline_result["status"] == "extracted"
    assert inline_result["fields"]["make"]["values"][0]["value"] == "\x02ABC"

    out_of_line = _tiff([_entry(271, 2, 6, 26)], extra=b"North\x00")
    assert extract_embedded_metadata(_jpeg_exif(out_of_line), "image/jpeg")["fields"]["make"]["values"][0]["value"] == "North"

    assert extract_embedded_metadata(_jpeg_exif(b"II" + struct.pack("<HI", 42, 0)), "image/jpeg")["status"] == "malformed"
    assert extract_embedded_metadata(_jpeg_exif(b"II" + struct.pack("<HI", 42, 4)), "image/jpeg")["status"] == "malformed"
    into_header = _tiff([_entry(271, 2, 6, 2)])
    assert extract_embedded_metadata(_jpeg_exif(into_header), "image/jpeg")["status"] == "malformed"
    overlap = _tiff([_entry(271, 2, 8, 20)], extra=b"overlap!")
    assert extract_embedded_metadata(_jpeg_exif(overlap), "image/jpeg")["status"] == "malformed"
    repeated = _tiff([_entry(271, 2, 6, 40), _entry(272, 2, 6, 40)], extra=b"\x00" * 20 + b"Camera\x00")
    assert extract_embedded_metadata(_jpeg_exif(repeated), "image/jpeg")["status"] == "malformed"
    thumbnail = _tiff([_entry(271, 2, 4, b"ABCD")], next_offset=4)
    assert extract_embedded_metadata(_jpeg_exif(thumbnail), "image/jpeg")["fields"]["make"]["status"] == "present"
    maker = _tiff([_entry(271, 2, 4, b"ABCD"), _entry(37500, 7, 4, 0)])
    assert extract_embedded_metadata(_jpeg_exif(maker), "image/jpeg")["fields"]["make"]["values"][0]["value"] == "ABCD"

    first = _make_tiff(b"Keep")
    broken = _jpeg_exif(first, b"NOPE")
    failed = extract_embedded_metadata(broken, "image/jpeg")
    assert failed["status"] == "malformed"
    assert failed["fields"] == {}
    ninth = _jpeg_exif(_make_tiff(), *(_tiff([]) for _ in range(8)))
    capped = extract_embedded_metadata(ninth, "image/jpeg")
    assert capped["status"] == "extraction_failed"
    assert capped["fields"] == {}
    huge = _png_chunks([(b"eXIf", b"II" + b"\x00" * (64 * 1024))])
    assert extract_embedded_metadata(huge, "image/png")["status"] == "extraction_failed"
    declared = b"II" + struct.pack("<HI", 42, 8) + struct.pack("<H", 257)
    assert extract_embedded_metadata(_jpeg_exif(declared), "image/jpeg")["status"] == "extraction_failed"


def test_gps_conflicts_dates_and_redaction():
    south = _gps_tiff(lat_ref=b"S\x00")
    parsed = extract_embedded_metadata(_jpeg_exif(south), "image/jpeg")
    gps = parsed["fields"]["gps"]
    assert gps["status"] == "present"
    assert gps["values"][0]["latitude"] == "-" + PRECISE
    assert gps["values"][0]["altitudeStatus"] == "absent"
    assert gps["values"][0]["occurrences"][0]["container"] == "jpeg-app1"
    assert gps["values"][0]["occurrences"][0]["sourceTags"]["latitude"] == 2
    boundary = _gps_tiff(lat=(90, 1, 0, 1, 1, 1))
    assert extract_embedded_metadata(_jpeg_exif(boundary), "image/jpeg")["fields"]["gps"]["status"] == "malformed"
    located = _gps_tiff(altitude=(25, 0, 2))
    located_fields = extract_embedded_metadata(_jpeg_exif(located), "image/jpeg")["fields"]["gps"]["values"][0]
    assert located_fields["altitude"] == "12.500000"
    other = _gps_tiff(lat=(10, 1, 0, 1, 0, 1))
    conflict = extract_embedded_metadata(_jpeg_exif(_gps_tiff(), other), "image/jpeg")["fields"]["gps"]
    assert conflict["status"] == "conflict"
    assert len(conflict["values"]) == 2
    same = extract_embedded_metadata(_jpeg_exif(_make_tiff(b"ABCD"), _make_tiff(b"ABCD")), "image/jpeg")
    assert same["fields"]["make"]["status"] == "present"
    assert len(same["fields"]["make"]["values"][0]["occurrences"]) == 2
    differ = extract_embedded_metadata(_jpeg_exif(_make_tiff(b"AAAA"), _make_tiff(b"BBBB")), "image/jpeg")
    assert differ["fields"]["make"]["status"] == "conflict"
    date = b"2024:05:01 12:30:00\x00"
    exif_dir = struct.pack("<H", 1) + _entry(36867, 2, 20, 44) + struct.pack("<I", 0) + date
    pointer = _entry(34665, 4, 1, 26)
    dated = _tiff([pointer]) + exif_dir
    assert extract_embedded_metadata(_jpeg_exif(dated), "image/jpeg")["fields"]["dateTimeOriginal"]["values"][0]["value"] == "2024:05:01 12:30:00"
    public = public_embedded_metadata({"status": "extracted", "fields": parsed["fields"], "consent": {}})
    assert public["fields"]["gps"]["values"][0]["latitude"] == "-37.81"
    assert "808333" not in json.dumps(public)
    assert "altitude" not in json.dumps(public["fields"]["gps"])


def test_consent_records_and_invalid_values_are_not_stored(tmp_path):
    path, app = _app(tmp_path)
    image = _jpeg_exif(_gps_tiff())
    with TestClient(app) as client:
        _ensure_auth(client, "owner@example.com")
        accepted_id = _create(client, "Accepted metadata.")
        omitted_id = _create(client, "Omitted metadata.")
        declined_id = _create(client, "Declined metadata.")
        invalid_id = _create(client, "Invalid metadata.")
        accepted = _upload(client, accepted_id, image, "image-metadata-1")
        omitted = _upload(client, omitted_id, image)
        declined = _upload(client, declined_id, image, "declined")
        invalid = _upload(client, invalid_id, image, "image-upload-1")
        padded = _upload(client, invalid_id, image, " image-metadata-1")
        legacy_id = _create(client, "Old metadata header.")
        legacy = client.post(
            f"/api/investigations/{legacy_id}/asset",
            content=image,
            headers={
                "Content-Type": "application/octet-stream",
                "X-Image-Consent": "image-upload-1",
                "X-Metadata-Consent": "image-metadata-1",
            },
        )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["metadataConsentVersion"] == "image-metadata-1"
    assert accepted.json()["metadataConsentDecision"] == "accepted"
    assert omitted.json()["metadataConsentDecision"] == "omitted"
    assert declined.json()["metadataConsentDecision"] == "declined"
    assert invalid.status_code == 400
    assert invalid.json()["code"] == "metadata_consent_invalid"
    assert padded.status_code == 400
    assert padded.json()["code"] == "metadata_consent_invalid"
    assert legacy.status_code == 200, legacy.text
    assert legacy.json()["metadataConsentDecision"] == "omitted"
    assert PRECISE not in accepted.text
    stored = {row["investigation_id"]: row for row in _rows(path, "SELECT * FROM image_assets")}
    assert len(stored) == 4
    assert stored[invalid_id] if False else invalid_id not in stored
    assert stored[accepted_id]["metadata_consent_version"] == "image-metadata-1"
    assert stored[omitted_id]["metadata_consent_decision"] == "omitted"
    assert stored[declined_id]["metadata_consent_decision"] == "declined"
    assert stored[legacy_id]["metadata_consent_decision"] == "omitted"


def test_seal_redacts_every_response_and_reveal_is_owner_only(tmp_path):
    path, app = _app(tmp_path)
    image = _jpeg_exif(_gps_tiff())
    prompts = []

    def capture(request: httpx.Request) -> httpx.Response:
        prompts.append(json.loads(request.content.decode())["messages"][0]["content"])
        return _openai(request)

    app = __import__("app.main", fromlist=["create_app"]).create_app(
        settings=_settings(ledger_path=path, openai_api_key=DUMMY_OPENAI),
        openai_transport=httpx.MockTransport(capture),
    )
    with TestClient(app) as owner, TestClient(app) as other, TestClient(app) as anon:
        _ensure_auth(owner, "owner@example.com")
        _ensure_auth(other, "other@example.com")
        investigation_id = _create(owner, "A located picture.")
        uploaded = _upload(owner, investigation_id, image, "image-metadata-1")
        assert uploaded.status_code == 200, uploaded.text
        sealed = owner.post(f"/api/investigations/{investigation_id}/seal")
        assert sealed.status_code == 200, sealed.text
        assessed = owner.post(
            f"/api/investigations/{investigation_id}/assess",
            json={"assessmentToken": sealed.json()["assessmentToken"]},
        )
        evidence = owner.get(f"/api/investigations/{investigation_id}/evidence")
        claims = owner.post(f"/api/investigations/{investigation_id}/extract-claims")
        snapshot_id = assessed.json()["imageEvidence"]["snapshotId"]
        revealed = owner.post(
            f"/api/investigations/{investigation_id}/image-metadata/gps",
            json={"snapshotId": snapshot_id},
        )
        stolen = other.post(
            f"/api/investigations/{investigation_id}/image-metadata/gps",
            json={"snapshotId": snapshot_id},
        )
        anon_response = anon.post(
            f"/api/investigations/{investigation_id}/image-metadata/gps",
            json={"snapshotId": snapshot_id},
        )
        saved = owner.headers["X-CSRF-Token"]
        owner.headers["X-CSRF-Token"] = "not-the-token"
        csrf = owner.post(
            f"/api/investigations/{investigation_id}/image-metadata/gps",
            json={"snapshotId": snapshot_id},
        )
        owner.headers["X-CSRF-Token"] = saved
        removed = owner.delete(f"/api/investigations/{investigation_id}")
        after = owner.post(
            f"/api/investigations/{investigation_id}/image-metadata/gps",
            json={"snapshotId": snapshot_id},
        )
    assert assessed.status_code == 200, assessed.text
    public_gps = assessed.json()["imageEvidence"]["embeddedMetadata"]["fields"]["gps"]["values"][0]
    assert public_gps["latitude"] == ROUNDED
    assert PRECISE not in assessed.text
    assert PRECISE not in sealed.text
    assert PRECISE not in uploaded.text
    assert PRECISE not in evidence.text
    assert PRECISE not in claims.text
    assert PRECISE not in stolen.text
    assert PRECISE not in prompts[0]
    assert "gps" not in prompts[0].lower()
    assert revealed.status_code == 200, revealed.text
    assert revealed.json()["gps"][0]["latitude"] == PRECISE
    assert revealed.headers["cache-control"] == "no-store"
    for response in (stolen, anon_response, csrf, after):
        assert response.headers["cache-control"] == "no-store"
        assert "pragma" in response.headers
    assert stolen.status_code == 404
    assert anon_response.status_code == 401
    assert csrf.status_code == 403
    assert csrf.json()["code"] == "csrf_failed"
    assert removed.status_code == 200
    assert after.status_code == 404
    assert PRECISE not in after.text
    conn = sqlite3.connect(path)
    try:
        remaining = conn.execute("SELECT COUNT(*) FROM assessment_snapshots").fetchone()[0]
    finally:
        conn.close()
    assert remaining == 0


def test_snapshot_is_immutable_and_failure_discards_partial_metadata(tmp_path, monkeypatch):
    path, app = _app(tmp_path)
    image = _jpeg_exif(_make_tiff(b"Keep"))
    with TestClient(app) as client:
        _ensure_auth(client, "owner@example.com")
        investigation_id = _create(client, "Keep the make.")
        assert _upload(client, investigation_id, image, "image-metadata-1").status_code == 200
        assert client.post(f"/api/investigations/{investigation_id}/seal").status_code == 200
    conn = sqlite3.connect(path)
    try:
        stored = conn.execute("SELECT snapshot_json FROM assessment_snapshots").fetchone()[0]
        try:
            conn.execute("UPDATE assessment_snapshots SET snapshot_json = '{}'")
            conn.commit()
            updated = True
        except sqlite3.Error:
            updated = False
    finally:
        conn.close()
    assert updated is False
    assert "Keep" in stored
    assert "currentFile" not in stored

    def explode(_data, _media):
        raise RuntimeError("metadata extraction failed")

    monkeypatch.setattr("app.ledger.extract_embedded_metadata", explode)
    path_two, app_two = _app(tmp_path / "second")
    with TestClient(app_two) as client:
        _ensure_auth(client, "owner@example.com")
        investigation_id = _create(client, "Exception during parsing.")
        assert _upload(client, investigation_id, image, "image-metadata-1").status_code == 200
        sealed = client.post(f"/api/investigations/{investigation_id}/seal")
        assert sealed.status_code == 200, sealed.text
    body = _rows(path_two, "SELECT snapshot_json FROM assessment_snapshots")[0]["snapshot_json"]
    parsed = json.loads(body)
    assert parsed["embeddedMetadata"]["status"] == "extraction_failed"
    assert parsed["embeddedMetadata"]["fields"] == {}
    assert "Keep" not in body
    assert "metadata extraction failed" not in body


def test_replacement_and_deletion_do_not_seal_the_old_parse(tmp_path, monkeypatch):
    path, app = _app(tmp_path)
    image = _jpeg_exif(_make_tiff(b"Old!"))
    replacement = _jpeg()
    with TestClient(app) as client:
        _ensure_auth(client, "owner@example.com")
        investigation_id = _create(client, "Replace before seal.")
        assert _upload(client, investigation_id, image, "image-metadata-1").status_code == 200
        ledger = app.state.ledger
        owner_id = _rows(path, "SELECT owner_id FROM image_assets")[0]["owner_id"]

        def replace_during_parse(_data, _media):
            from hashlib import sha256
            from secrets import token_hex

            store = app.state.assets
            asset_id = token_hex(16)
            digest = sha256(replacement).hexdigest()
            storage_name = store.write(asset_id, replacement, owner_id=owner_id, investigation_id=investigation_id)
            ledger.save_image_asset(
                owner_id,
                investigation_id,
                asset_id,
                digest,
                len(replacement),
                "image/jpeg",
                "not_supplied",
                storage_name,
                "image-upload-1",
                "declined",
                "declined",
            )
            store.finish_intent(storage_name)
            return {"status": "extracted", "fields": {"make": {"status": "present", "values": [{"value": "Old!", "occurrences": []}]}}}

        monkeypatch.setattr("app.ledger.extract_embedded_metadata", replace_during_parse)
        sealed = client.post(f"/api/investigations/{investigation_id}/seal")
        assert sealed.status_code == 503
        assert _rows(path, "SELECT COUNT(*) AS n FROM assessment_snapshots")[0]["n"] == 0
        monkeypatch.undo()
        assert ledger.prepare_investigation_deletion(owner_id, investigation_id) is True
        blocked = client.post(f"/api/investigations/{investigation_id}/seal")
        assert blocked.status_code == 409
        assert _rows(path, "SELECT COUNT(*) AS n FROM assessment_snapshots")[0]["n"] == 0


def test_reveal_rate_limit_and_migration(tmp_path):
    path, app = _app(tmp_path, limits={"gps_reveal": (1, 3600)})
    image = _jpeg_exif(_gps_tiff())
    with TestClient(app) as client:
        _ensure_auth(client, "owner@example.com")
        investigation_id = _create(client, "Limit the reveal.")
        assert _upload(client, investigation_id, image, "image-metadata-1").status_code == 200
        assessed = client.post(
            f"/api/investigations/{investigation_id}/assess",
            json={"assessmentToken": _seal(client, investigation_id)},
        )
        snapshot_id = assessed.json()["imageEvidence"]["snapshotId"]
        first = client.post(
            f"/api/investigations/{investigation_id}/image-metadata/gps",
            json={"snapshotId": snapshot_id},
        )
        second = client.post(
            f"/api/investigations/{investigation_id}/image-metadata/gps",
            json={"snapshotId": snapshot_id},
        )
    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers["cache-control"] == "no-store"
    assert PRECISE not in second.text

    old = tmp_path / "old-ledger.sqlite"
    conn = sqlite3.connect(old)
    conn.execute(
        """
        CREATE TABLE image_assets (
            id TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            byte_length INTEGER NOT NULL,
            media_type TEXT NOT NULL,
            received_at TEXT NOT NULL,
            retention TEXT NOT NULL,
            client_hash_status TEXT NOT NULL,
            storage_name TEXT NOT NULL,
            consent_version TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()
    Ledger(old)
    migrated = sqlite3.connect(old)
    try:
        columns = {row[1] for row in migrated.execute("PRAGMA table_info(image_assets)")}
    finally:
        migrated.close()
    assert {"metadata_consent_version", "metadata_consent_decision", "metadata_consent_at"} <= columns


def _sealed_point(altitude, altitude_status="present", latitude=PRECISE):
    return {
        "status": "extracted",
        "fields": {
            "gps": {
                "status": "present",
                "values": [{
                    "latitude": latitude,
                    "longitude": "10.000000",
                    "altitude": altitude,
                    "altitudeStatus": altitude_status,
                    "occurrences": [{
                        "container": "jpeg-app1",
                        "blockIndex": 0,
                        "sourceTags": {"latitude": 2, "longitude": 4},
                    }],
                }],
            }
        },
    }


def _gps_duplicate_latitudes(first, second):
    gps_offset = 26
    count = 5
    directory_end = gps_offset + 2 + count * 12 + 4
    lat1_at = directory_end
    lat2_at = lat1_at + 24
    lon_at = lat2_at + 24
    entries = [
        _entry(1, 2, 2, b"N\x00".ljust(4, b"\x00")),
        _entry(2, 5, 3, lat1_at),
        _entry(2, 5, 3, lat2_at),
        _entry(3, 2, 2, b"E\x00".ljust(4, b"\x00")),
        _entry(4, 5, 3, lon_at),
    ]
    extra = struct.pack("<6I", *first) + struct.pack("<6I", *second) + struct.pack("<6I", 10, 1, 0, 1, 0, 1)
    gps = struct.pack("<H", len(entries)) + b"".join(entries) + struct.pack("<I", 0) + extra
    return _tiff([_entry(34853, 4, 1, gps_offset)]) + gps


def test_altitude_range_is_separate_from_coordinates():
    assert decimal_from_dms((999999999, 1000000), (0, 1), (0, 1), 100000) == "999.999999"
    assert decimal_from_dms((1000, 1), (0, 1), (0, 1), 100000) == "1000.000000"
    assert decimal_from_dms((99999999999, 1000000), (0, 1), (0, 1), 100000) == "99999.999999"
    assert decimal_from_dms((100000, 1), (0, 1), (0, 1), 100000) == "100000.000000"
    assert decimal_from_dms((100000, 1), (0, 1), (1, 1), 100000) is None
    assert decimal_from_dms((100001, 1), (0, 1), (0, 1), 100000) is None
    for value in ("999.999999", "1000.000000", "99999.999999", "100000.000000", "-100000.000000"):
        points = precise_gps_points(_sealed_point(value))
        assert points[0]["altitude"] == value
        assert points[0]["latitude"] == PRECISE
    assert precise_gps_points(_sealed_point("100000.000001")) == []
    assert precise_gps_points(_sealed_point("100001.000000")) == []
    assert precise_gps_points(_sealed_point("-100000.000001")) == []
    latitude = _sealed_point("12.500000", latitude="1000.000000")
    assert precise_gps_points(latitude) == []
    stored = extract_embedded_metadata(_jpeg_exif(_gps_tiff(altitude=(1000, 0, 1))), "image/jpeg")
    assert stored["fields"]["gps"]["values"][0]["altitude"] == "1000.000000"
    maximum = extract_embedded_metadata(_jpeg_exif(_gps_tiff(altitude=(100000, 0, 1))), "image/jpeg")
    assert maximum["fields"]["gps"]["values"][0]["altitude"] == "100000.000000"
    over = extract_embedded_metadata(_jpeg_exif(_gps_tiff(altitude=(100001, 0, 1))), "image/jpeg")
    assert over["fields"]["gps"]["status"] == "malformed"


def test_equivalent_gps_rationals_collapse_and_different_values_conflict():
    same = extract_embedded_metadata(
        _jpeg_exif(_gps_duplicate_latitudes((10, 1, 0, 1, 0, 1), (20, 2, 0, 1, 0, 1))),
        "image/jpeg",
    )
    assert same["fields"]["gps"]["status"] == "present"
    assert same["fields"]["gps"]["values"][0]["latitude"] == "10.000000"
    assert len(same["fields"]["gps"]["values"]) == 1
    conflict = extract_embedded_metadata(
        _jpeg_exif(_gps_duplicate_latitudes((10, 1, 0, 1, 0, 1), (11, 1, 0, 1, 0, 1))),
        "image/jpeg",
    )
    assert conflict["fields"]["gps"]["status"] == "conflict"
    latitudes = sorted(item["latitude"] for item in conflict["fields"]["gps"]["values"])
    assert latitudes == ["10.000000", "11.000000"]


def test_changed_bytes_after_the_verified_read_are_not_sealed(tmp_path, monkeypatch):
    path, app = _app(tmp_path)
    image = _jpeg_exif(_make_tiff(b"Keep"))
    replacement = _jpeg()
    with TestClient(app) as client:
        _ensure_auth(client, "owner@example.com")
        investigation_id = _create(client, "Bytes changed after the read.")
        assert _upload(client, investigation_id, image, "image-metadata-1").status_code == 200
        storage_name = _rows(path, "SELECT storage_name FROM image_assets")[0]["storage_name"]
        asset_path = Path(path).parent / "assets" / storage_name

        def swap(data, _media):
            asset_path.write_bytes(replacement)
            return extract_embedded_metadata(data, "image/jpeg")

        monkeypatch.setattr("app.ledger.extract_embedded_metadata", swap)
        sealed = client.post(f"/api/investigations/{investigation_id}/seal")
    assert sealed.status_code == 503
    assert "Keep" not in sealed.text
    assert _rows(path, "SELECT COUNT(*) AS n FROM assessment_snapshots")[0]["n"] == 0


def test_results_page_sends_metadata_consent_and_keeps_precise_values_out_of_storage():
    script = (FRONTEND / "engine.js").read_text()
    page = (FRONTEND / "index.html").read_text()
    assert "X-Image-Metadata-Consent" in script
    assert "X-Metadata-Consent" not in script
    assert "toFixed(6)" not in script
    assert "formatLocalCoordinate" in script
    assert "image-metadata-1" in script
    assert "metadata-consent" in page
    assert "two decimal places" in page
    assert "precise coordinates" in page
    assert "A backup made before deletion" in page
    reveal = script.split("image-evidence-reveal")[1].split("function noteSealedFileDeleted")[0]
    assert "localStorage" not in reveal
    assert "sessionStorage" not in reveal
    assert "console." not in reveal
