"""Bounded reader for allowlisted EXIF fields.

The reader follows IFD0, the Exif IFD, and the GPS IFD. It does not decode
pixels, follow a thumbnail, or follow a maker note. Coordinates are integer
rationals. A structural failure or a resource cap returns no field values.
"""

from __future__ import annotations

import re
import zlib

METADATA_CONSENT_VERSION = "image-metadata-1"
METADATA_VERSION = "image-metadata-1"

MAX_BLOCKS = 8
MAX_TIFF_BYTES = 64 * 1024
MAX_IFD_ENTRIES = 256
MAX_VALUE_READS = 128
MAX_TEXT_COUNT = 128

_HEADER = 8
_UINT32_MAX = 2**32 - 1
_ARITHMETIC_MAX = 2**256 - 1
_LATITUDE_LIMIT = 90
_LONGITUDE_LIMIT = 180
_ALTITUDE_LIMIT = 100_000

_FILE_STATUSES = {
    "not_performed",
    "extraction_failed",
    "malformed",
    "unsupported_format",
    "unsupported_structure",
    "no_supported_metadata",
    "extracted",
    "not_extracted",
}
_FIELD_NAMES = (
    "make",
    "model",
    "orientation",
    "software",
    "dateTime",
    "dateTimeOriginal",
    "dateTimeDigitized",
    "gps",
)
_SIX_DECIMAL = re.compile(r"^-?\d{1,3}\.\d{6}$")
_ALTITUDE_TEXT = re.compile(r"^-?\d{1,6}\.\d{6}$")
_ALTITUDE_MICRO_MAX = _ALTITUDE_LIMIT * 1_000_000

_TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8}
_XMP_PREFIX = b"http://ns.adobe.com/xap/1.0/\x00"
_EXIF_PREFIX = b"Exif\x00\x00"

# IFD0 tags that may be dereferenced, then the two pointer tags.
_IFD0_TEXT = {271: "make", 272: "model", 305: "software", 306: "dateTime"}
_EXIF_TEXT = {36867: "dateTimeOriginal", 36868: "dateTimeDigitized"}
_POINTER_EXIF = 34665
_POINTER_GPS = 34853
_ORIENTATION = 274


class _Stop(Exception):
    """A known parse stop. The message is the file status and nothing else."""

    def __init__(self, status: str) -> None:
        super().__init__(status)
        self.status = status


def classify_metadata_consent(header: str | None) -> tuple[str, str] | None:
    """Map the upload header to the stored decision.

    A missing header and an explicit decline are stored differently. Any
    other value, including the upload-consent version, is refused.
    """
    if header is None or str(header).strip() == "":
        return "declined", "omitted"
    text = str(header)
    if text == "declined":
        return "declined", "declined"
    if text == METADATA_CONSENT_VERSION:
        return METADATA_CONSENT_VERSION, "accepted"
    return None


def extract_embedded_metadata(data: bytes, media_type: str) -> dict:
    """Return a status and fields. Known failures carry no field values.

    Unexpected exceptions propagate so the seal caller can discard a partial
    result and store ``extraction_failed``.
    """
    if media_type == "image/gif":
        return {"status": "unsupported_format", "fields": {}}
    if media_type not in {"image/jpeg", "image/png", "image/webp"}:
        return {"status": "unsupported_format", "fields": {}}
    if not isinstance(data, (bytes, bytearray)):
        return {"status": "malformed", "fields": {}}
    try:
        return _extract(bytes(data), media_type)
    except _Stop as stop:
        return {"status": stop.status, "fields": {}}


def decimal_from_dms(
    degrees: tuple[int, int],
    minutes: tuple[int, int],
    seconds: tuple[int, int],
    limit: int,
) -> str | None:
    """Convert one DMS triple to a six-decimal absolute value, or reject it."""
    pair = _accept_dms(degrees, minutes, seconds, limit)
    if pair is None:
        return None
    numerator, denominator = pair
    q = _round_half_away(numerator, denominator, 1_000_000)
    if q is None or q > limit * 1_000_000:
        return None
    return _format_scaled(q, 6)


def public_embedded_metadata(value) -> dict:
    """Copy a sealed metadata object without six-decimal coordinates."""
    if not isinstance(value, dict):
        return {"status": "not_extracted"}
    status = value.get("status")
    if status not in _FILE_STATUSES or status == "not_extracted":
        return {"status": "not_extracted"}
    public = {
        "version": METADATA_VERSION,
        "status": status,
        "consent": _public_consent(value.get("consent")),
        "fields": {},
    }
    if status not in {"extracted", "no_supported_metadata"}:
        return public
    fields = value.get("fields")
    if not isinstance(fields, dict):
        public["status"] = "malformed"
        return public
    safe_fields = {}
    for name in _FIELD_NAMES:
        if name not in fields:
            continue
        if name == "gps":
            safe_fields["gps"] = _public_gps(fields.get("gps"))
        else:
            safe_fields[name] = _public_text_field(fields.get(name))
    if safe_fields.get("gps", {}).get("status") == "malformed" and _gps_was_readable(fields.get("gps")):
        safe_fields["gps"] = {"status": "malformed", "values": []}
    public["fields"] = safe_fields
    return public


def precise_gps_points(value) -> list[dict]:
    """Return sealed coordinates for the owner reveal, or an empty list."""
    if not isinstance(value, dict) or value.get("status") != "extracted":
        return []
    fields = value.get("fields")
    if not isinstance(fields, dict):
        return []
    gps = fields.get("gps")
    if not isinstance(gps, dict) or gps.get("status") not in {"present", "conflict"}:
        return []
    points = []
    values = gps.get("values")
    if not isinstance(values, list):
        return []
    for item in values:
        if not isinstance(item, dict):
            return []
        latitude = item.get("latitude")
        longitude = item.get("longitude")
        if not isinstance(latitude, str) or _SIX_DECIMAL.fullmatch(latitude) is None:
            return []
        if not isinstance(longitude, str) or _SIX_DECIMAL.fullmatch(longitude) is None:
            return []
        occurrences = item.get("occurrences")
        if not isinstance(occurrences, list) or not occurrences:
            return []
        altitude = item.get("altitude")
        altitude_status = item.get("altitudeStatus")
        for occurrence in occurrences:
            if not isinstance(occurrence, dict):
                return []
            point = {
                "latitude": latitude,
                "longitude": longitude,
                "container": occurrence.get("container") if isinstance(occurrence.get("container"), str) else "",
                "blockIndex": occurrence.get("blockIndex") if isinstance(occurrence.get("blockIndex"), int) else 0,
                "sourceTags": _source_tags(occurrence.get("sourceTags")),
            }
            if altitude_status == "present":
                accepted_altitude = _accepted_altitude(altitude)
                if accepted_altitude is None:
                    return []
                point["altitude"] = accepted_altitude
            elif altitude_status not in {None, "absent"}:
                return []
            points.append(point)
            if len(points) > 64:
                return []
    return points


def _extract(data: bytes, media_type: str) -> dict:
    containers, saw_other = _containers(data, media_type)
    if not containers and saw_other:
        return {"status": "unsupported_structure", "fields": {}}
    if not containers:
        return {"status": "no_supported_metadata", "fields": {}}
    blocks = []
    for index, (container, payload) in enumerate(containers):
        blocks.append(_parse_tiff(payload, container, index))
    return _merge_blocks(blocks)


def _containers(data: bytes, media_type: str) -> tuple[list[tuple[str, bytes]], bool]:
    if media_type == "image/jpeg":
        return _jpeg_containers(data)
    if media_type == "image/png":
        return _png_containers(data)
    return _webp_containers(data)


def _remember(blocks: list, container: str, payload: bytes) -> None:
    if len(blocks) >= MAX_BLOCKS:
        raise _Stop("extraction_failed")
    if len(payload) > MAX_TIFF_BYTES:
        raise _Stop("extraction_failed")
    blocks.append((container, payload))


def _jpeg_containers(data: bytes) -> tuple[list[tuple[str, bytes]], bool]:
    blocks: list[tuple[str, bytes]] = []
    saw_other = False
    if len(data) < 4 or data[:3] != b"\xff\xd8\xff":
        raise _Stop("malformed")
    pos = 2
    while pos < len(data):
        if data[pos] != 0xFF:
            raise _Stop("malformed")
        while pos < len(data) and data[pos] == 0xFF:
            pos += 1
        if pos >= len(data):
            raise _Stop("malformed")
        marker = data[pos]
        pos += 1
        if marker == 0xD9 or marker == 0xDA:
            break
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            continue
        if pos + 2 > len(data):
            raise _Stop("malformed")
        length = int.from_bytes(data[pos:pos + 2], "big")
        if length < 2 or pos + length > len(data):
            raise _Stop("malformed")
        segment = data[pos + 2:pos + length]
        pos += length
        if marker != 0xE1:
            continue
        if segment.startswith(_EXIF_PREFIX):
            _remember(blocks, "jpeg-app1", segment[len(_EXIF_PREFIX):])
        elif segment.startswith(_XMP_PREFIX):
            saw_other = True
    return blocks, saw_other


def _png_containers(data: bytes) -> tuple[list[tuple[str, bytes]], bool]:
    blocks: list[tuple[str, bytes]] = []
    saw_other = False
    if len(data) < 8 or data[:8] != b"\x89PNG\r\n\x1a\n":
        raise _Stop("malformed")
    pos = 8
    while pos + 12 <= len(data):
        length = int.from_bytes(data[pos:pos + 4], "big")
        tag = data[pos + 4:pos + 8]
        chunk_end = pos + 12 + length
        if chunk_end > len(data):
            raise _Stop("malformed")
        expected = zlib.crc32(data[pos + 4:chunk_end - 4]) & 0xFFFFFFFF
        actual = int.from_bytes(data[chunk_end - 4:chunk_end], "big")
        if expected != actual:
            raise _Stop("malformed")
        payload = data[pos + 8:chunk_end - 4]
        pos = chunk_end
        if tag == b"eXIf":
            _remember(blocks, "png-exif", payload)
        elif tag in {b"tEXt", b"zTXt", b"iTXt"}:
            saw_other = True
        if tag == b"IEND":
            break
    return blocks, saw_other


def _webp_containers(data: bytes) -> tuple[list[tuple[str, bytes]], bool]:
    blocks: list[tuple[str, bytes]] = []
    saw_other = False
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        raise _Stop("malformed")
    pos = 12
    while pos + 8 <= len(data):
        tag = data[pos:pos + 4]
        size = int.from_bytes(data[pos + 4:pos + 8], "little")
        start = pos + 8
        end = start + size
        if end > len(data):
            raise _Stop("malformed")
        payload = data[start:end]
        pos = end + (size & 1)
        if pos > len(data):
            raise _Stop("malformed")
        if tag == b"EXIF":
            if payload.startswith(_EXIF_PREFIX):
                _remember(blocks, "webp-exif", payload[len(_EXIF_PREFIX):])
            elif payload.startswith((b"II", b"MM")):
                _remember(blocks, "webp-exif", payload)
            else:
                raise _Stop("malformed")
        elif tag == b"XMP ":
            saw_other = True
    return blocks, saw_other


def _parse_tiff(payload: bytes, container: str, block_index: int) -> dict:
    if len(payload) < _HEADER:
        raise _Stop("malformed")
    if payload[:2] == b"II":
        endian = "little"
    elif payload[:2] == b"MM":
        endian = "big"
    else:
        raise _Stop("malformed")
    if _u16(payload, 2, endian) != 42:
        raise _Stop("malformed")
    occupied = [(0, _HEADER)]
    reads = [0]
    ifd0 = _u32(payload, 4, endian)
    fields = _blank_block()
    _parse_ifd(
        payload,
        ifd0,
        endian,
        occupied,
        reads,
        fields,
        container,
        block_index,
        kind="ifd0",
    )
    return fields


def _blank_block() -> dict:
    return {name: {"malformed": False, "items": []} for name in _FIELD_NAMES}


def _parse_ifd(payload, offset, endian, occupied, reads, fields, container, block_index, kind: str) -> None:
    if offset < _HEADER:
        raise _Stop("malformed")
    if offset + 2 > len(payload):
        raise _Stop("malformed")
    count = _u16(payload, offset, endian)
    if count > MAX_IFD_ENTRIES:
        raise _Stop("extraction_failed")
    directory_end = offset + 2 + count * 12 + 4
    _add_span(occupied, offset, directory_end, len(payload))
    for index in range(count):
        entry = offset + 2 + index * 12
        tag = _u16(payload, entry, endian)
        typ = _u16(payload, entry + 2, endian)
        number = _u32(payload, entry + 4, endian)
        raw = payload[entry + 8:entry + 12]
        _read_entry(
            payload, endian, occupied, reads, fields, container, block_index,
            kind, tag, typ, number, raw,
        )


def _read_entry(payload, endian, occupied, reads, fields, container, block_index, kind, tag, typ, number, raw) -> None:
    if kind == "ifd0" and tag == _POINTER_EXIF:
        _follow_pointer(payload, endian, occupied, reads, fields, container, block_index, tag, typ, number, raw, "exif")
        return
    if kind == "ifd0" and tag == _POINTER_GPS:
        _follow_pointer(payload, endian, occupied, reads, fields, container, block_index, tag, typ, number, raw, "gps")
        return
    if kind == "ifd0" and tag == _ORIENTATION:
        _read_orientation(payload, endian, occupied, reads, fields, container, block_index, typ, number, raw)
        return
    if kind == "ifd0" and tag in _IFD0_TEXT:
        _read_text(payload, endian, occupied, reads, fields, container, block_index, _IFD0_TEXT[tag], tag, typ, number, raw)
        return
    if kind == "exif" and tag in _EXIF_TEXT:
        _read_text(payload, endian, occupied, reads, fields, container, block_index, _EXIF_TEXT[tag], tag, typ, number, raw)
        return
    if kind == "gps" and tag in {1, 2, 3, 4, 5, 6}:
        _read_gps_tag(payload, endian, occupied, reads, fields, container, block_index, tag, typ, number, raw)


def _follow_pointer(payload, endian, occupied, reads, fields, container, block_index, tag, typ, number, raw, kind: str) -> None:
    if typ != 4 or number != 1:
        raise _Stop("malformed")
    target = int.from_bytes(raw, endian)
    _parse_ifd(payload, target, endian, occupied, reads, fields, container, block_index, kind)


def _read_orientation(payload, endian, occupied, reads, fields, container, block_index, typ, number, raw) -> None:
    bucket = fields["orientation"]
    if typ != 3 or number != 1:
        bucket["malformed"] = True
        return
    value = int.from_bytes(raw[:2], endian)
    if value < 1 or value > 8:
        bucket["malformed"] = True
        return
    bucket["items"].append(_occurrence(str(value), container, block_index, 274))


def _read_text(payload, endian, occupied, reads, fields, container, block_index, name, tag, typ, number, raw) -> None:
    bucket = fields[name]
    if typ != 2 or number < 1 or number > MAX_TEXT_COUNT:
        bucket["malformed"] = True
        return
    data = _value_bytes(payload, endian, occupied, reads, typ, number, raw)
    if data is None:
        bucket["malformed"] = True
        return
    if name.startswith("date"):
        text = _date_text(data)
    else:
        text = _plain_text(data)
    if text is None:
        bucket["malformed"] = True
        return
    bucket["items"].append(_occurrence(text, container, block_index, tag))


def _read_gps_tag(payload, endian, occupied, reads, fields, container, block_index, tag, typ, number, raw) -> None:
    bucket = fields["gps"]
    expected = {1: (2, {1, 2}), 3: (2, {1, 2}), 5: (1, {1}), 2: (5, {3}), 4: (5, {3}), 6: (5, {1})}
    type_id, counts = expected[tag]
    if typ != type_id or number not in counts:
        bucket["malformed"] = True
        return
    data = _value_bytes(payload, endian, occupied, reads, typ, number, raw)
    if data is None:
        bucket["malformed"] = True
        return
    bucket.setdefault("tags", {}).setdefault(tag, []).append(data)
    bucket["container"] = container
    bucket["blockIndex"] = block_index
    bucket["endian"] = endian


def _value_bytes(payload, endian, occupied, reads, typ, number, raw) -> bytes | None:
    unit = _TYPE_SIZE.get(typ)
    if unit is None or number > (_UINT32_MAX // unit):
        raise _Stop("malformed")
    length = number * unit
    if length <= 4:
        return raw[:length]
    _account_read(reads)
    start = int.from_bytes(raw, endian)
    end = start + length
    _add_span(occupied, start, end, len(payload))
    return payload[start:end]


def _account_read(reads: list[int]) -> None:
    reads[0] += 1
    if reads[0] > MAX_VALUE_READS:
        raise _Stop("extraction_failed")


def _add_span(occupied: list[tuple[int, int]], start: int, end: int, limit: int) -> None:
    if start < _HEADER or end < start or end > limit:
        raise _Stop("malformed")
    for existing_start, existing_end in occupied:
        if start == existing_start or (start < existing_end and end > existing_start):
            raise _Stop("malformed")
    occupied.append((start, end))


def _occurrence(value: str, container: str, block_index: int, source_tag: int) -> dict:
    return {
        "value": value,
        "container": container,
        "blockIndex": block_index,
        "sourceTag": source_tag,
    }


def _plain_text(data: bytes) -> str | None:
    if data.endswith(b"\x00"):
        data = data[:-1]
    if b"\x00" in data or not data:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        return None
    if len(text) > MAX_TEXT_COUNT:
        return None
    return text


def _date_text(data: bytes) -> str | None:
    text = _plain_text(data)
    if text is None or len(text) != 19:
        return None
    if text[4] != ":" or text[7] != ":" or text[10] != " " or text[13] != ":" or text[16] != ":":
        return None
    parts = (text[0:4], text[5:7], text[8:10], text[11:13], text[14:16], text[17:19])
    if any(len(part) != (4 if index == 0 else 2) or not part.isdigit() for index, part in enumerate(parts)):
        return None
    _year, month, day, hour, minute, second = (int(part) for part in parts)
    if not (1 <= month <= 12 and 1 <= day <= 31 and 0 <= hour <= 23 and 0 <= minute <= 59 and 0 <= second <= 59):
        return None
    return text


def _merge_blocks(blocks: list[dict]) -> dict:
    fields = {}
    any_value = False
    gps_malformed = any(block["gps"].get("malformed") for block in blocks)
    for name in _FIELD_NAMES:
        if name == "gps":
            continue
        if any(block[name]["malformed"] for block in blocks):
            fields[name] = {"status": "malformed", "values": []}
            any_value = True
            continue
        items = [item for block in blocks for item in block[name]["items"]]
        if not items:
            fields[name] = {"status": "absent"}
            continue
        any_value = True
        fields[name] = _group_text(items)
    gps_items = []
    if not gps_malformed:
        for block in blocks:
            built = _gps_from_block(block["gps"])
            if built == "absent":
                continue
            if built == "malformed":
                gps_malformed = True
                gps_items = []
                break
            gps_items.extend(built)
    if gps_malformed:
        fields["gps"] = {"status": "malformed", "values": []}
        any_value = True
    elif not gps_items:
        fields["gps"] = {"status": "absent"}
    else:
        any_value = True
        fields["gps"] = _group_gps(gps_items)
    status = "extracted" if any_value or any(fields[name]["status"] == "malformed" for name in _FIELD_NAMES) else "no_supported_metadata"
    if status == "no_supported_metadata":
        fields = {name: {"status": "absent"} for name in _FIELD_NAMES}
    return {"status": status, "fields": fields}


def _group_text(items: list[dict]) -> dict:
    groups: list[dict] = []
    for item in items:
        found = next((group for group in groups if group["value"] == item["value"]), None)
        occurrence = {
            "container": item["container"],
            "blockIndex": item["blockIndex"],
            "sourceTag": item["sourceTag"],
        }
        if found is None:
            groups.append({"value": item["value"], "occurrences": [occurrence]})
        else:
            found["occurrences"].append(occurrence)
    status = "present" if len(groups) == 1 else "conflict"
    return {"status": status, "values": groups}


def _gps_from_block(bucket: dict):
    if bucket.get("malformed"):
        return "malformed"
    tags = bucket.get("tags")
    if not tags:
        return "absent"
    try:
        latitude_ref = _one_ref(tags.get(1), {b"N", b"N\x00", b"S", b"S\x00"})
        longitude_ref = _one_ref(tags.get(3), {b"E", b"E\x00", b"W", b"W\x00"})
        latitudes = _canonical_coordinates(tags.get(2), bucket["endian"], _LATITUDE_LIMIT)
        longitudes = _canonical_coordinates(tags.get(4), bucket["endian"], _LONGITUDE_LIMIT)
    except _GpsInvalid:
        return "malformed"
    if latitude_ref is None or longitude_ref is None or latitudes is None or longitudes is None:
        return "malformed"
    altitude_values, altitude_status, altitude_tags = _altitude(tags, bucket["endian"])
    if altitude_status == "malformed":
        return "malformed"
    if altitude_status != "present":
        altitude_values = [None]
    source_tags = {"latitude": 2, "latitudeRef": 1, "longitude": 4, "longitudeRef": 3}
    if altitude_status == "present":
        source_tags.update(altitude_tags)
    points = []
    for latitude in latitudes:
        if latitude_ref in {b"S", b"S\x00"} and latitude != "0.000000":
            latitude = "-" + latitude
        for longitude in longitudes:
            if longitude_ref in {b"W", b"W\x00"} and longitude != "0.000000":
                longitude = "-" + longitude
            for altitude in altitude_values:
                points.append({
                    "latitude": latitude,
                    "longitude": longitude,
                    "altitude": altitude,
                    "altitudeStatus": altitude_status,
                    "container": bucket.get("container", ""),
                    "blockIndex": bucket.get("blockIndex", 0),
                    "sourceTags": dict(source_tags),
                })
    return points


class _GpsInvalid(Exception):
    pass


def _one_ref(values, allowed: set[bytes]) -> bytes | None:
    if not values:
        return None
    if any(item not in allowed for item in values):
        raise _GpsInvalid()
    first = values[0]
    letter = first[:1]
    if any(item[:1] != letter for item in values):
        raise _GpsInvalid()
    return first


def _canonical_coordinates(values, endian: str, limit: int) -> list[str] | None:
    """Return unique validated coordinates in the order they were stored.

    Rationals are compared after DMS validation, so 10/1 and 20/2 are one
    value. Distinct validated coordinates stay separate for a conflict.
    """
    if not values:
        return None
    found: list[str] = []
    for item in values:
        parts = _rationals(item, endian, 3)
        if parts is None:
            raise _GpsInvalid()
        text = decimal_from_dms(parts[0], parts[1], parts[2], limit)
        if text is None:
            raise _GpsInvalid()
        if text not in found:
            found.append(text)
    return found


def _rationals(data: bytes, endian: str, count: int):
    width = 8 * count
    if len(data) != width:
        return None
    parts = []
    for index in range(count):
        start = index * 8
        numerator = int.from_bytes(data[start:start + 4], endian)
        denominator = int.from_bytes(data[start + 4:start + 8], endian)
        if denominator == 0:
            return None
        parts.append((numerator, denominator))
    return tuple(parts)


def _altitude(tags: dict, endian: str):
    has_value = 6 in tags
    has_ref = 5 in tags
    if not has_value and not has_ref:
        return None, "absent", {}
    if not has_value or not has_ref:
        return None, "malformed", {}
    refs = tags[5]
    if any(item not in {b"\x00", b"\x01"} for item in refs) or any(item != refs[0] for item in refs):
        return None, "malformed", {}
    texts: list[str] = []
    for item in tags[6]:
        parsed = _rationals(item, endian, 1)
        if parsed is None:
            return None, "malformed", {}
        pair = parsed[0]
        text = decimal_from_dms((pair[0], pair[1]), (0, 1), (0, 1), _ALTITUDE_LIMIT)
        if text is None:
            return None, "malformed", {}
        if refs[0] == b"\x01" and text != "0.000000":
            text = "-" + text
        if text not in texts:
            texts.append(text)
    return texts, "present", {"altitude": 6, "altitudeRef": 5}


def _group_gps(items: list[dict]) -> dict:
    groups: list[dict] = []
    for item in items:
        key = (item["latitude"], item["longitude"], item["altitude"], item["altitudeStatus"])
        found = next(
            (
                group for group in groups
                if (group["latitude"], group["longitude"], group["altitude"], group["altitudeStatus"]) == key
            ),
            None,
        )
        occurrence = {
            "container": item["container"],
            "blockIndex": item["blockIndex"],
            "sourceTags": item["sourceTags"],
        }
        if found is None:
            groups.append({
                "latitude": item["latitude"],
                "longitude": item["longitude"],
                "altitude": item["altitude"],
                "altitudeStatus": item["altitudeStatus"],
                "occurrences": [occurrence],
            })
        else:
            found["occurrences"].append(occurrence)
    status = "present" if len(groups) == 1 else "conflict"
    return {"status": status, "values": groups}


def _accept_dms(degrees, minutes, seconds, limit: int):
    deg_n, deg_d = degrees
    min_n, min_d = minutes
    sec_n, sec_d = seconds
    if 0 in (deg_d, min_d, sec_d):
        return None
    if min_n >= 60 * min_d or sec_n >= 60 * sec_d:
        return None
    if deg_n > limit * deg_d:
        return None
    if deg_n == limit * deg_d and (min_n != 0 or sec_n != 0):
        return None
    numerator = deg_n * min_d * sec_d * 3600 + min_n * deg_d * sec_d * 60 + sec_n * deg_d * min_d
    denominator = deg_d * min_d * sec_d * 3600
    if numerator > _ARITHMETIC_MAX or denominator > _ARITHMETIC_MAX:
        return None
    if numerator > limit * denominator:
        return None
    return numerator, denominator


def _round_half_away(numerator: int, denominator: int, scale: int) -> int | None:
    if denominator <= 0 or scale <= 0:
        return None
    scaled = numerator * scale
    if scaled > _ARITHMETIC_MAX:
        return None
    quotient, remainder = divmod(scaled, denominator)
    if remainder * 2 >= denominator:
        quotient += 1
    return quotient


def _format_scaled(value: int, places: int) -> str:
    scale = 10 ** places
    whole, frac = divmod(abs(value), scale)
    text = f"{whole}.{frac:0{places}d}"
    if value < 0 and text != f"0.{'0' * places}":
        return "-" + text
    return text


def _u16(payload: bytes, offset: int, endian: str) -> int:
    return int.from_bytes(payload[offset:offset + 2], endian)


def _u32(payload: bytes, offset: int, endian: str) -> int:
    return int.from_bytes(payload[offset:offset + 4], endian)


def _public_consent(value) -> dict:
    if not isinstance(value, dict):
        return {
            "uploadConsentVersion": "",
            "metadataConsentVersion": "",
            "metadataConsentDecision": "",
            "metadataConsentAt": "",
        }
    return {
        "uploadConsentVersion": value.get("uploadConsentVersion") if isinstance(value.get("uploadConsentVersion"), str) else "",
        "metadataConsentVersion": value.get("metadataConsentVersion") if isinstance(value.get("metadataConsentVersion"), str) else "",
        "metadataConsentDecision": value.get("metadataConsentDecision") if isinstance(value.get("metadataConsentDecision"), str) else "",
        "metadataConsentAt": value.get("metadataConsentAt") if isinstance(value.get("metadataConsentAt"), str) else "",
    }


def _public_text_field(value) -> dict:
    if not isinstance(value, dict):
        return {"status": "malformed", "values": []}
    status = value.get("status")
    if status == "absent":
        return {"status": "absent"}
    if status not in {"present", "conflict", "malformed"}:
        return {"status": "malformed", "values": []}
    if status == "malformed":
        return {"status": "malformed", "values": []}
    values = []
    for item in value.get("values") or []:
        if not isinstance(item, dict) or not isinstance(item.get("value"), str):
            return {"status": "malformed", "values": []}
        if len(item["value"]) > MAX_TEXT_COUNT:
            return {"status": "malformed", "values": []}
        occurrences = _public_text_occurrences(item.get("occurrences"))
        if occurrences is None:
            return {"status": "malformed", "values": []}
        values.append({"value": item["value"], "occurrences": occurrences})
    if status == "present" and len(values) != 1:
        return {"status": "malformed", "values": []}
    if status == "conflict" and len(values) < 2:
        return {"status": "malformed", "values": []}
    return {"status": status, "values": values}


def _public_text_occurrences(value):
    if not isinstance(value, list) or not value:
        return None
    occurrences = []
    for item in value:
        if not isinstance(item, dict):
            return None
        occurrences.append({
            "container": item.get("container") if isinstance(item.get("container"), str) else "",
            "blockIndex": item.get("blockIndex") if isinstance(item.get("blockIndex"), int) and not isinstance(item.get("blockIndex"), bool) else 0,
            "sourceTag": item.get("sourceTag") if isinstance(item.get("sourceTag"), int) and not isinstance(item.get("sourceTag"), bool) else 0,
        })
    return occurrences


def _public_gps(value) -> dict:
    if not isinstance(value, dict):
        return {"status": "malformed", "values": []}
    status = value.get("status")
    if status == "absent":
        return {"status": "absent"}
    if status == "malformed":
        return {"status": "malformed", "values": []}
    if status not in {"present", "conflict"}:
        return {"status": "malformed", "values": []}
    public_values = []
    for item in value.get("values") or []:
        if not isinstance(item, dict):
            return {"status": "malformed", "values": []}
        latitude = _mask_coordinate(item.get("latitude"), 9000)
        longitude = _mask_coordinate(item.get("longitude"), 18000)
        if latitude is None or longitude is None:
            return {"status": "malformed", "values": []}
        occurrences = []
        for occurrence in item.get("occurrences") or []:
            if not isinstance(occurrence, dict):
                return {"status": "malformed", "values": []}
            occurrences.append({
                "container": occurrence.get("container") if isinstance(occurrence.get("container"), str) else "",
                "blockIndex": occurrence.get("blockIndex") if isinstance(occurrence.get("blockIndex"), int) and not isinstance(occurrence.get("blockIndex"), bool) else 0,
                "sourceTags": _source_tags(occurrence.get("sourceTags")),
            })
        if not occurrences:
            return {"status": "malformed", "values": []}
        public_values.append({
            "latitude": latitude,
            "longitude": longitude,
            "occurrences": occurrences,
        })
    if status == "present" and len(public_values) != 1:
        return {"status": "malformed", "values": []}
    if status == "conflict" and len(public_values) < 2:
        return {"status": "malformed", "values": []}
    return {"status": status, "values": public_values}


def _gps_was_readable(value) -> bool:
    return isinstance(value, dict) and value.get("status") in {"present", "conflict", "malformed"}


def _accepted_altitude(value) -> str | None:
    """Accept one sealed altitude through 100000.000000, including a sign."""
    if not isinstance(value, str) or _ALTITUDE_TEXT.fullmatch(value) is None:
        return None
    body = value[1:] if value.startswith("-") else value
    whole, frac = body.split(".")
    micro = int(whole) * 1_000_000 + int(frac)
    if micro > _ALTITUDE_MICRO_MAX:
        return None
    return value


def _mask_coordinate(value, limit_q: int) -> str | None:
    if not isinstance(value, str) or _SIX_DECIMAL.fullmatch(value) is None:
        return None
    sign = value.startswith("-")
    whole, frac = value[1:].split(".") if sign else value.split(".")
    micro = int(whole) * 1_000_000 + int(frac)
    quotient, remainder = divmod(micro, 10_000)
    if remainder * 2 >= 10_000:
        quotient += 1
    if quotient > limit_q:
        return None
    shown = f"{quotient // 100}.{quotient % 100:02d}"
    if quotient == 0:
        return "0.00"
    return f"-{shown}" if sign else shown


def _source_tags(value) -> dict:
    if not isinstance(value, dict):
        return {}
    clean = {}
    for key, item in value.items():
        if isinstance(key, str) and isinstance(item, int) and not isinstance(item, bool):
            clean[key] = item
    return clean


def seal_metadata(parsed: dict, consent_version: str, metadata_version: str, decision: str, decided_at: str) -> dict:
    """Attach the asset's stored consent to a parser result."""
    status = parsed.get("status") if isinstance(parsed, dict) else None
    if status not in _FILE_STATUSES or status == "not_extracted":
        status = "extraction_failed"
    fields = {}
    if status in {"extracted", "no_supported_metadata"} and isinstance(parsed.get("fields"), dict):
        fields = parsed["fields"]
    return {
        "version": METADATA_VERSION,
        "status": status,
        "consent": {
            "uploadConsentVersion": consent_version if isinstance(consent_version, str) else "",
            "metadataConsentVersion": metadata_version if isinstance(metadata_version, str) else "declined",
            "metadataConsentDecision": decision if isinstance(decision, str) else "omitted",
            "metadataConsentAt": decided_at if isinstance(decided_at, str) else "",
        },
        "fields": fields,
    }
