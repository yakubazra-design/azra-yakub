"""Identify a raster image from its bytes.

The browser-reported type is not used. A file that does not match one of
the supported structures is rejected. This does not judge whether the
picture was edited.
"""

import re
import struct
import zlib

_SHA256 = re.compile(r"[0-9a-f]{64}")
IMAGE_CONSENT_VERSION = "image-upload-1"
_JPEG_SOF = {0xC0, 0xC1, 0xC2}
_WEBP_CHUNKS = {b"VP8 ", b"VP8L", b"VP8X"}


def client_hash_status(supplied: str, server_digest: str) -> str:
    """Compare an untrusted client hash with the server digest.

    The client value is never returned and never becomes the stored identity.
    """
    text = str(supplied or "").strip().lower()
    if not text:
        return "not_supplied"
    if _SHA256.fullmatch(text) is None:
        return "unusable"
    if text == server_digest:
        return "match"
    return "mismatch"


def detect_image(data: bytes) -> str | None:
    """Return the media type of a complete supported image, or None."""
    if not isinstance(data, (bytes, bytearray)) or not data:
        return None
    blob = bytes(data)
    if _jpeg(blob):
        return "image/jpeg"
    if _png(blob):
        return "image/png"
    if _gif(blob):
        return "image/gif"
    if _webp(blob):
        return "image/webp"
    return None


def _jpeg(data: bytes) -> bool:
    if len(data) < 4 or data[:3] != b"\xff\xd8\xff":
        return False
    pos = 2
    saw_frame = False
    while pos < len(data):
        if data[pos] != 0xFF:
            return False
        while pos < len(data) and data[pos] == 0xFF:
            pos += 1
        if pos >= len(data):
            return False
        marker = data[pos]
        pos += 1
        if marker == 0xD9:
            return saw_frame and pos == len(data)
        if marker == 0xDA:
            while pos + 1 < len(data):
                if data[pos] == 0xFF and data[pos + 1] not in (0x00, 0xFF):
                    if data[pos + 1] == 0xD9:
                        return saw_frame and pos + 2 == len(data)
                    return False
                pos += 1
            return False
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            continue
        if pos + 2 > len(data):
            return False
        length = int.from_bytes(data[pos:pos + 2], "big")
        if length < 2 or pos + length > len(data):
            return False
        if marker in _JPEG_SOF:
            saw_frame = True
        pos += length
    return False


def _png(data: bytes) -> bool:
    if len(data) < 8 or data[:8] != b"\x89PNG\r\n\x1a\n":
        return False
    pos = 8
    saw_header = False
    while pos + 12 <= len(data):
        length = int.from_bytes(data[pos:pos + 4], "big")
        tag = data[pos + 4:pos + 8]
        crc_start = pos + 4
        chunk_end = pos + 12 + length
        if length < 0 or chunk_end > len(data):
            return False
        expected = zlib.crc32(data[crc_start:chunk_end - 4]) & 0xFFFFFFFF
        actual = int.from_bytes(data[chunk_end - 4:chunk_end], "big")
        if expected != actual:
            return False
        if tag == b"IHDR":
            if saw_header or length != 13 or pos != 8:
                return False
            width, height = struct.unpack(">II", data[pos + 8:pos + 16])
            if width < 1 or height < 1:
                return False
            saw_header = True
        elif tag == b"IEND":
            return saw_header and length == 0 and chunk_end == len(data)
        pos = chunk_end
    return False


def _gif(data: bytes) -> bool:
    if len(data) < 13 or data[:6] not in (b"GIF87a", b"GIF89a"):
        return False
    pos = 13
    if data[10] & 0x80:
        pos += 3 * (2 << (data[10] & 7))
    if pos > len(data):
        return False
    saw_image = False
    while pos < len(data):
        marker = data[pos]
        pos += 1
        if marker == 0x3B:
            return saw_image and pos == len(data)
        if marker == 0x21:
            if pos >= len(data):
                return False
            pos += 1
            pos = _subblocks(data, pos)
        elif marker == 0x2C:
            if pos + 9 > len(data):
                return False
            packed = data[pos + 8]
            pos += 9
            if packed & 0x80:
                pos += 3 * (2 << (packed & 7))
            if pos >= len(data):
                return False
            pos += 1
            pos = _subblocks(data, pos)
            saw_image = True
        else:
            return False
        if pos is None:
            return False
    return False


def _subblocks(data: bytes, pos: int) -> int | None:
    while pos < len(data):
        size = data[pos]
        pos += 1
        if size == 0:
            return pos
        pos += size
        if pos > len(data):
            return None
    return None


def _webp(data: bytes) -> bool:
    if len(data) < 20 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        return False
    declared = int.from_bytes(data[4:8], "little")
    if declared + 8 != len(data) or declared < 12:
        return False
    pos = 12
    saw_image = False
    while pos + 8 <= len(data):
        chunk = data[pos:pos + 4]
        chunk_size = int.from_bytes(data[pos + 4:pos + 8], "little")
        pos += 8 + chunk_size + (chunk_size & 1)
        if pos > len(data):
            return False
        if chunk in _WEBP_CHUNKS:
            saw_image = True
    return saw_image and pos == len(data)
