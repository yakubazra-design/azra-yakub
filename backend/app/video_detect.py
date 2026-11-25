"""Identify an allowed video container from leading bytes.

The browser-reported type and filename extension are not used. This does
not decode the media and does not judge authenticity.
"""

from __future__ import annotations

VIDEO_CONSENT_VERSION = "video-upload-1"
VIDEO_METADATA_CONSENT_VERSION = "video-metadata-1"
VIDEO_REMOVE_CONFIRM = "remove-video-1"

# Attachment states (V1.2.2E).
ATTACHMENT_READY = "ready"
ATTACHMENT_MISSING = "missing"
ATTACHMENT_INTEGRITY_FAILED = "integrity_failed"
ATTACHMENT_RETIRING = "retiring"
ATTACHMENT_REMOVED_BY_USER = "removed_by_user"

ATTACHMENT_STATES = frozenset({
    ATTACHMENT_READY,
    ATTACHMENT_MISSING,
    ATTACHMENT_INTEGRITY_FAILED,
    ATTACHMENT_RETIRING,
    ATTACHMENT_REMOVED_BY_USER,
})

ALLOWED_VIDEO_CODECS = frozenset({"h264", "vp8", "vp9"})
ALLOWED_AUDIO_CODECS = frozenset({"aac", "opus", "vorbis"})
REJECTED_VIDEO_CODECS = frozenset({"hevc", "h265", "av1", "av01"})


def detect_video_container(data: bytes) -> str | None:
    """Return a supported video media type from a prefix, or None.

    Requires enough leading bytes for a confident sniff (typically the first
    64 KiB of an upload). Classic QuickTime without an ``ftyp`` box is
    rejected. Ambiguous or unsupported containers return None.
    """
    if not isinstance(data, (bytes, bytearray)) or len(data) < 12:
        return None
    blob = bytes(data)
    webm = _webm(blob)
    if webm:
        return webm
    return _iso_bmff(blob)


def _webm(data: bytes) -> str | None:
    # EBML header 0x1A45DFA3
    if data[:4] != b"\x1a\x45\xdf\xa3":
        return None
    # Require DocType "webm" somewhere in the first window (fail closed for matroska-only).
    window = data[: min(len(data), 256)]
    if b"webm" in window.lower():
        return "video/webm"
    return None


def _iso_bmff(data: bytes) -> str | None:
    """MP4 / QuickTime with an ftyp box at a small offset."""
    # Scan a few top-level boxes for ftyp (usually at 0).
    pos = 0
    limit = min(len(data), 64 * 1024)
    while pos + 8 <= limit:
        size = int.from_bytes(data[pos:pos + 4], "big")
        box = data[pos + 4:pos + 8]
        if size == 1:
            if pos + 16 > limit:
                return None
            size = int.from_bytes(data[pos + 8:pos + 16], "big")
            header = 16
        elif size == 0:
            size = limit - pos
            header = 8
        else:
            header = 8
        if size < header or pos + size > len(data) and pos + header > limit:
            # Incomplete size in prefix — cannot confirm.
            if box == b"ftyp" and pos + header + 4 <= limit:
                return _ftyp_brand(data[pos + header:pos + min(pos + size, limit)])
            return None
        if box == b"ftyp":
            end = pos + size if pos + size <= len(data) else limit
            return _ftyp_brand(data[pos + header:end])
        if size <= 0:
            return None
        pos += size
        if pos > limit:
            break
    return None


def _ftyp_brand(payload: bytes) -> str | None:
    if len(payload) < 4:
        return None
    major = payload[:4]
    compat = payload[8:] if len(payload) >= 8 else b""
    brands = {major}
    for i in range(0, len(compat) - 3, 4):
        brands.add(compat[i:i + 4])
    # QuickTime
    if b"qt  " in brands:
        return "video/quicktime"
    # Common MP4 brands
    mp4_brands = {
        b"isom", b"iso2", b"iso3", b"iso4", b"iso5", b"iso6",
        b"mp41", b"mp42", b"avc1", b"dash", b"msdh", b"m4v ",
    }
    if brands & mp4_brands:
        return "video/mp4"
    # Major brand alone sometimes is isom family
    if major in mp4_brands:
        return "video/mp4"
    return None


def classify_video_metadata_consent(header: str | None) -> tuple[str, str] | None:
    """Return (version, decision) or None when the header is invalid."""
    if header is None or str(header).strip() == "":
        return ("declined", "omitted")
    text = str(header).strip()
    if text == "declined":
        return ("declined", "declined")
    if text == VIDEO_METADATA_CONSENT_VERSION:
        return (VIDEO_METADATA_CONSENT_VERSION, "accepted")
    return None


def codec_allowed(video_codec: str | None, audio_codec: str | None) -> str | None:
    """Return a failure code if codecs are disallowed, else None."""
    vc = (video_codec or "").strip().lower()
    ac = (audio_codec or "").strip().lower()
    if not vc:
        return "no_video_stream"
    if vc in REJECTED_VIDEO_CODECS or vc.startswith("hev") or vc.startswith("av1"):
        if "av1" in vc or vc == "av01":
            return "av1_not_allowed"
        return "hevc_not_allowed"
    if vc not in ALLOWED_VIDEO_CODECS:
        return "codec_not_allowed"
    if ac and ac not in ALLOWED_AUDIO_CODECS:
        return "codec_not_allowed"
    return None
