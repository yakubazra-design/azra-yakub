"""Fixed request limits.

Login and registration are counted per TCP peer address. A client-supplied
forwarding header is not the key. The other buckets are counted per
authenticated user. These are the application defaults.
"""

MAX_BODY_BYTES = 64 * 1024
MAX_IMAGE_BYTES = 8 * 1024 * 1024
# V1.2.A video ingest (feature-flagged off by default). 100 MiB exact.
MAX_VIDEO_BYTES = 100 * 1024 * 1024
MAX_VIDEO_DURATION_MS = 180_000
MAX_VIDEO_WIDTH = 1920
MAX_VIDEO_HEIGHT = 1080
MAX_VIDEO_PIXELS = 1920 * 1080
MAX_VIDEO_FRAME_RATE = 60.0
MAX_VIDEO_BITRATE_BPS = 20_000_000
MAX_VIDEO_AUDIO_STREAMS = 1

# bucket: (maximum requests, window in seconds)
LIMITS = {
    "login": (10, 15 * 60),
    "register": (5, 60 * 60),
    "investigation": (30, 60 * 60),
    "search": (60, 60 * 60),
    "fetch": (30, 60 * 60),
    "extract": (60, 60 * 60),
    "seal": (60, 60 * 60),
    "assess": (30, 60 * 60),
    "evidence": (120, 60 * 60),
    "asset": (20, 60 * 60),
    "gps_reveal": (30, 60 * 60),
    "video_asset": (5, 60 * 60),
}
