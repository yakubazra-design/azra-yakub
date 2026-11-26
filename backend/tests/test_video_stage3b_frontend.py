"""Stage 3.B.2B — frontend Video Evidence presentation string/DOM contract tests.

Does not enable video ingestion. Does not call providers. Does not open the live ledger.
Does not modify the Git stash.
"""

from pathlib import Path

from app.image_evidence import RETENTION_STATEMENT

FRONTEND = Path(__file__).resolve().parents[2] / "frontend"
ENGINE = FRONTEND / "engine.js"
STYLES = FRONTEND / "styles.css"

VIDEO_DISCLAIMER = (
    "This information describes the identity and technical properties of the uploaded file. "
    "It does not establish authenticity, original recording time, publication history, "
    "or the truth of any claim."
)
RETAINED = (
    "The sealed file was present and its file identity was checked when this presentation was generated."
)
DELETED = (
    "The sealed file identity remains recorded, but the original uploaded file is no longer retained."
)
UNAVAILABLE = "The sealed file could not be confirmed against the retained bytes."


def _engine() -> str:
    assert ENGINE.is_file(), "frontend/engine.js must be materialized before these tests"
    return ENGINE.read_text(encoding="utf-8")


def test_video_evidence_section_and_helpers_exist():
    script = _engine()
    assert "function serverVideoEvidence" in script
    assert "function renderVideoEvidence" in script
    assert "function videoAvailabilityCopy" in script
    assert "function videoTechnicalBlock" in script
    assert "function sha256Row" in script
    assert "id = 'video-evidence'" in script or 'id = "video-evidence"' in script
    assert "video-evidence-sha256" in script
    assert "videoEvidence: serverVideoEvidence(r.videoEvidence)" in script


def test_no_video_and_invalid_evidence_rejected_by_server_projector():
    script = _engine()
    assert "value.version !== 'video-evidence-1'" in script
    assert "!/^[0-9a-f]{64}$/.test(identity.sha256)" in script
    # Missing/null videoEvidence yields null from serverVideoEvidence and is not rendered.
    assert "if (r.videoEvidence)" in script
    assert "renderVideoEvidence(r.videoEvidence)" in script


def test_full_sha256_and_copy_controls():
    script = _engine()
    assert "Copy SHA-256" in script
    assert "copyTextToClipboard" in script
    assert "navigator.clipboard" in script
    assert "aria-label', 'Copy SHA-256 file identity'" in script
    assert "identifies the exact sealed file bytes only" in script
    styles = STYLES.read_text(encoding="utf-8")
    assert "video-evidence-hash-value" in styles
    assert "overflow-wrap: anywhere" in styles or "word-break: break-word" in styles


def test_approved_availability_wording_and_disclaimer():
    script = _engine()
    assert RETAINED in script
    assert DELETED in script
    assert UNAVAILABLE in script
    assert VIDEO_DISCLAIMER in script
    # Image availability copy must remain distinct where it conflicts.
    assert "This check does not show whether the file is still stored." in script
    assert script.index(RETAINED) != script.index(
        "This check does not show whether the file is still stored."
    )


def test_selective_metadata_and_consent_paths():
    script = _engine()
    assert "function videoTechnicalBlock" in script
    assert "not_disclosed" in script
    assert "Duration" in script
    assert "Video codec" in script
    assert "Audio codec" in script
    video_render = script.split("function renderVideoEvidence")[1].split(
        "function renderEmbeddedMetadata"
    )[0]
    tech_block = script.split("function videoTechnicalBlock")[1].split("var PROVENANCE_EVENT_TEXT")[0]
    for blob in (video_render, tech_block):
        assert "formatName" not in blob
        assert "frameRate" not in blob
        assert "bitRate" not in blob
        assert "assets/video" not in blob
        assert "storageName" not in blob
    assert "Genuine video" not in script
    assert "Authentic video" not in script
    assert "Verified original" not in script
    assert "Proven real" not in script
    assert "Manipulated video" not in script
    assert "No authenticity verdict is produced" in script


def test_assess_request_remains_token_only_and_image_evidence_unchanged():
    script = _engine()
    assess_request = script.split("function assess")[1].split("function validate")[0]
    assert "assessmentToken: sealed.assessmentToken" in assess_request
    assert "videoEvidence:" not in assess_request
    assert "sealedVideo:" not in assess_request
    assert "imageEvidence:" not in assess_request
    assert "function renderImageEvidence" in script
    assert "function serverImageEvidence" in script
    assert RETENTION_STATEMENT in script
    assert "Local image metadata on this device" in script
    assert "not server-verified evidence" in script
    assert "image-evidence-sha256" in script
    # Placement: video after image evidence, before evidence chain.
    image_pos = script.index("renderImageEvidence(r.imageEvidence)")
    video_pos = script.index("renderVideoEvidence(r.videoEvidence)")
    chain_pos = script.index("section('Evidence chain')")
    assert image_pos < video_pos < chain_pos


def test_historical_projection_uses_validate_server_fields():
    script = _engine()
    # Historical/current assessment responses both pass through validate → serverVideoEvidence.
    validate_body = script.split("function validate(r, sourceCount)")[1].split(
        "function serverEmbeddedMetadata"
    )[0]
    assert "videoEvidence: serverVideoEvidence(r.videoEvidence)" in validate_body
    assert "imageEvidence: serverImageEvidence(r.imageEvidence)" in validate_body
