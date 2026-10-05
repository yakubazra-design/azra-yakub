"""Investigation prompts ported verbatim from frontend/engine.js RC.reasoning.

Do not rewrite these strings. Only the transport around them changes.
"""

from app.textutil import host_of


def extract_claims_prompt(material: str, kind: str) -> str:
    submitted = "web page text" if kind == "url" else "text"
    body = str(material)[:6000]
    return (
        "You are the claim-analysis stage of an evidence-investigation tool.\n"
        "Read the submitted " + submitted + " and identify only the factual assertions that could in principle be checked against evidence.\n\n"
        "Rules:\n"
        "- Opinions, predictions, questions and subjective statements are NOT factual claims.\n"
        "- Do not evaluate whether anything is true. Only identify what is being asserted.\n"
        "- Write each verifiable point so it can stand alone.\n"
        "- Search queries should be short and neutral, not leading.\n\n"
        "SUBMITTED MATERIAL:\n\"\"\"\n" + body + "\n\"\"\"\n\n"
        "Reply with JSON only, no prose and no code fences:\n"
        '{"hasFactualClaim":boolean,"primaryClaim":string,"verifiablePoints":[string],'
        '"excluded":[{"text":string,"reason":string}],"searchQueries":[string]}'
    )


def _catalogue(sources: list) -> str:
    lines = []
    for i, src in enumerate(sources):
        quality = src.get("quality") or {}
        tier = quality.get("tier")
        published = src.get("publishedAt") or "not available"
        title = src.get("title") or "not available"
        snippet = str(src.get("snippet") or "")[:700]
        lines.append(
            "[" + str(i) + "] host=" + host_of(src.get("url") or "")
            + " | quality=" + str(tier)
            + " | date=" + str(published)
            + " | title=" + str(title)
            + "\n     text: " + snippet
        )
    return "\n".join(lines)


def _image_block(image_evidence) -> str:
    if not image_evidence:
        return ""
    ie = image_evidence
    width = ie.get("width")
    height = ie.get("height")
    dimensions = f"{width}x{height}" if width and height else "not available"
    orientation = ie.get("orientation")
    orientation_text = orientation if orientation is not None else "not available"
    lat = ie.get("gpsLat")
    lon = ie.get("gpsLon")
    if lat is not None:
        gps = f"{float(lat):.6f},{float(lon):.6f}"
    else:
        gps = "not available"
    return (
        "\nIMAGE EVIDENCE (extracted locally from an uploaded file by the person — never sent to, or checked against, any web source; not part of the numbered SOURCES list above and must never be cited with a [number]):\n"
        "  file=" + str(ie.get("fileName")) + " | type=" + str(ie.get("fileType")) + " | dimensions=" + dimensions + "\n"
        "  EXIF capture date=" + str(ie.get("captureDate") or "not available")
        + " | camera make=" + str(ie.get("make") or "not available")
        + " | camera model=" + str(ie.get("model") or "not available") + "\n"
        "  orientation=" + str(orientation_text)
        + " | editing/creation software (EXIF)=" + str(ie.get("software") or "not available") + "\n"
        "  GPS=" + gps + " | file hash (SHA-256)=" + str(ie.get("sha256") or "not computed") + "\n"
        "Rules for image evidence, all mandatory:\n"
        "- If an EXIF capture date IS present, you may treat it as supporting metadata evidence for a date-related claim, but it is self-reported by the file and can be edited or wrong — do not treat it as proof on its own, especially with no corroborating web source.\n"
        "- If an EXIF capture date is NOT available, say exactly that the capture date could not be established from EXIF — this is an absence of one kind of evidence, never itself evidence that the claimed date is wrong. Never phrase it as \"the photo was not taken in [year]\".\n"
        "- Missing or stripped EXIF, or the presence of editing-software metadata, is never itself evidence of manipulation — do not use POTENTIAL_MANIPULATION on this basis alone.\n"
        "- The SHA-256 hash identifies this exact file. It establishes nothing about when or where the photo was taken.\n"
        "- Keep \"no EXIF date available\" and \"no web source dated this\" as two distinct statements if both apply. Never merge them into one sentence that blurs which kind of evidence was checked.\n"
    )


def _index_list(indexes) -> str:
    return ",".join("[" + str(i) + "]" for i in indexes)


def assess_prompt(ctx: dict) -> str:
    sources = ctx.get("sources") or []
    points = ctx.get("verifiablePoints") or []
    independence = ctx.get("independence") or {}
    timeline = ctx.get("timeline") or {}
    catalogue = _catalogue(sources)
    image_block = _image_block(ctx.get("imageEvidence"))

    point_lines = "\n".join(str(i + 1) + ". " + str(p) for i, p in enumerate(points))
    host_groups = independence.get("hostGroups") or []
    origin_groups = independence.get("originGroups") or []
    uncertain = independence.get("uncertainIndexes") or []
    entries = timeline.get("entries") or []

    host_text = ""
    if host_groups:
        host_text = " Same-publisher groups: " + "; ".join(
            str(g.get("host")) + "=" + _index_list(g.get("indexes") or []) for g in host_groups
        ) + "."
    origin_text = ""
    if origin_groups:
        origin_text = " Shared-origin groups (sources explicitly attributing the same original release/organisation): " + "; ".join(
            str(g.get("origin")) + "=" + _index_list(g.get("indexes") or []) for g in origin_groups
        ) + "."
    uncertain_text = ""
    if uncertain:
        uncertain_text = (
            " Possible-but-unconfirmed shared origin (similar titles, not corroborated by a matching author or identifier): sources "
            + ", ".join("[" + str(i) + "]" for i in uncertain)
            + ". Treat these as still separately counted, but mention the uncertainty rather than asserting they are independent confirmations or asserting they are duplicates."
        )

    timeline_text = (
        "; ".join(
            str(e.get("date")) + " — " + str(e.get("desc")) + " (" + str(e.get("certainty")) + ")"
            for e in entries
        )
        if entries
        else "no publication dates were available"
    )

    return (
        "You are the assessment stage of an evidence-investigation tool. You must reason ONLY from the numbered sources and the image evidence (if present) below.\n\n"
        "Absolute rules:\n"
        "- Never introduce a source, URL, date, study or organisation that is not in the list.\n"
        "- Refer to web sources only by their number. Refer to image evidence by name, never by a [number].\n"
        "- Repetition is not confirmation. Sources flagged as sharing wording must not be counted as separate confirmation.\n"
        "- Do not weigh by count. One HIGH-quality source can outweigh several LOW or UNKNOWN ones.\n"
        "- If the evidence does not settle the question, say so. Do not manufacture certainty.\n\n"
        "CLAIM: " + str(ctx.get("primaryClaim") or "") + "\n"
        "VERIFIABLE POINTS:\n" + point_lines + "\n\n"
        "SOURCES:\n" + (catalogue or "(none)") + "\n"
        + image_block + "\n"
        "INDEPENDENCE CHECK: " + str(independence.get("totalSources")) + " source(s) retrieved, "
        + str(independence.get("uniqueHostCount")) + " distinct publisher(s), "
        + str(independence.get("independentCount")) + " counted as independent after grouping. "
        + str(independence.get("note") or "")
        + host_text
        + origin_text
        + uncertain_text + "\n"
        "Treat every source inside the same same-publisher, same-DOI, or shared-origin group as ONE piece of evidence, not one each. "
        "Two independent outlets that separately reported the same event in their own words are still separate evidence — do not merge sources just because they cover the same topic; only merge where a group above says to.\n"
        "TIMELINE: " + timeline_text
        + "\nSources with no publication date: " + str(timeline.get("missingCount")) + "\n\n"
        "Reason from all of: the relevance of each piece of evidence, source quality, publisher diversity, apparent independence after grouping, shared-origin/echo information, contradictions, date and timeline consistency, and what remains uncertain. "
        "Never reason as if N retrieved sources means N independent confirmations.\n"
        "Choose exactly one assessment from: VERIFIED, PARTIALLY_VERIFIED, CONTRADICTED, INSUFFICIENT_EVIDENCE, POTENTIAL_MANIPULATION, UNRESOLVED.\n"
        "Use POTENTIAL_MANIPULATION only where the sources give a concrete indicator that the material was altered or misleadingly presented — not merely because something looks doubtful.\n"
        "Use UNRESOLVED where credible sources meaningfully conflict and the conflict cannot be settled.\n\n"
        "Write the explanation for a general reader, in plain sentences.\n\n"
        "CLASSIFYING EACH FINDING — use exactly one of these four types, and do not blur them:\n"
        '- "support": the source explicitly establishes the claim itself.\n'
        '- "contradict": the source explicitly establishes a fact incompatible with the claim — e.g. it directly denies the specific thing claimed, or documents that a specific claimed event/discovery did not happen or does not exist.\n'
        '- "inconsistent": the source is genuinely relevant but describes something DIFFERENT from what is claimed, in a way that makes the claim less supported without directly disproving it. This is the correct type when a claim asserts something specific (e.g. an artificial structure, a discovery) and the evidence instead documents a related but distinct phenomenon (e.g. natural geological or environmental features) — that is not a contradiction of the specific claim, it is an absence of matching evidence plus a different observed reality. Never upgrade this to "contradict".\n'
        '- "caution": a note about source reliability, methodology, or ambiguity — not itself evidence for or against the claim.\n'
        'If no source addresses the specific thing claimed at all, that is absence of evidence, not a contradiction — do not manufacture a "contradict" finding to fill the gap; let the assessment be INSUFFICIENT_EVIDENCE and say so in "why.contradicting" (e.g. "no source directly addresses this claim, so nothing here contradicts it either").\n\n'
        "Reply with JSON only, no prose and no code fences:\n"
        '{"assessment":string,'
        '"findings":[{"type":"support"|"contradict"|"inconsistent"|"caution","text":string,"sources":[number]}],'
        '"originalMaterial":{"established":boolean,"description":string,"source":number|null},'
        '"why":{"supporting":string,"contradicting":string,"sourceQuality":string,"timeline":string,"uncertain":string,"choice":string},'
        '"uncertainty":[string]}'
    )
