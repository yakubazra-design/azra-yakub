"""Assessment validation copied from frontend/engine.js RC.reasoning.validate."""

VALID_ASSESSMENTS = [
    "VERIFIED",
    "PARTIALLY_VERIFIED",
    "CONTRADICTED",
    "INSUFFICIENT_EVIDENCE",
    "POTENTIAL_MANIPULATION",
    "UNRESOLVED",
]
FINDING_TYPES = ["support", "contradict", "inconsistent", "caution"]


def _is_index(n, source_count: int) -> bool:
    return isinstance(n, int) and not isinstance(n, bool) and 0 <= n < source_count


def validate_assessment(raw, source_count: int) -> dict:
    r = raw if isinstance(raw, dict) else {}
    assessment = r.get("assessment") if r.get("assessment") in VALID_ASSESSMENTS else "UNRESOLVED"
    if source_count == 0:
        assessment = "INSUFFICIENT_EVIDENCE"

    findings = []
    for f in r.get("findings") if isinstance(r.get("findings"), list) else []:
        if not isinstance(f, dict):
            continue
        text = str(f.get("text") or "").strip()
        if not text:
            continue
        sources = f.get("sources") if isinstance(f.get("sources"), list) else []
        findings.append({
            "type": f.get("type") if f.get("type") in FINDING_TYPES else "caution",
            "text": text,
            "sources": [n for n in sources if _is_index(n, source_count)],
        })

    om = r.get("originalMaterial") if isinstance(r.get("originalMaterial"), dict) else {}
    source = om.get("source")
    original = {
        "established": bool(om.get("established")) and _is_index(source, source_count),
        "description": str(om.get("description") or "").strip(),
        "source": source if _is_index(source, source_count) else None,
    }

    why = r.get("why") if isinstance(r.get("why"), dict) else {}
    uncertainty = r.get("uncertainty") if isinstance(r.get("uncertainty"), list) else []
    return {
        "assessment": assessment,
        "findings": findings,
        "originalMaterial": original,
        "why": {
            "supporting": str(why.get("supporting") or "").strip(),
            "contradicting": str(why.get("contradicting") or "").strip(),
            "sourceQuality": str(why.get("sourceQuality") or "").strip(),
            "timeline": str(why.get("timeline") or "").strip(),
            "uncertain": str(why.get("uncertain") or "").strip(),
            "choice": str(why.get("choice") or "").strip(),
        },
        "uncertainty": [s for s in (str(u).strip() for u in uncertainty) if s],
    }


def normalise_claims(raw, material: str) -> dict:
    r = raw if isinstance(raw, dict) else {}
    points = r.get("verifiablePoints") if isinstance(r.get("verifiablePoints"), list) else []
    excluded = r.get("excluded") if isinstance(r.get("excluded"), list) else []
    queries = r.get("searchQueries") if isinstance(r.get("searchQueries"), list) else []
    primary = r.get("primaryClaim") or str(material)[:300]
    return {
        "hasFactualClaim": bool(r.get("hasFactualClaim")),
        "primaryClaim": primary,
        "verifiablePoints": points[:6],
        "excluded": excluded[:5],
        "searchQueries": queries[:5],
    }
