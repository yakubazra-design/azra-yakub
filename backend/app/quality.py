"""Source-quality tiers ported from frontend/engine.js RC.quality.

The match order is part of the result. A host is classified by the first
rule that applies, and a lookalike suffix must not inherit a trust tier.
"""

import re

from app.textutil import host_of

HIGH_EXACT = [
    "who.int", "un.org", "europa.eu", "worldbank.org", "imf.org", "oecd.org",
    "nih.gov", "cdc.gov", "fda.gov", "nhs.uk", "ecdc.europa.eu",
    "nature.com", "science.org", "thelancet.com", "nejm.org", "bmj.com",
    "jamanetwork.com", "cell.com", "pubmed.ncbi.nlm.nih.gov", "ncbi.nlm.nih.gov",
    "cochranelibrary.com", "who.europe.int", "idf.org", "diabetes.org",
    "pib.gov.in", "rbi.org.in", "icmr.gov.in", "mohfw.gov.in",
]
MEDIUM_EXACT = [
    "reuters.com", "apnews.com", "bbc.com", "bbc.co.uk", "npr.org",
    "nytimes.com", "washingtonpost.com", "theguardian.com", "ft.com",
    "economist.com", "aljazeera.com", "dw.com", "france24.com",
    "thehindu.com", "indianexpress.com", "hindustantimes.com", "ndtv.com",
    "timesofindia.indiatimes.com", "livemint.com", "scroll.in",
    "snopes.com", "factcheck.org", "politifact.com", "fullfact.org",
    "altnews.in", "boomlive.in", "healthline.com", "mayoclinic.org",
    "clevelandclinic.org", "webmd.com", "arxiv.org", "biorxiv.org", "medrxiv.org",
    "britannica.com",
]
LOW_EXACT = [
    "facebook.com", "x.com", "twitter.com", "instagram.com", "tiktok.com",
    "reddit.com", "quora.com", "pinterest.com", "youtube.com", "medium.com",
    "substack.com", "blogspot.com", "wordpress.com", "tumblr.com",
    "whatsapp.com", "telegram.org", "linkedin.com",
]
STRUCTURED_DB_EXACT = ["wikidata.org", "wikipedia.org"]
PRIMARY_ORG_EXACT = ["toureiffel.paris"]
PREPRINTS = ["arxiv.org", "biorxiv.org", "medrxiv.org"]

_GOV = re.compile(r"\.gov$|\.gov\.[a-z]{2}$|\.mil$")
_EDU = re.compile(r"\.edu$|\.ac\.[a-z]{2}$|\.edu\.[a-z]{2}$")
_LOW_TLD = re.compile(r"\.(blog|xyz|top|click|info)$")
_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def _ends_with_any(host: str, domains: list[str]) -> bool:
    return any(host == domain or host.endswith("." + domain) for domain in domains)


def classify(url: str) -> dict:
    host = host_of(url)
    if not host:
        return {"tier": "UNKNOWN", "reason": "No usable address for this source."}
    if _GOV.search(host):
        return {"tier": "HIGH", "reason": "Government domain — treated as an official primary source."}
    if _EDU.search(host):
        return {"tier": "HIGH", "reason": "Academic institution domain."}
    if _ends_with_any(host, HIGH_EXACT):
        return {"tier": "HIGH", "reason": "Recognised official, intergovernmental or peer-reviewed publisher."}
    if _ends_with_any(host, PRIMARY_ORG_EXACT):
        return {
            "tier": "HIGH",
            "reason": "Official site of the subject itself — a primary source for facts about it, though it is not independent corroboration from an outside party.",
        }
    if _ends_with_any(host, STRUCTURED_DB_EXACT):
        return {
            "tier": "MEDIUM",
            "reason": "Structured, crowd-edited knowledge database — broadly reliable for simple facts, but not an editorially reviewed publication.",
        }
    if _ends_with_any(host, PREPRINTS):
        return {"tier": "MEDIUM", "reason": "Preprint server — not yet peer reviewed."}
    if _ends_with_any(host, MEDIUM_EXACT):
        return {"tier": "MEDIUM", "reason": "Established news, specialist or fact-checking organisation."}
    if _ends_with_any(host, LOW_EXACT):
        return {"tier": "LOW", "reason": "User-generated platform — content is not editorially verified."}
    if _LOW_TLD.search(host):
        return {"tier": "LOW", "reason": "Domain type commonly used for unverified content."}
    return {"tier": "UNKNOWN", "reason": "Publisher not recognised, so its editorial standards cannot be assessed."}


def rank(tier: str) -> int:
    return _RANK.get(tier, 0)
