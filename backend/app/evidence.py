"""Source independence and timeline.

Independence follows frontend/engine.js. The timeline keeps a date only when
the source record already contains a real calendar date. Nothing is inferred
to fill a gap. Dates from these records are provider-reported; this stage has
no check that could confirm an original publication date.
"""

import datetime
import re

from app.quality import classify, rank
from app.textutil import detect_date_type, host_of
from app.urls import stored_source_url

MAX_SOURCES = 12
_CALENDAR_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_DATE_TYPES = {"published", "updated", "unspecified"}
_WORD = re.compile(r"[^a-z0-9\s]")
_TOKEN_SPLIT = re.compile(r"\s+")
_DOI = re.compile(r"\b10\.\d{4,9}/[^\s\"'<>)]+", re.IGNORECASE)
_TITLE_SITE = re.compile(
    r"\s+[-|·–—]\s*([A-Z][A-Za-z0-9.&']{1,15}(?:\s+[A-Za-z0-9.&']{1,15}){0,2})$"
)
_AUTHOR = re.compile(r"\bby\s+([A-Z][A-Za-z.]*\s+[A-Z][a-zA-Z'-]+)\b")
_ORIGIN_NOISE = re.compile(r"\b(the|report|release|news|organization|organisation|study|statement)\b")
_ORIGIN_PATTERNS = [
    re.compile(r"according to (?:the )?([A-Z][A-Za-z0-9&.'-]+(?:\s+[A-Z][A-Za-z0-9&.'-]+){0,4})"),
    re.compile(r"\bthe\s+([A-Z][A-Za-z0-9&.'-]+(?:\s+[A-Z][A-Za-z0-9&.'-]+){0,4})\s+(?:release|report|statement|study)\b"),
    re.compile(r"\b([A-Z][A-Za-z0-9&.'-]+(?:\s+[A-Z][A-Za-z0-9&.'-]+){0,3})\s+(?:reported|reports|announced|announces|says|said|found|finds|warns|warned)\b"),
]
_ORIGIN_ALIASES = {
    "who": "who",
    "world health organization": "who",
    "world health organisation": "who",
}


def prepare_sources(sources: list) -> list[dict]:
    """Dedupe, replace any client quality, sort, and keep the same 12-source cap."""
    seen = set()
    prepared = []
    for item in sources or []:
        if not isinstance(item, dict):
            continue
        url = stored_source_url(item.get("url"))
        if url is None or url in seen:
            continue
        seen.add(url)
        record = {
            "url": url,
            "title": item.get("title"),
            "snippet": item.get("snippet") or "",
            "publishedAt": item.get("publishedAt"),
            "provider": item.get("provider"),
            "quality": classify(url),
        }
        published, certainty, date_type = date_fields(record)
        record["publishedAt"] = published
        record["dateCertainty"] = certainty
        record["dateType"] = date_type
        prepared.append(record)
    prepared.sort(key=lambda source: rank(source["quality"]["tier"]), reverse=True)
    return prepared[:MAX_SOURCES]


def canonical_published_at(value) -> str | None:
    """Return the supplied calendar date, or nothing.

    Only an exact YYYY-MM-DD that is a real day is kept. Other text is not
    repaired into a date.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not _CALENDAR_DATE.fullmatch(text):
        return None
    try:
        datetime.date.fromisoformat(text)
    except ValueError:
        return None
    return text


def date_fields(source: dict) -> tuple[str | None, str | None, str | None]:
    published = canonical_published_at(source.get("publishedAt"))
    if not published:
        return None, None, None
    label = detect_date_type(f"{source.get('snippet') or ''} {source.get('title') or ''}")
    if label not in _DATE_TYPES:
        label = "unspecified"
    return published, "provider-reported", label


def build_timeline(sources: list) -> dict:
    """Sort supplied dates. Missing and invalid dates stay off the timeline."""
    entries = []
    missing = []
    for index, source in enumerate(sources or []):
        if not isinstance(source, dict):
            missing.append(index)
            continue
        published, certainty, date_type = date_fields(source)
        if not published:
            missing.append(index)
            continue
        title = source.get("title")
        if isinstance(title, str) and title.strip():
            desc = title
        else:
            desc = host_of(str(source.get("url") or ""))
        entries.append({
            "date": published,
            "certainty": certainty,
            "dateType": date_type,
            "desc": desc,
            "sourceIndex": index,
        })
    entries.sort(key=lambda entry: entry["date"])
    return {
        "entries": entries,
        "missingCount": len(missing),
        "missingIndexes": missing,
        "earliest": entries[0] if entries else None,
    }


def independence(sources: list) -> dict:
    rows = [source for source in sources or [] if isinstance(source, dict)]
    count = len(rows)
    texts = [_tokens(source.get("snippet") or source.get("title")) for source in rows]
    hosts = [host_of(str(source.get("url") or "")) for source in rows]
    origins = [_detect_origin(source.get("snippet") or source.get("title")) for source in rows]
    dois = [_extract_doi(source.get("snippet")) or _extract_doi(source.get("url")) for source in rows]
    titles = [_title_tokens(source.get("title")) for source in rows]
    authors = [_extract_author(source.get("snippet")) for source in rows]
    parent = list(range(count))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        root_left, root_right = find(left), find(right)
        if root_left != root_right:
            parent[max(root_left, root_right)] = min(root_left, root_right)

    text_pairs = []
    origin_pairs = []
    doi_pairs = []
    uncertain_pairs = []
    for i in range(count):
        for j in range(i + 1, count):
            same_host = bool(hosts[i]) and hosts[i] == hosts[j]
            same_origin = bool(origins[i]) and origins[i] == origins[j]
            same_doi = bool(dois[i]) and dois[i] == dois[j]
            same_text = _jaccard(texts[i], texts[j]) >= 0.55
            same_title = _jaccard(titles[i], titles[j]) >= 0.6 and len(titles[i]) >= 3
            same_author = bool(authors[i]) and authors[i] == authors[j]
            if same_host:
                union(i, j)
            if same_origin:
                union(i, j)
                origin_pairs.append((i, j))
            if same_doi:
                union(i, j)
                doi_pairs.append((i, j))
            if same_text:
                union(i, j)
                text_pairs.append((i, j))
            if not same_host and not same_origin and not same_doi and not same_text and same_title:
                if same_author:
                    union(i, j)
                    doi_pairs.append((i, j))
                else:
                    uncertain_pairs.append((i, j))

    by_host: dict[str, list[int]] = {}
    for index, host in enumerate(hosts):
        if not host:
            continue
        by_host.setdefault(host, []).append(index)
    host_groups = [
        {"host": host, "indexes": indexes}
        for host, indexes in by_host.items()
        if len(indexes) > 1
    ]
    unique_host_count = len(by_host) + sum(1 for host in hosts if not host)

    origin_members: dict[str, list[int]] = {}
    for left, right in origin_pairs:
        members = origin_members.setdefault(origins[left], [])
        if left not in members:
            members.append(left)
        if right not in members:
            members.append(right)
    origin_groups = [
        {"origin": origin, "indexes": indexes}
        for origin, indexes in origin_members.items()
    ]

    clusters_by_root: dict[int, list[int]] = {}
    for index in range(count):
        clusters_by_root.setdefault(find(index), []).append(index)
    clusters = [indexes for indexes in clusters_by_root.values() if len(indexes) > 1]

    repeated = []
    reasons = {}
    for group in clusters:
        for index in group[1:]:
            if index not in repeated:
                repeated.append(index)
            tags = []
            if any(index in group_hosts["indexes"] and group[0] in group_hosts["indexes"] for group_hosts in host_groups):
                tags.append("same publisher (" + hosts[index] + ")")
            if origins[index] and origins[index] == origins[group[0]]:
                tags.append("shares attributed origin (" + origins[index] + ")")
            if dois[index] and dois[index] == dois[group[0]]:
                tags.append("same DOI (" + dois[index] + ")")
            if _jaccard(texts[index], texts[group[0]]) >= 0.55:
                tags.append("shares near-identical wording")
            if (
                not tags
                and _jaccard(titles[index], titles[group[0]]) >= 0.6
                and authors[index]
                and authors[index] == authors[group[0]]
            ):
                tags.append("same title and author (" + authors[index] + ") — likely the same study mirrored on a different site")
            reasons[index] = "; ".join(tags) if tags else "grouped with source [" + str(group[0]) + "]"

    uncertain = []
    uncertain_reasons = {}
    for left, right in uncertain_pairs:
        for index, other in ((right, left), (left, right)):
            if index in repeated:
                continue
            if index not in uncertain:
                uncertain.append(index)
            uncertain_reasons[index] = (
                "Possible shared origin with [" + str(other) + "] — titles closely match but this could not be "
                "confirmed (no matching author or identifier found) — independence uncertain."
            )

    notes = []
    if host_groups:
        notes.append(str(len(host_groups)) + " publisher(s) supplied more than one of the retrieved pages.")
    if origin_groups:
        notes.append(str(len(origin_groups)) + " group(s) of sources explicitly attribute their claim to the same original release or organisation.")
    if doi_pairs:
        notes.append(str(len(doi_pairs)) + " pair(s) of sources matched on a publication identifier, author, or title — treated as the same underlying study mirrored across sites.")
    if uncertain:
        notes.append(str(len(uncertain)) + " source(s) have a title close enough to another that they may share an origin, but this could not be confirmed — flagged rather than merged.")
    if text_pairs and not host_groups and not origin_groups and not doi_pairs:
        notes.append("Some sources share very similar wording despite different publishers, suggesting one was copied from another.")
    if not notes:
        notes.append("No two retrieved sources appear to share a publisher, an attributed origin, or near-identical wording — treated as independent.")

    return {
        "totalSources": count,
        "uniqueHostCount": unique_host_count,
        "hostGroups": host_groups,
        "originGroups": origin_groups,
        "clusters": clusters,
        "repeatedIndexes": repeated,
        "repeatedReason": {str(index): reason for index, reason in reasons.items()},
        "uncertainIndexes": uncertain,
        "uncertainReason": {str(index): reason for index, reason in uncertain_reasons.items()},
        "independentCount": (count - len(repeated)) if clusters else count,
        "note": " ".join(notes),
    }


def _tokens(value) -> set[str]:
    cleaned = _WORD.sub(" ", str(value or "").lower())
    return {word for word in _TOKEN_SPLIT.split(cleaned) if len(word) > 3}


def _jaccard(left: set[str], right: set[str]) -> float:
    if not left or not right:
        return 0
    overlap = len(left & right)
    return overlap / (len(left) + len(right) - overlap)


def _normalise_origin(name: str) -> str:
    cleaned = _WORD.sub("", str(name or "").lower())
    cleaned = _ORIGIN_NOISE.sub("", cleaned)
    cleaned = " ".join(cleaned.split())
    return _ORIGIN_ALIASES.get(cleaned, cleaned)


def _detect_origin(value) -> str | None:
    text = str(value or "")
    for pattern in _ORIGIN_PATTERNS:
        match = pattern.search(text)
        if match and match.group(1):
            normalised = _normalise_origin(match.group(1))
            if len(normalised) >= 2:
                return normalised
    return None


def _extract_doi(value) -> str | None:
    match = _DOI.search(str(value or ""))
    if not match:
        return None
    return re.sub(r"[.,;]+$", "", match.group(0)).lower()


def _normalise_title(title) -> str:
    stripped = _TITLE_SITE.sub("", str(title or ""))
    return " ".join(_WORD.sub(" ", stripped.lower()).split())


def _title_tokens(title) -> set[str]:
    return {word for word in _normalise_title(title).split(" ") if len(word) > 2}


def _extract_author(value) -> str | None:
    match = _AUTHOR.search(str(value or ""))
    if not match:
        return None
    return match.group(1).lower().replace(".", "").strip()
