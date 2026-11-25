"""Assessment validation.

Structural checks keep the six outcome labels and drop empty findings.
Evidence alignment then compares each finding with the sealed snapshot
snippets. Word overlap, a matching quotation, and the model's label are not
proof that a claim is true. literally_aligned means the wording matches a
stored sentence. It does not mean the claim was verified.
"""

import re

VALID_ASSESSMENTS = [
    "VERIFIED",
    "PARTIALLY_VERIFIED",
    "CONTRADICTED",
    "INSUFFICIENT_EVIDENCE",
    "POTENTIAL_MANIPULATION",
    "UNRESOLVED",
]
FINDING_TYPES = ["support", "contradict", "inconsistent", "caution"]
EVIDENCE_STATUSES = ("invalid_reference", "literally_aligned", "contradicted", "not_established")

SUPPORT_LIMITATION = (
    "The stored source text was checked for integrity and alignment only. "
    "Semantic support was not established."
)
CONTRADICTION_NOTE = (
    "The contradicted outcome records a literal negation between the primary claim "
    "and one cited stored sentence. It does not prove a broader conclusion."
)
MANIPULATION_NOTE = (
    "The manipulation outcome records a fabrication statement in a cited stored "
    "sentence that names the sealed asset. It does not prove how the asset was altered."
)
INSUFFICIENT_NOTE = "A lack of stored evidence is not confirmation of the claim."
UNRESOLVED_CHOICE = (
    "The outcome is unresolved. Stored text was not accepted as proof of the claim."
)
INSUFFICIENT_CHOICE = "The outcome is insufficient evidence."
LITERAL_FINDING_TEXT = (
    "This finding uses the same wording as a cited stored sentence. "
    "That match does not verify the claim."
)
UNESTABLISHED_FINDING_TEXT = "This finding is not established by the cited stored text."
INVALID_FINDING_TEXT = "This finding cites a source that is not in the stored evidence."
CONTRADICTED_FINDING_TEXT = (
    "A cited stored sentence is a direct grammatical reversal of this finding. "
    "That reversal is not a broader proof."
)
_FACING_TEXT = {
    "literally_aligned": LITERAL_FINDING_TEXT,
    "not_established": UNESTABLISHED_FINDING_TEXT,
    "invalid_reference": INVALID_FINDING_TEXT,
    "contradicted": CONTRADICTED_FINDING_TEXT,
}

# Grammatical negators only. Words such as false, fake, positive, negative,
# no, without, and none depend on context and do not reverse a sentence by
# themselves.
_NEGATION = {
    "not", "never", "cannot", "cant",
    "dont", "doesnt", "isnt", "arent", "wasnt", "werent", "didnt",
    "hasnt", "havent", "hadnt", "wont", "wouldnt",
}
_AUX = {"do", "does", "did"}
_QUALIFIERS = {
    "if", "unless", "except", "only", "may", "might", "could", "possibly",
    "however", "but", "although", "though", "despite", "provided", "some",
}
_ATTRIBUTION = {
    "alleged", "allegedly", "allegation", "accused", "accusation", "claimed",
    "claims", "reportedly", "rumor", "rumour", "rumored", "rumoured",
    "suspected", "unverified", "according",
}
_DISCUSSION = {
    "discusses", "discussing", "discussion", "unconfirmed", "whether", "unclear",
}
_MANIPULATION_WORDS = {
    "manipulated", "manipulation", "edited", "doctored", "fabricated", "altered", "forged",
}
_STOP = {
    "the", "a", "an", "of", "to", "and", "or", "is", "was", "were", "be", "been",
    "by", "for", "that", "this", "it", "on", "in", "with", "as", "at", "from",
    "its", "are", "has", "had", "have",
}
_FABRICATION_PHRASES = (
    "was digitally fabricated",
    "has been digitally fabricated",
    "was digitally altered",
    "was digitally manipulated",
    "is a digital fabrication",
    "was fabricated",
    "has been fabricated",
    "was doctored",
    "has been doctored",
)
_SCOPE_PATTERNS = (
    ("not", "only"),
    ("not", "just"),
    ("not", "necessarily"),
    ("not", "all"),
    ("cannot", "be", "ruled"),
    ("no", "evidence"),
)
_MONTHS = (
    "january|february|march|april|may|june|july|august|september|october|november|december"
)
_DATE = re.compile(
    rf"\b(?:\d{{1,2}}\s+(?:{_MONTHS})\s+\d{{4}}"
    rf"|(?:{_MONTHS})\s+\d{{1,2}},?\s+\d{{4}}"
    rf"|\d{{4}}-\d{{2}}-\d{{2}})\b",
    re.IGNORECASE,
)
_CONTRAST_SPLIT = re.compile(
    r"\s*(?:;|\bbut\b|\bhowever\b|\balthough\b|\bthough\b|\bexcept\b)\s*",
    re.IGNORECASE,
)
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")
_TOKEN = re.compile(r"[^a-z0-9]+")
_YEAR = re.compile(r"(?:1[6-9]|20)\d{2}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


def _is_index(n, source_count: int) -> bool:
    return isinstance(n, int) and not isinstance(n, bool) and 0 <= n < source_count


def _tokens(text: str) -> list[str]:
    return [part for part in _TOKEN.sub(" ", str(text or "").casefold()).split() if part]


def _stem(word: str) -> str:
    for suffix in ("ing", "ed", "es", "s"):
        if word.endswith(suffix) and len(word) - len(suffix) >= 4:
            return word[: -len(suffix)]
    return word


def _inflect(left: str, right: str) -> bool:
    return left == right or _stem(left) == _stem(right)


def _sentences(text: str) -> list[str]:
    parts = _SENTENCE_SPLIT.split(str(text or "").strip())
    return [part.strip() for part in parts if part.strip()]


def _snippet(source) -> str:
    if not isinstance(source, dict):
        return ""
    value = source.get("snippet")
    return value if isinstance(value, str) else ""


def _negation_count(tokens: list[str]) -> int:
    return sum(1 for token in tokens if token in _NEGATION)


def _scope_blocked(tokens: list[str]) -> bool:
    window = tuple(tokens)
    for pattern in _SCOPE_PATTERNS:
        width = len(pattern)
        for index in range(len(window) - width + 1):
            if window[index:index + width] == pattern:
                return True
    return False


def _issue_tokens(tokens: list[str]) -> bool:
    markers = _QUALIFIERS | _ATTRIBUTION | _DISCUSSION
    return _scope_blocked(tokens) or any(token in markers for token in tokens)


def _neighbors_block(sentences: list[str], index: int) -> bool:
    """Any other sentence makes the snippet's context ambiguous.

    A neighbor can restate, confirm, qualify, or change the claim without
    using a fixed marker word. A deterministic check cannot treat that
    multi-sentence snippet as an unambiguous reversal.
    """
    return len(sentences) > 1 and 0 <= index < len(sentences)


def _drop_one_negation(tokens: list[str]) -> tuple[list[str], int | None] | None:
    indexes = [index for index, token in enumerate(tokens) if token in _NEGATION]
    if len(indexes) != 1:
        return None
    index = indexes[0]
    reduced = tokens[:index] + tokens[index + 1:]
    verb_at = None
    auxiliary = index - 1
    if auxiliary >= 0 and auxiliary < len(reduced) and reduced[auxiliary] in _AUX:
        reduced = reduced[:auxiliary] + reduced[auxiliary + 1:]
        verb_at = auxiliary
    return reduced, verb_at


def _equal_allowing_verb(reduced: list[str], other: list[str], verb_at: int | None) -> bool:
    if reduced == other:
        return True
    if verb_at is None or len(reduced) != len(other) or not (0 <= verb_at < len(reduced)):
        return False
    for index, (left, right) in enumerate(zip(reduced, other)):
        if left == right:
            continue
        if index == verb_at and _inflect(left, right):
            continue
        return False
    return True


def _literal_negation(left: str, right: str) -> bool:
    left_tokens = _tokens(left)
    right_tokens = _tokens(right)
    if not left_tokens or not right_tokens:
        return False
    if _scope_blocked(left_tokens) or _scope_blocked(right_tokens):
        return False
    left_count = _negation_count(left_tokens)
    right_count = _negation_count(right_tokens)
    if abs(left_count - right_count) != 1:
        return False
    if left_count > right_count:
        dropped = _drop_one_negation(left_tokens)
        other = right_tokens
    else:
        dropped = _drop_one_negation(right_tokens)
        other = left_tokens
    if dropped is None:
        return False
    reduced, verb_at = dropped
    return _equal_allowing_verb(reduced, other, verb_at)


def _content_stems(tokens: list[str]) -> set[str]:
    stems = set()
    for token in tokens:
        if token in _STOP or token in _NEGATION or token in _AUX or token in _QUALIFIERS:
            continue
        if token.isdigit():
            continue
        stem = _stem(token)
        if len(stem) >= 4:
            stems.add(stem)
    return stems


def _dates(text: str) -> list[str]:
    return [match.group(0).casefold() for match in _DATE.finditer(str(text or ""))]


def _numbers(tokens: list[str]) -> list[str]:
    return [token for token in tokens if any(character.isdigit() for character in token)]


def _residue(tokens: list[str]) -> list[str]:
    return [token for token in tokens if not any(character.isdigit() for character in token)]


def _years_only(numbers: list[str]) -> bool:
    return bool(numbers) and all(_YEAR.fullmatch(number) for number in numbers)


def _date_or_quantity(finding: str, sentence: str) -> str | None:
    finding_dates = _dates(finding)
    sentence_dates = _dates(sentence)
    finding_stripped = _tokens(_DATE.sub(" ", finding))
    sentence_stripped = _tokens(_DATE.sub(" ", sentence))
    if finding_dates != sentence_dates and (finding_dates or sentence_dates):
        if _residue(finding_stripped) == _residue(sentence_stripped) and _numbers(finding_stripped) == _numbers(sentence_stripped):
            return "date_differs"
    finding_tokens = _tokens(finding)
    sentence_tokens = _tokens(sentence)
    if _residue(finding_tokens) == _residue(sentence_tokens) and _numbers(finding_tokens) != _numbers(sentence_tokens):
        finding_numbers = _numbers(finding_tokens)
        sentence_numbers = _numbers(sentence_tokens)
        if (
            len(finding_numbers) == len(sentence_numbers)
            and _years_only(finding_numbers)
            and _years_only(sentence_numbers)
        ):
            return "date_differs"
        return "quantity_differs"
    return None


def _qualifier_omitted(clause_tokens: list[str], finding_tokens: list[str]) -> bool:
    if not finding_tokens or not any(token in _QUALIFIERS for token in clause_tokens):
        return False
    if any(token in _QUALIFIERS for token in finding_tokens):
        return False
    left = 0
    right = 0
    skipped = False
    while left < len(clause_tokens) and right < len(finding_tokens):
        if _inflect(clause_tokens[left], finding_tokens[right]):
            left += 1
            right += 1
        elif clause_tokens[left] in _QUALIFIERS:
            skipped = True
            left += 1
        else:
            return False
    while left < len(clause_tokens) and clause_tokens[left] in _QUALIFIERS:
        skipped = True
        left += 1
    return skipped and left == len(clause_tokens) and right == len(finding_tokens)


def _prefixed_extraction(sentence_tokens: list[str], finding_tokens: list[str], markers: set[str]) -> bool:
    if not finding_tokens or len(finding_tokens) > len(sentence_tokens):
        return False
    if any(token in markers for token in finding_tokens):
        return False
    if not any(token in markers for token in sentence_tokens):
        return False
    start = len(sentence_tokens) - len(finding_tokens)
    if start <= 0:
        return False
    tail = sentence_tokens[start:]
    if any(not _inflect(left, right) for left, right in zip(tail, finding_tokens)):
        return False
    return any(token in markers for token in sentence_tokens[:start])


def _align_snippet(finding: str, snippet: str) -> tuple[str, str]:
    sentences = _sentences(snippet)
    if not sentences:
        return ("not_established", "empty_snippet")
    finding_tokens = _tokens(finding)
    if finding_tokens and finding_tokens == _tokens(snippet):
        return ("literally_aligned", "literal_sentence")

    for index, sentence in enumerate(sentences):
        if finding_tokens and _tokens(sentence) == finding_tokens:
            if _neighbors_block(sentences, index):
                return ("not_established", "context_conflict")
            return ("literally_aligned", "literal_sentence")

    for index, sentence in enumerate(sentences):
        if not _literal_negation(finding, sentence):
            continue
        if _issue_tokens(_tokens(sentence)) or _neighbors_block(sentences, index):
            return ("not_established", "context_conflict")
        return ("contradicted", "negation_conflict")

    for sentence in sentences:
        difference = _date_or_quantity(finding, sentence)
        if difference:
            return ("not_established", difference)

    for sentence in _sentences(snippet):
        clauses = [clause for clause in _CONTRAST_SPLIT.split(sentence) if clause.strip()]
        for clause in clauses:
            if _qualifier_omitted(_tokens(clause), finding_tokens):
                return ("not_established", "qualification_present")
        sentence_tokens = _tokens(sentence)
        if _prefixed_extraction(sentence_tokens, finding_tokens, _ATTRIBUTION):
            return ("not_established", "attribution_not_established")
        if _prefixed_extraction(sentence_tokens, finding_tokens, _DISCUSSION):
            return ("not_established", "discussed_not_confirmed")

    finding_stems = _content_stems(finding_tokens)
    for sentence in sentences:
        sentence_tokens = _tokens(sentence)
        if _negation_count(finding_tokens) == _negation_count(sentence_tokens):
            continue
        if finding_stems & _content_stems(sentence_tokens):
            return ("not_established", "negation_unresolved")

    if _has_manipulation_word(finding) and _has_manipulation_word(snippet):
        return ("not_established", "manipulation_word_not_indicator")
    return ("not_established", "paraphrase_not_established")


def _has_manipulation_word(text: str) -> bool:
    return any(token in _MANIPULATION_WORDS for token in _tokens(text))


def _has_fabrication(sentence: str) -> bool:
    folded = sentence.casefold()
    return any(phrase in folded for phrase in _FABRICATION_PHRASES)


def _sealed_digest(snapshot: dict) -> str | None:
    asset = snapshot.get("sealedAsset")
    if not isinstance(asset, dict):
        return None
    digest = asset.get("sha256")
    if not isinstance(digest, str):
        return None
    folded = digest.strip().lower()
    if _SHA256.fullmatch(folded):
        return folded
    return None


def _cited_indexes(findings: list[dict]) -> list[int]:
    indexes = []
    for finding in findings:
        for index in finding.get("sources") or []:
            if index not in indexes:
                indexes.append(index)
    return indexes


def _literal_claim_negation(primary: str, sources: list, cited: list[int]) -> bool:
    """Confirm a contradiction only for one unambiguous grammatical reversal.

    Every cited snippet must be a single sentence. A second sentence can
    confirm, qualify, or restate the claim, so the outcome stays unresolved.
    The reversal itself must be a grammatical negator, not a word such as
    false, fake, positive, or negative.
    """
    claim = str(primary or "").strip()
    if not claim or not cited:
        return False
    matched = False
    for index in cited:
        if not _is_index(index, len(sources)):
            return False
        sentences = _sentences(_snippet(sources[index]))
        if len(sentences) != 1:
            return False
        sentence = sentences[0]
        tokens = _tokens(sentence)
        if _issue_tokens(tokens) or _scope_blocked(tokens) or tokens == _tokens(claim):
            return False
        if not _literal_negation(claim, sentence):
            return False
        matched = True
    return matched


def _manipulation_confirmed(sources: list, cited: list[int], snapshot: dict) -> bool:
    digest = _sealed_digest(snapshot)
    if digest is None:
        return False
    for index in cited:
        for sentence in _sentences(_snippet(sources[index])):
            folded = sentence.casefold()
            if digest not in folded:
                continue
            if _issue_tokens(_tokens(sentence)) or _scope_blocked(_tokens(sentence)):
                continue
            if any(token in _NEGATION for token in _tokens(sentence)):
                continue
            if _has_fabrication(sentence):
                return True
    return False


def _display_type(status: str) -> str:
    if status == "contradicted":
        return "contradict"
    return "caution"


def _blank_why() -> dict:
    return {
        "supporting": "",
        "contradicting": "",
        "sourceQuality": "",
        "timeline": "",
        "uncertain": "",
        "choice": "",
    }


def controlled_explanation(outcome: str) -> dict:
    """Server text for one outcome. Model prose is not included."""
    why = _blank_why()
    if outcome == "CONTRADICTED":
        why["contradicting"] = CONTRADICTION_NOTE
        why["choice"] = CONTRADICTION_NOTE
        notes = [CONTRADICTION_NOTE]
    elif outcome == "POTENTIAL_MANIPULATION":
        why["choice"] = MANIPULATION_NOTE
        notes = [MANIPULATION_NOTE]
    elif outcome == "INSUFFICIENT_EVIDENCE":
        why["choice"] = INSUFFICIENT_CHOICE
        why["uncertain"] = INSUFFICIENT_NOTE
        notes = [INSUFFICIENT_NOTE]
    else:
        why["choice"] = UNRESOLVED_CHOICE
        why["uncertain"] = SUPPORT_LIMITATION
        notes = [SUPPORT_LIMITATION]
    return {"why": why, "uncertainty": notes}


def _align_finding(text: str, sources: list, indexes: list[int]) -> tuple[str, str, list[int]]:
    valid = [index for index in indexes if _is_index(index, len(sources))]
    if not valid:
        return ("invalid_reference", "invalid_index", [])
    cited = [_snippet(sources[index]) for index in valid]
    if all(not snippet.strip() for snippet in cited):
        return ("not_established", "empty_snippet", valid)
    usable = [(index, snippet) for index, snippet in zip(valid, cited) if snippet.strip()]
    results = [_align_snippet(text, snippet) for _, snippet in usable]
    if any(reason == "context_conflict" for _, reason in results):
        return ("not_established", "context_conflict", valid)
    for status, reason in results:
        if status == "contradicted":
            return (status, reason, valid)
    for status, reason in results:
        if status == "literally_aligned":
            return (status, reason, valid)
    priority = {
        "date_differs": 0,
        "quantity_differs": 1,
        "qualification_present": 2,
        "attribution_not_established": 3,
        "discussed_not_confirmed": 4,
        "negation_unresolved": 5,
        "manipulation_word_not_indicator": 6,
        "paraphrase_not_established": 7,
    }
    best = min(results, key=lambda item: priority.get(item[1], 99))
    if best[1] == "paraphrase_not_established":
        others = [
            _snippet(source)
            for number, source in enumerate(sources)
            if number not in valid and _snippet(source).strip()
        ]
        for snippet in others:
            snippet_sentences = _sentences(snippet)
            if _tokens(text) == _tokens(snippet) or any(_tokens(text) == _tokens(sentence) for sentence in snippet_sentences):
                return ("not_established", "not_in_cited_snippet", valid)
            if any(_literal_negation(text, sentence) for sentence in snippet_sentences):
                return ("not_established", "not_in_cited_snippet", valid)
    return (best[0], best[1], valid)


def _outcome(model: str, source_count: int, primary: str, sources: list, findings: list[dict], snapshot: dict) -> str:
    if source_count == 0 or model == "INSUFFICIENT_EVIDENCE":
        return "INSUFFICIENT_EVIDENCE"
    cited = _cited_indexes(findings)
    if model == "CONTRADICTED" and _literal_claim_negation(primary, sources, cited):
        return "CONTRADICTED"
    if model == "POTENTIAL_MANIPULATION" and _manipulation_confirmed(sources, cited, snapshot):
        return "POTENTIAL_MANIPULATION"
    if model == "UNRESOLVED":
        return "UNRESOLVED"
    return "UNRESOLVED"


def validate_assessment(raw, snapshot) -> dict:
    """Validate one model assessment against the sealed snapshot.

    ``snapshot`` is the stored investigation snapshot. Client-submitted source
    text is not an argument and is not read from ``raw``.
    """
    record = snapshot if isinstance(snapshot, dict) else {}
    sources = record.get("sources") if isinstance(record.get("sources"), list) else []
    primary = record.get("primaryClaim") if isinstance(record.get("primaryClaim"), str) else ""
    source_count = len(sources)
    body = raw if isinstance(raw, dict) else {}
    model = body.get("assessment") if body.get("assessment") in VALID_ASSESSMENTS else "UNRESOLVED"

    findings = []
    supplied = body.get("findings") if isinstance(body.get("findings"), list) else []
    for item in supplied:
        if not isinstance(item, dict):
            continue
        text = str(item.get("text") or "").strip()
        if not text:
            continue
        indexes = item.get("sources") if isinstance(item.get("sources"), list) else []
        status, reason, valid = _align_finding(text, sources, indexes)
        findings.append({
            "type": _display_type(status),
            "text": _FACING_TEXT[status],
            "sources": valid,
            "evidenceStatus": status,
            "alignmentReason": reason,
        })

    described = body.get("originalMaterial") if isinstance(body.get("originalMaterial"), dict) else {}
    source_index = described.get("source")
    # established stays false. A literal sentence match is traceability, not
    # proof that original material was identified.
    original = {
        "established": False,
        "description": "",
        "source": source_index if _is_index(source_index, source_count) else None,
    }

    outcome = _outcome(model, source_count, primary, sources, findings, record)
    # Model why and uncertainty are discarded. A wording filter cannot tell a
    # useful caveat from a claim that the source proved the result.
    explanation = controlled_explanation(outcome)

    return {
        "assessment": outcome,
        # Raw model label before facing controls. Callers that persist may store
        # this separately; public HTTP responses must not expose it in Phase A.
        "modelAssessment": model,
        "findings": findings,
        "originalMaterial": original,
        "why": explanation["why"],
        "uncertainty": explanation["uncertainty"],
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
