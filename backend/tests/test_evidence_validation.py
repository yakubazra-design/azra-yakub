"""Conservative evidence alignment. Temporary databases and mocked providers.

A matching quotation is traceability. It does not confirm VERIFIED,
PARTIALLY_VERIFIED, or a finding check mark. Client source text is ignored.
"""

import json
import sqlite3
import subprocess
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app.validation import (
    CONTRADICTED_FINDING_TEXT,
    INVALID_FINDING_TEXT,
    LITERAL_FINDING_TEXT,
    MANIPULATION_NOTE,
    UNESTABLISHED_FINDING_TEXT,
    VALID_ASSESSMENTS,
    controlled_explanation,
    validate_assessment,
)
from test_api import DUMMY_OPENAI, _create, _ledger, _seal
from test_integration import ENGINE, _app, _chat

FORGED = "FORGED-SNIPPET-TEXT must not validate a finding."
ASSET = "ab" * 32


def _search(snippets):
    def handler(_request: httpx.Request) -> httpx.Response:
        results = []
        for index, text in enumerate(snippets):
            results.append({
                "url": f"https://www.cdc.gov/evidence-{index}",
                "title": f"Record {index}",
                "publish_date": "2024-01-15",
                "excerpts": [text],
            })
        return httpx.Response(200, json={"results": results, "session_id": "evidence"})
    return handler


def _assess(tmp_path, claim, snippets, model, image=None):
    seen = {"calls": 0}

    def openai(request: httpx.Request) -> httpx.Response:
        seen["calls"] += 1
        seen["prompt"] = json.loads(request.content.decode())["messages"][0]["content"]
        return _chat(model)

    app = _app(tmp_path, openai=openai, parallel=_search(snippets))
    with TestClient(app) as client:
        investigation_id = _create(client, claim)
        if snippets:
            searched = client.post(
                f"/api/investigations/{investigation_id}/search",
                json={"queries": ["evidence check"]},
            )
            assert searched.status_code == 200, searched.text
        token = _seal(client, investigation_id)
        payload = {
            "assessmentToken": token,
            "primaryClaim": "FORGED-PRIMARY",
            "sources": [{
                "url": "https://evil.example/injected",
                "title": "Injected",
                "snippet": FORGED,
                "quality": {"tier": "HIGH", "reason": "CLIENT-SUPPLIED-REASON"},
            }],
            "imageEvidence": image,
        }
        response = client.post(f"/api/investigations/{investigation_id}/assess", json=payload)
        replay = client.post(
            f"/api/investigations/{investigation_id}/assess",
            json={"assessmentToken": token},
        )
    assert response.status_code == 200, response.text
    body = response.json()
    assert FORGED not in seen["prompt"]
    assert "evil.example" not in seen["prompt"]
    assert "CLIENT-SUPPLIED-REASON" not in seen["prompt"]
    assert DUMMY_OPENAI not in response.text
    assert replay.status_code == 403
    assert replay.json()["code"] == "assessment_token_used"
    assert seen["calls"] == 1
    return body, seen


def _finding(text, sources):
    return {"type": "support", "text": text, "sources": sources}


CASES = [
    {
        "name": "exact-wording-is-not-verification",
        "claim": "The event happened.",
        "snippets": ["The event happened."],
        "model": "VERIFIED",
        "findings": [_finding("The event happened.", [0])],
        "outcome": "UNRESOLVED",
        "status": "literally_aligned",
        "reason": "literal_sentence",
        "type": "caution",
    },
    {
        "name": "partial-label-is-not-confirmed",
        "claim": "The event happened.",
        "snippets": ["The event happened."],
        "model": "PARTIALLY_VERIFIED",
        "findings": [_finding("The event happened.", [0])],
        "outcome": "UNRESOLVED",
        "status": "literally_aligned",
        "reason": "literal_sentence",
        "type": "caution",
    },
    {
        "name": "literal-negation",
        "claim": "The event happened.",
        "snippets": ["The event did not happen."],
        "model": "CONTRADICTED",
        "findings": [_finding("The event happened.", [0])],
        "outcome": "CONTRADICTED",
        "status": "contradicted",
        "reason": "negation_conflict",
        "type": "contradict",
    },
    {
        "name": "negation-context-mismatch",
        "claim": "The event happened.",
        "snippets": ["The event did not happen. Officials alleged a similar event happened elsewhere."],
        "model": "CONTRADICTED",
        "findings": [_finding("The event happened.", [0])],
        "outcome": "UNRESOLVED",
        "status": "not_established",
        "reason": "context_conflict",
        "type": "caution",
    },
    {
        "name": "negation-scope-is-unresolved",
        "claim": "The event happened.",
        "snippets": ["The event did not only happen."],
        "model": "CONTRADICTED",
        "findings": [_finding("The event happened.", [0])],
        "outcome": "UNRESOLVED",
        "status": "not_established",
        "reason": "negation_unresolved",
        "type": "caution",
    },
    {
        "name": "pronoun-negation-is-unresolved",
        "claim": "It happened.",
        "snippets": ["The event did not happen."],
        "model": "CONTRADICTED",
        "findings": [_finding("It happened.", [0])],
        "outcome": "UNRESOLVED",
        "status": "not_established",
        "reason": "negation_unresolved",
        "type": "caution",
    },
    {
        "name": "qualification-changes-meaning",
        "claim": "Warm water eases symptoms.",
        "snippets": ["Warm water may ease symptoms, but it does not cure the common cold."],
        "model": "VERIFIED",
        "findings": [_finding("Warm water eases symptoms.", [0])],
        "outcome": "UNRESOLVED",
        "status": "not_established",
        "reason": "qualification_present",
        "type": "caution",
    },
    {
        "name": "attribution-is-not-a-fact",
        "claim": "The company hid the data.",
        "snippets": ["Officials alleged the company hid the data."],
        "model": "VERIFIED",
        "findings": [_finding("The company hid the data.", [0])],
        "outcome": "UNRESOLVED",
        "status": "not_established",
        "reason": "attribution_not_established",
        "type": "caution",
    },
    {
        "name": "discussion-is-not-confirmation",
        "claim": "Warm water cures colds.",
        "snippets": ["This article discusses whether warm water cures colds."],
        "model": "VERIFIED",
        "findings": [_finding("Warm water cures colds.", [0])],
        "outcome": "UNRESOLVED",
        "status": "not_established",
        "reason": "discussed_not_confirmed",
        "type": "caution",
    },
    {
        "name": "quantity-differs",
        "claim": "The study counted 500 cases.",
        "snippets": ["The study counted 50 cases."],
        "model": "VERIFIED",
        "findings": [_finding("The study counted 500 cases.", [0])],
        "outcome": "UNRESOLVED",
        "status": "not_established",
        "reason": "quantity_differs",
        "type": "caution",
    },
    {
        "name": "date-differs",
        "claim": "The notice was published on 2 March 2024.",
        "snippets": ["The notice was published on 2 March 2020."],
        "model": "VERIFIED",
        "findings": [_finding("The notice was published on 2 March 2024.", [0])],
        "outcome": "UNRESOLVED",
        "status": "not_established",
        "reason": "date_differs",
        "type": "caution",
    },
    {
        "name": "paraphrase-is-not-support",
        "claim": "Warm water cures the common cold.",
        "snippets": ["Warm water does not cure the common cold."],
        "model": "VERIFIED",
        "findings": [_finding("Drinking heated water is not a remedy for colds.", [0])],
        "outcome": "UNRESOLVED",
        "status": "not_established",
        "reason": "paraphrase_not_established",
        "type": "caution",
    },
    {
        "name": "most-words-are-not-proof",
        "claim": "Warm water cures the common cold.",
        "snippets": ["Warm water does not cure the common cold."],
        "model": "VERIFIED",
        "findings": [_finding("Warm water does not cure the common cold today.", [0])],
        "outcome": "UNRESOLVED",
        "status": "not_established",
        "reason": "paraphrase_not_established",
        "type": "caution",
    },
    {
        "name": "wrong-source-index",
        "claim": "Warm water cures the common cold.",
        "snippets": [
            "Warm water does not cure the common cold.",
            "Bridge inspections were skipped.",
        ],
        "model": "VERIFIED",
        "findings": [_finding("Warm water does not cure the common cold.", [1])],
        "outcome": "UNRESOLVED",
        "status": "not_established",
        "reason": "not_in_cited_snippet",
        "type": "caution",
        "sources": [1],
    },
    {
        "name": "invalid-source-index",
        "claim": "The event happened.",
        "snippets": ["The event happened."],
        "model": "VERIFIED",
        "findings": [_finding("The event happened.", [9, True, "0"])],
        "outcome": "UNRESOLVED",
        "status": "invalid_reference",
        "reason": "invalid_index",
        "type": "caution",
        "sources": [],
    },
    {
        "name": "valid-index-drops-invalid",
        "claim": "The event happened.",
        "snippets": ["The event happened."],
        "model": "UNRESOLVED",
        "findings": [_finding("The event happened.", [0, 9])],
        "outcome": "UNRESOLVED",
        "status": "literally_aligned",
        "reason": "literal_sentence",
        "type": "caution",
        "sources": [0],
    },
    {
        "name": "empty-snippet",
        "claim": "The event happened.",
        "snippets": [""],
        "model": "VERIFIED",
        "findings": [_finding("The event happened.", [0])],
        "outcome": "UNRESOLVED",
        "status": "not_established",
        "reason": "empty_snippet",
        "type": "caution",
    },
    {
        "name": "high-quality-without-textual-support",
        "claim": "The agency verified the claim.",
        "snippets": ["Bridge inspections were skipped last winter."],
        "model": "VERIFIED",
        "findings": [_finding("The government source verifies the claim.", [0])],
        "outcome": "UNRESOLVED",
        "status": "not_established",
        "reason": "paraphrase_not_established",
        "type": "caution",
    },
    {
        "name": "title-match-is-not-snippet-support",
        "claim": "The event happened.",
        "snippets": ["Bridge inspections were skipped."],
        "model": "VERIFIED",
        "findings": [_finding("Record 0", [0])],
        "outcome": "UNRESOLVED",
        "status": "not_established",
        "reason": "paraphrase_not_established",
        "type": "caution",
    },
    {
        "name": "manipulation-word-without-assertion",
        "claim": "The image was manipulated.",
        "snippets": ["The transcript was edited for length."],
        "model": "POTENTIAL_MANIPULATION",
        "findings": [_finding("The image was manipulated.", [0])],
        "outcome": "UNRESOLVED",
        "status": "not_established",
        "reason": "manipulation_word_not_indicator",
        "type": "caution",
    },
    {
        "name": "fabrication-sentence-without-sealed-asset",
        "claim": "The photograph was altered.",
        "snippets": [f"The photograph {ASSET} was digitally fabricated."],
        "model": "POTENTIAL_MANIPULATION",
        "findings": [_finding(f"The photograph {ASSET} was digitally fabricated.", [0])],
        "outcome": "UNRESOLVED",
        "status": "literally_aligned",
        "reason": "literal_sentence",
        "type": "caution",
        "image": {"fileName": "photo.jpg", "sha256": ASSET, "software": "Adobe Photoshop"},
    },
    {
        "name": "insufficient-evidence-stays",
        "claim": "The event happened.",
        "snippets": ["The event happened."],
        "model": "INSUFFICIENT_EVIDENCE",
        "findings": [_finding("The event happened.", [0])],
        "outcome": "INSUFFICIENT_EVIDENCE",
        "status": "literally_aligned",
        "reason": "literal_sentence",
        "type": "caution",
    },
    {
        "name": "unresolved-stays",
        "claim": "The event happened.",
        "snippets": ["Bridge inspections were skipped."],
        "model": "UNRESOLVED",
        "findings": [_finding("Bridge inspections were skipped.", [0])],
        "outcome": "UNRESOLVED",
        "status": "literally_aligned",
        "reason": "literal_sentence",
        "type": "caution",
    },
]


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_snapshot_alignment_cases(tmp_path, case):
    model = {
        "assessment": case["model"],
        "findings": case["findings"],
        "originalMaterial": {"established": True, "description": "Invented original.", "source": 0},
        "why": {"supporting": "The model says this is verified.", "choice": "Because the model is confident."},
        "uncertainty": ["Model note."],
    }
    body, _seen = _assess(
        tmp_path,
        case["claim"],
        case["snippets"],
        model,
        image=case.get("image"),
    )
    assert body["assessment"] == case["outcome"]
    assert body["assessment"] in {
        "VERIFIED",
        "PARTIALLY_VERIFIED",
        "CONTRADICTED",
        "INSUFFICIENT_EVIDENCE",
        "POTENTIAL_MANIPULATION",
        "UNRESOLVED",
    }
    finding = body["findings"][0]
    facing = {
        "literally_aligned": LITERAL_FINDING_TEXT,
        "not_established": UNESTABLISHED_FINDING_TEXT,
        "invalid_reference": INVALID_FINDING_TEXT,
        "contradicted": CONTRADICTED_FINDING_TEXT,
    }[case["status"]]
    explanation = controlled_explanation(case["outcome"])
    assert finding["evidenceStatus"] == case["status"]
    assert finding["alignmentReason"] == case["reason"]
    assert finding["type"] == case["type"]
    assert finding["type"] != "support"
    assert finding["sources"] == case.get("sources", [0] if case["status"] != "invalid_reference" else [])
    assert finding["text"] == facing
    assert case["findings"][0]["text"] not in finding["text"]
    assert body["originalMaterial"]["established"] is False
    assert body["originalMaterial"]["description"] == ""
    assert body["why"] == explanation["why"]
    assert body["uncertainty"] == explanation["uncertainty"]
    assert "The model says this is verified." not in json.dumps(body)
    assert "Because the model is confident." not in json.dumps(body)
    assert "Model note." not in json.dumps(body)
    assert FORGED not in json.dumps(body)


def test_zero_sources_stay_insufficient_and_indexes_are_invalid(tmp_path):
    body, _seen = _assess(
        tmp_path,
        "Nothing stored.",
        [],
        {
            "assessment": "VERIFIED",
            "findings": [_finding("Nothing stored.", [0])],
            "why": {},
            "uncertainty": [],
        },
    )
    assert body["assessment"] == "INSUFFICIENT_EVIDENCE"
    assert body["findings"] == [{
        "type": "caution",
        "text": INVALID_FINDING_TEXT,
        "sources": [],
        "evidenceStatus": "invalid_reference",
        "alignmentReason": "invalid_index",
    }]


def test_mixed_findings_and_malformed_entries(tmp_path):
    claim = "The event happened."
    body, _seen = _assess(
        tmp_path,
        claim,
        ["The event did not happen.", "Bridge inspections were skipped."],
        {
            "assessment": "PARTIALLY_VERIFIED",
            "findings": [
                "not-an-object",
                {"type": "support", "text": "   ", "sources": [0]},
                {"type": "support", "text": "The event happened.", "sources": [0]},
                {"type": "contradict", "text": "Bridge inspections were skipped.", "sources": [1]},
                {"text": "No index supplied"},
            ],
            "why": {},
            "uncertainty": [],
        },
    )
    assert body["assessment"] == "UNRESOLVED"
    assert [item["evidenceStatus"] for item in body["findings"]] == [
        "contradicted",
        "literally_aligned",
        "invalid_reference",
    ]
    assert [item["alignmentReason"] for item in body["findings"]] == [
        "negation_conflict",
        "literal_sentence",
        "invalid_index",
    ]
    assert all(item["type"] != "support" for item in body["findings"])
    assert body["findings"][0]["sources"] == [0]
    assert body["findings"][1]["sources"] == [1]


def test_unconfirmed_contradiction_does_not_upgrade_a_partial_label(tmp_path):
    body, _seen = _assess(
        tmp_path,
        "The event happened.",
        ["The event did not happen."],
        {
            "assessment": "PARTIALLY_VERIFIED",
            "findings": [_finding("The event happened.", [0])],
            "why": {},
            "uncertainty": [],
        },
    )
    assert body["assessment"] == "UNRESOLVED"
    assert body["findings"][0]["evidenceStatus"] == "contradicted"


def test_manipulation_with_a_sealed_asset_names_that_asset():
    snapshot = {
        "primaryClaim": "The photograph was altered.",
        "sources": [{"snippet": f"The photograph {ASSET} was digitally fabricated.", "quality": {"tier": "HIGH"}}],
        "sealedAsset": {"sha256": ASSET.upper()},
    }
    confirmed = validate_assessment({
        "assessment": "POTENTIAL_MANIPULATION",
        "findings": [_finding(f"The photograph {ASSET} was digitally fabricated.", [0])],
        "why": {},
        "uncertainty": [],
    }, snapshot)
    assert confirmed["assessment"] == "POTENTIAL_MANIPULATION"
    assert confirmed["findings"][0]["type"] == "caution"
    assert confirmed["findings"][0]["evidenceStatus"] == "literally_aligned"
    assert MANIPULATION_NOTE in confirmed["uncertainty"]
    assert confirmed["originalMaterial"]["established"] is False

    alleged = validate_assessment({
        "assessment": "POTENTIAL_MANIPULATION",
        "findings": [_finding(f"Critics alleged the photograph {ASSET} was digitally fabricated.", [0])],
        "why": {},
        "uncertainty": [],
    }, {
        "primaryClaim": "The photograph was altered.",
        "sources": [{"snippet": f"Critics alleged the photograph {ASSET} was digitally fabricated."}],
        "sealedAsset": {"sha256": ASSET},
    })
    assert alleged["assessment"] == "UNRESOLVED"
    assert alleged["findings"][0]["evidenceStatus"] == "literally_aligned"

    unsealed = validate_assessment({
        "assessment": "POTENTIAL_MANIPULATION",
        "findings": [_finding(f"The photograph {ASSET} was digitally fabricated.", [0])],
        "why": {},
        "uncertainty": [],
        "imageEvidence": {"sha256": ASSET},
        "sources": [{"snippet": FORGED}],
    }, snapshot | {"sealedAsset": None})
    assert unsealed["assessment"] == "UNRESOLVED"


def test_provider_timeout_consumes_the_token_and_is_not_an_outcome(tmp_path):
    calls = {"n": 0}

    def openai(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        raise httpx.TimeoutException("timed out")

    path = _ledger(tmp_path)
    app = _app(tmp_path, openai=openai, parallel=_search(["The event happened."]))
    with TestClient(app) as client:
        investigation_id = _create(client, "The event happened.")
        searched = client.post(
            f"/api/investigations/{investigation_id}/search",
            json={"queries": ["evidence check"]},
        )
        assert searched.status_code == 200
        token = _seal(client, investigation_id)
        failed = client.post(
            f"/api/investigations/{investigation_id}/assess",
            json={"assessmentToken": token, "sources": [{"snippet": FORGED}]},
        )
        replay = client.post(
            f"/api/investigations/{investigation_id}/assess",
            json={"assessmentToken": token},
        )
    assert failed.status_code == 502
    assert failed.json()["code"] == "server_unavailable"
    assert "assessment" not in failed.json()
    assert replay.status_code == 403
    assert replay.json()["code"] == "assessment_token_used"
    assert calls["n"] == 2
    consumed = sqlite3.connect(path).execute(
        "SELECT consumed_at FROM assessment_snapshots"
    ).fetchone()
    assert consumed[0]


def _controlled_case(tmp_path, name, claim, snippet, finding, model):
    directory = tmp_path / name
    directory.mkdir()
    body, _seen = _assess(
        tmp_path / name,
        claim,
        [snippet],
        {
            "assessment": model,
            "findings": [_finding(finding, [0])],
            "why": {
                "supporting": "The source proves the claim.",
                "choice": "This claim is verified.",
            },
            "uncertainty": ["Verified with high confidence."],
            "originalMaterial": {"established": True, "description": "The source confirms the claim.", "source": 0},
        },
    )
    dumped = json.dumps(body)
    assert "The source proves the claim." not in dumped
    assert "This claim is verified." not in dumped
    assert "Verified with high confidence." not in dumped
    assert "The source confirms the claim." not in dumped
    assert body["findings"][0]["type"] != "support"
    return body


def test_model_explanations_cannot_overstate_an_unresolved_outcome(tmp_path):
    body = _controlled_case(
        tmp_path,
        "explain",
        "The event happened.",
        "Bridge inspections were skipped.",
        "This claim is verified by the source.",
        "VERIFIED",
    )
    assert body["assessment"] == "UNRESOLVED"
    assert body["findings"][0]["evidenceStatus"] == "not_established"
    assert body["findings"][0]["text"] == UNESTABLISHED_FINDING_TEXT
    assert body["why"] == controlled_explanation("UNRESOLVED")["why"]
    assert body["uncertainty"] == controlled_explanation("UNRESOLVED")["uncertainty"]


def test_false_and_false_positive_do_not_count_as_negation(tmp_path):
    propaganda = _controlled_case(
        tmp_path,
        "propaganda",
        "It is propaganda.",
        "It is false propaganda.",
        "It is propaganda.",
        "CONTRADICTED",
    )
    assert propaganda["assessment"] == "UNRESOLVED"
    assert propaganda["findings"][0]["evidenceStatus"] != "contradicted"

    positive = _controlled_case(
        tmp_path,
        "positive",
        "It is a positive.",
        "It is a false positive.",
        "It is a positive.",
        "CONTRADICTED",
    )
    assert positive["assessment"] == "UNRESOLVED"
    assert positive["findings"][0]["evidenceStatus"] != "contradicted"


def test_neighbor_confirmation_or_qualification_blocks_contradiction(tmp_path):
    confirmed = _controlled_case(
        tmp_path,
        "confirmed",
        "The event happened.",
        "The event did not happen. Officials confirmed the event happened.",
        "The event happened.",
        "CONTRADICTED",
    )
    assert confirmed["assessment"] == "UNRESOLVED"
    assert confirmed["findings"][0]["alignmentReason"] == "context_conflict"

    qualified = _controlled_case(
        tmp_path,
        "qualified",
        "The event happened.",
        "The event did not happen. Later notes qualify that account.",
        "The event happened.",
        "CONTRADICTED",
    )
    assert qualified["assessment"] == "UNRESOLVED"
    assert qualified["findings"][0]["evidenceStatus"] != "contradicted"


def test_genuine_negation_still_stands_and_scope_does_not(tmp_path):
    direct = _controlled_case(
        tmp_path,
        "direct",
        "The event happened.",
        "The event did not happen.",
        "The event happened.",
        "CONTRADICTED",
    )
    assert direct["assessment"] == "CONTRADICTED"
    assert direct["findings"][0]["evidenceStatus"] == "contradicted"
    assert direct["findings"][0]["text"] == CONTRADICTED_FINDING_TEXT
    assert direct["uncertainty"] == controlled_explanation("CONTRADICTED")["uncertainty"]

    scoped = _controlled_case(
        tmp_path,
        "scoped",
        "The event happened.",
        "The event did not only happen.",
        "The event happened.",
        "CONTRADICTED",
    )
    assert scoped["assessment"] == "UNRESOLVED"
    assert scoped["findings"][0]["evidenceStatus"] != "contradicted"


def test_regression_for_all_six_outcome_labels(tmp_path):
    assert VALID_ASSESSMENTS == [
        "VERIFIED",
        "PARTIALLY_VERIFIED",
        "CONTRADICTED",
        "INSUFFICIENT_EVIDENCE",
        "POTENTIAL_MANIPULATION",
        "UNRESOLVED",
    ]
    expectations = {
        "VERIFIED": "UNRESOLVED",
        "PARTIALLY_VERIFIED": "UNRESOLVED",
        "CONTRADICTED": "UNRESOLVED",
        "INSUFFICIENT_EVIDENCE": "INSUFFICIENT_EVIDENCE",
        "POTENTIAL_MANIPULATION": "UNRESOLVED",
        "UNRESOLVED": "UNRESOLVED",
    }
    for label, outcome in expectations.items():
        body = _controlled_case(
            tmp_path,
            label.lower(),
            "It is propaganda.",
            "It is false propaganda.",
            "This claim is verified.",
            label,
        )
        assert body["assessment"] == outcome
        assert body["assessment"] in VALID_ASSESSMENTS
        assert "verified" not in body["findings"][0]["text"].casefold()
        assert "proves" not in json.dumps(body["why"]).casefold()


def test_frontend_does_not_show_a_verification_mark_for_alignment():
    completed = subprocess.run(
        ["node", "-e", _RENDER_SCRIPT, str(ENGINE)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    body = json.loads(completed.stdout)
    assert body["icons"] == ["⚠", "⚠", "✕"]
    assert "finding support" not in body["classes"]
    assert "✓" not in body["icons"]
    assert body["supportCount"] == 0


_RENDER_SCRIPT = r"""
const fs = require('fs');
const vm = require('vm');
const byId = {};
const extras = {};

function makeEl() {
  const node = {
    children: [],
    style: {},
    className: '',
    id: '',
    hidden: false,
    textContent: '',
    setAttribute(name, value) { node[name] = value; },
    appendChild(child) { node.children.push(child); return child; },
    remove() {},
    focus() {}
  };
  node.classList = { add() {}, remove() {}, toggle() {} };
  return node;
}

function querySelector(sel) {
  if (typeof sel === 'string' && sel.charAt(0) === '#') {
    if (!byId[sel.slice(1)]) byId[sel.slice(1)] = makeEl();
    return byId[sel.slice(1)];
  }
  if (!extras[sel]) extras[sel] = makeEl();
  return extras[sel];
}

const sandbox = {
  console, URL, JSON, Math, Date, Promise, setTimeout, clearTimeout, scrollTo() {}
};
sandbox.window = sandbox;
sandbox.document = {
  readyState: 'loading',
  addEventListener() {},
  querySelector,
  querySelectorAll() { return []; },
  getElementById(id) { return querySelector('#' + id); },
  createElement() { return makeEl(); }
};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), sandbox);

const report = {
  input: 'The event happened.',
  provider: 'Parallel',
  live: true,
  errors: [],
  understanding: {
    primaryClaim: 'The event happened.',
    verifiablePoints: [],
    excluded: []
  },
  sources: [{
    url: 'https://www.cdc.gov/evidence-0',
    title: 'Record',
    snippet: 'The event happened.',
    publishedAt: '2024-01-15',
    quality: { tier: 'HIGH', reason: 'Government domain.' }
  }],
  independence: {
    uniqueHostCount: 1,
    independentCount: 1,
    note: 'One source.',
    repeatedIndexes: [],
    uncertainIndexes: [],
    repeatedReason: {},
    uncertainReason: {}
  },
  timeline: { entries: [], missingCount: 1, missingIndexes: [0], earliest: null },
  result: {
    assessment: 'VERIFIED',
    findings: [
      { type: 'support', text: 'Literal quotation.', sources: [0], evidenceStatus: 'literally_aligned', alignmentReason: 'literal_sentence' },
      { type: 'support', text: 'Not established.', sources: [0], evidenceStatus: 'not_established', alignmentReason: 'paraphrase_not_established' },
      { type: 'contradict', text: 'Denied by the sentence.', sources: [0], evidenceStatus: 'contradicted', alignmentReason: 'negation_conflict' }
    ],
    originalMaterial: { established: false, description: '', source: null },
    why: { supporting: '', contradicting: '', sourceQuality: '', timeline: '', uncertain: '', choice: '' },
    uncertainty: ['Semantic support was not established.']
  }
};
sandbox.RC.ui.render(report);

const icons = [];
const classes = [];
function walk(node) {
  if (!node) return;
  if (typeof node.className === 'string') {
    if (node.className.indexOf('finding-icon') >= 0) icons.push(node.textContent);
    if (node.className.indexOf('finding ') === 0) classes.push(node.className);
  }
  (node.children || []).forEach(walk);
}
walk(byId['results-body']);
const chain = (byId['results-body'] && JSON.stringify(byId['results-body'])) || '';
process.stdout.write(JSON.stringify({
  icons: icons,
  classes: classes,
  supportCount: chain.indexOf('0 supporting') >= 0 ? 0 : 1
}));
"""


def test_frontend_rejects_unexpected_verified_labels():
    completed = subprocess.run(
        ["node", "-e", _UNEXPECTED_LABEL_SCRIPT, str(ENGINE)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    body = json.loads(completed.stdout)
    assert body["verified"]["assessment"] == "Unresolved"
    assert body["partial"]["assessment"] == "Unresolved"
    for key in ("verified", "partial"):
        assert "This claim is verified." not in body[key]["body"]
        assert "This claim is partially verified." not in body[key]["body"]
        assert "The source proves the claim." not in body[key]["body"]
        assert "Verified with high confidence." not in body[key]["body"]
        assert "✓" not in body[key]["icons"]
    assert body["verified"]["icons"] == ["⚠"]
    assert body["partial"]["icons"] == ["⚠"]
    for key in ("verifiedMemory", "verifiedAgain", "partialMemory", "partialAgain"):
        stored = body[key]
        dumped = json.dumps(stored)
        assert stored["assessment"] == "UNRESOLVED"
        assert stored["assessment"] != "VERIFIED"
        assert stored["assessment"] != "PARTIALLY_VERIFIED"
        assert "This claim is verified." not in dumped
        assert "This claim is partially verified." not in dumped
        assert "The source proves the claim." not in dumped
        assert "Verified with high confidence." not in dumped
        assert stored["findings"][0]["text"] == UNESTABLISHED_FINDING_TEXT
        assert stored["why"] == controlled_explanation("UNRESOLVED")["why"]
        assert stored["uncertainty"] == controlled_explanation("UNRESOLVED")["uncertainty"]
    assert body["verifiedAgainView"]["assessment"] == "Unresolved"
    assert body["partialAgainView"]["assessment"] == "Unresolved"
    assert body["rawVerified"]["assessment"] == "VERIFIED"
    assert body["rawPartial"]["assessment"] == "PARTIALLY_VERIFIED"
    assert body["localChoice"] == (
        "Nothing in the submission can be checked against evidence, so no stronger assessment is possible."
    )
    assert body["retained"] == []
    forged = json.dumps(body["forgedMemory"])
    assert body["forgedMemory"]["assessment"] == "INSUFFICIENT_EVIDENCE"
    assert "Verified with high confidence." not in forged
    assert "The source proves the claim." not in forged
    assert body["forgedMemory"]["why"]["choice"] == "The outcome is insufficient evidence."


def test_stored_records_cannot_return_the_raw_outcome(tmp_path):
    """Facing outcome stays remapped; model outcome may be stored internally only.

    Phase A persists model_assessment separately for Evidence Intelligence.
    Public assess/history responses must still never return VERIFIED as the
    user-facing assessment, and must not expose modelAssessment.
    """
    body = _controlled_case(
        tmp_path,
        "canonical",
        "The event happened.",
        "Bridge inspections were skipped.",
        "This claim is verified by the source.",
        "VERIFIED",
    )
    assert body["assessment"] == "UNRESOLVED"
    assert "modelAssessment" not in body
    path = tmp_path / "canonical" / "ledger.sqlite"
    connection = sqlite3.connect(path)
    try:
        row = connection.execute(
            """
            SELECT model_assessment, facing_assessment, why_json, uncertainty_json,
                   original_material_json
            FROM assessment_results
            """
        ).fetchone()
        findings = connection.execute(
            "SELECT text, alignment_reason FROM findings"
        ).fetchall()
        # Dump every table except the dedicated model_assessment column so the
        # remapped facing payload and prose remain free of raw verified labels.
        tables = [
            name
            for (name,) in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        ]
        facing_dump_parts = []
        for table in tables:
            if table == "assessment_results":
                facing_dump_parts.append(
                    connection.execute(
                        """
                        SELECT id, investigation_id, owner_id, snapshot_id, status,
                               facing_assessment, failure_code, failure_message,
                               why_json, uncertainty_json, original_material_json,
                               image_evidence_json, created_at
                        FROM assessment_results
                        """
                    ).fetchall()
                )
            else:
                facing_dump_parts.append(
                    connection.execute(f"SELECT * FROM {table}").fetchall()
                )
    finally:
        connection.close()
    assert row is not None
    assert row[0] == "VERIFIED"  # model_assessment (internal)
    assert row[1] == "UNRESOLVED"  # facing_assessment (public)
    dumped = json.dumps(facing_dump_parts, default=str)
    assert "This claim is verified by the source." not in dumped
    assert "The source proves the claim." not in dumped
    assert "Verified with high confidence." not in dumped
    assert "The source confirms the claim." not in dumped
    assert "VERIFIED" not in dumped
    assert "PARTIALLY_VERIFIED" not in dumped
    for finding in findings:
        assert "verified" not in finding[0].lower()


_UNEXPECTED_LABEL_SCRIPT = r"""
const fs = require('fs');
const vm = require('vm');
const byId = {};
const extras = {};

function makeEl() {
  const node = {
    children: [],
    style: {},
    className: '',
    id: '',
    hidden: false,
    textContent: '',
    setAttribute(name, value) { node[name] = value; },
    appendChild(child) { node.children.push(child); return child; },
    remove() {},
    focus() {}
  };
  node.classList = { add() {}, remove() {}, toggle() {} };
  return node;
}

function querySelector(sel) {
  if (typeof sel === 'string' && sel.charAt(0) === '#') {
    if (!byId[sel.slice(1)]) byId[sel.slice(1)] = makeEl();
    return byId[sel.slice(1)];
  }
  if (!extras[sel]) extras[sel] = makeEl();
  return extras[sel];
}

const sandbox = {
  console, URL, JSON, Math, Date, Promise, setTimeout, clearTimeout, scrollTo() {}
};
sandbox.window = sandbox;
sandbox.document = {
  readyState: 'loading',
  addEventListener() {},
  querySelector,
  querySelectorAll() { return []; },
  getElementById(id) { return querySelector('#' + id); },
  createElement() { return makeEl(); }
};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), sandbox);

function blank() {
  Object.keys(byId).forEach(function (key) { delete byId[key]; });
  Object.keys(extras).forEach(function (key) { delete extras[key]; });
}

function report(assessment, findingText) {
  return {
    input: 'The event happened.',
    provider: 'Parallel',
    live: true,
    errors: [],
    understanding: { primaryClaim: 'The event happened.', verifiablePoints: [], excluded: [] },
    sources: [{
      url: 'https://www.cdc.gov/evidence-0',
      title: 'Record',
      snippet: 'Bridge inspections were skipped.',
      publishedAt: '2024-01-15',
      quality: { tier: 'HIGH', reason: 'Government domain.' }
    }],
    independence: {
      uniqueHostCount: 1,
      independentCount: 1,
      note: 'One source.',
      repeatedIndexes: [],
      uncertainIndexes: [],
      repeatedReason: {},
      uncertainReason: {}
    },
    timeline: { entries: [], missingCount: 1, missingIndexes: [0], earliest: null },
    result: {
      assessment: assessment,
      findings: [{ type: 'support', text: findingText, sources: [0] }],
      originalMaterial: { established: true, description: 'The source proves the claim.', source: 0 },
      why: { supporting: 'The source proves the claim.', contradicting: '', sourceQuality: '', timeline: '', uncertain: '', choice: 'This claim is verified.' },
      uncertainty: ['Verified with high confidence.']
    }
  };
}

function read() {
  const icons = [];
  const texts = [];
  function walk(node) {
    if (!node) return;
    if (typeof node.className === 'string' && node.className.indexOf('finding-icon') >= 0) icons.push(node.textContent);
    if (node.textContent && !(node.children || []).length) texts.push(node.textContent);
    (node.children || []).forEach(walk);
  }
  walk(byId['results-body']);
  walk(byId['why-panel']);
  return {
    assessment: byId['results-assessment'] ? byId['results-assessment'].textContent : '',
    icons: icons,
    body: texts.join('\n')
  };
}

function memory(report) {
  return JSON.parse(JSON.stringify(report.result));
}

function retainedNames() {
  const names = ['history', 'exportResult', 'export', 'share', 'download', 'savedResults', 'lastResult'];
  return names.filter(function (name) {
    return sandbox.RC[name] || sandbox.RC.ui[name] || sandbox.RC.engine[name];
  });
}

const verifiedReport = report('VERIFIED', 'This claim is verified.');
const rawVerified = memory(verifiedReport);
blank();
sandbox.RC.ui.render(verifiedReport);
const verified = read();
const verifiedMemory = memory(verifiedReport);
blank();
sandbox.RC.ui.render(verifiedReport);
const verifiedAgainView = read();
const verifiedAgain = memory(verifiedReport);

const partialReport = report('PARTIALLY_VERIFIED', 'This claim is partially verified.');
const rawPartial = memory(partialReport);
blank();
sandbox.RC.ui.render(partialReport);
const partial = read();
const partialMemory = memory(partialReport);
blank();
sandbox.RC.ui.render(partialReport);
const partialAgainView = read();
const partialAgain = memory(partialReport);

const local = report('INSUFFICIENT_EVIDENCE', 'not shown');
local.sources = [];
local.result = {
  assessment: 'INSUFFICIENT_EVIDENCE',
  findings: [],
  originalMaterial: { established: false, description: '', source: null },
  why: {
    supporting: 'Information not available.',
    contradicting: 'Information not available.',
    sourceQuality: 'No sources were searched.',
    timeline: 'Information not available.',
    uncertain: 'The submission does not contain an assertion that evidence could confirm or contradict.',
    choice: 'Nothing in the submission can be checked against evidence, so no stronger assessment is possible.'
  },
  uncertainty: ['The submission reads as opinion, a question or a subjective statement rather than a factual claim.']
};
blank();
sandbox.RC.ui.render(local);
const localMemory = memory(local);

const forged = report('INSUFFICIENT_EVIDENCE', 'This claim is verified.');
forged.result = {
  assessment: 'INSUFFICIENT_EVIDENCE',
  findings: [],
  originalMaterial: { established: false, description: 'The source proves the claim.', source: 0 },
  why: {
    supporting: 'The source proves the claim.',
    contradicting: '',
    sourceQuality: '',
    timeline: '',
    uncertain: '',
    choice: 'Nothing in the submission can be checked against evidence, so no stronger assessment is possible.'
  },
  uncertainty: ['Verified with high confidence.']
};
blank();
sandbox.RC.ui.render(forged);
const forgedMemory = memory(forged);

process.stdout.write(JSON.stringify({
  verified: verified,
  partial: partial,
  verifiedMemory: verifiedMemory,
  verifiedAgain: verifiedAgain,
  verifiedAgainView: verifiedAgainView,
  partialMemory: partialMemory,
  partialAgain: partialAgain,
  partialAgainView: partialAgainView,
  rawVerified: rawVerified,
  rawPartial: rawPartial,
  localChoice: localMemory.why.choice,
  forgedMemory: forgedMemory,
  retained: retainedNames()
}));
"""
