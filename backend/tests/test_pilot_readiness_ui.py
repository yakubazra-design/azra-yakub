"""E.7.2 pilot-readiness UI checks.

Temporary fixtures only. The live ledger is not opened. No provider calls.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INDEX = ROOT / "frontend" / "index.html"
ENGINE = ROOT / "frontend" / "engine.js"
STYLES = ROOT / "frontend" / "styles.css"
PRIVACY = ROOT / "frontend" / "privacy.html"


def test_landing_hero_and_live_limits_are_beside_check_now():
    page = INDEX.read_text()
    assert "Know what's true." not in page
    assert "Investigate claims." in page
    assert "Inspect the evidence." in page
    assert 'id="live-limit-note"' in page
    assert "Verified</strong> and <strong>Partially verified</strong> are not confirmed" in page
    assert page.index('id="live-limit-note"') < page.index('id="check-btn"')
    assert 'class="live-limit-outcomes"' in page
    for outcome in (
        "Verified",
        "Partially verified",
        "Unresolved",
        "Insufficient evidence",
        "Contradicted",
        "Potential manipulation",
    ):
        assert f"<li><strong>{outcome}</strong></li>" in page


def test_investigation_input_label_formats_and_url_guidance():
    page = INDEX.read_text()
    script = ENGINE.read_text()
    assert 'for="investigate-input"' in page
    assert 'id="investigate-input"' in page
    assert 'placeholder="Enter a claim or paste a URL…"' in page
    assert 'id="image-format-hint"' in page
    assert "Supported image formats: JPEG, PNG, GIF, and WebP." in page
    assert 'aria-describedby="image-format-hint"' in page
    assert 'id="url-format-hint"' in page
    assert 'id="url-access-hint"' in page
    assert "Focus field to paste URL" in page
    assert "Focus field to paste URL</strong> button only focuses that existing field" in page
    assert "Paste URL button" not in page
    assert "login requirements, privacy restrictions, website security controls, or redirects" in page
    assert "An unavailable page does not establish that its claims are false." in page
    assert 'aria-describedby="url-format-hint url-access-hint"' in page
    assert "Claim or URL field focused. Paste a full https:// address there." in script
    assert "sourceAction(report.pageClaim.url, 'Open submitted page')" in script
    assert "An unavailable page does not establish that its claims are false." in script
    assert "When the image is sent:" in page
    assert "If you decline metadata consent:" in page
    assert 'id="metadata-consent"' in page
    assert 'checked' not in page.split('id="metadata-consent"')[1].split(">")[0]


def test_claim_consent_is_required_and_not_preselected():
    page = INDEX.read_text()
    script = ENGINE.read_text()
    styles = STYLES.read_text()
    assert 'id="investigation-consent"' in page
    assert 'checked' not in page.split('id="investigation-consent"')[1].split(">")[0]
    assert "investigationConsentGiven" in script
    assert "Confirm the investigation consent checkbox before checking a claim." in script
    assert "Pilot Privacy Notice" in page.split('id="investigation-consent"')[1].split("</label>")[0]
    assert 'id="consent-gate-hint"' in page
    assert 'aria-describedby="consent-gate-hint"' in page
    check_btn_tag = page.split('id="check-btn"')[0].rsplit("<button", 1)[-1]
    assert "is-consent-blocked" in check_btn_tag
    assert 'aria-disabled="true"' in check_btn_tag or 'aria-disabled="true"' in page.split('id="check-btn"', 1)[1].split(">")[0]
    assert "syncInvestigationConsentUi" in script
    assert "clearTooltip" in script
    assert "is-consent-blocked" in styles
    assert ".consent-gate-hint" in styles


def test_consent_warning_clears_on_check_and_auth_open():
    script = ENGINE.read_text()
    assert "if (given) clearTooltip();" in script
    open_auth = script.split("openAuth = function (message)")[1].split("function closeAuth")[0]
    assert "clearTooltip();" in open_auth
    assert "consentBox.addEventListener('change'" in script


def test_progress_labels_match_real_stages():
    page = INDEX.read_text()
    script = ENGINE.read_text()
    assert "Finding original material" not in page
    assert "Comparing dates" not in page
    assert "Checking contradictions" not in page
    assert "Extracting the claim" in page
    assert "Searching sources" in page
    assert "Assessing sealed evidence" in page
    assert "var STEPS = ['understand', 'search', 'assess'];" in script
    assert "step('original'" not in script
    assert "step('dates'" not in script
    assert "step('contradictions'" not in script


def test_cost_transparency_without_invented_dollar_amounts():
    page = INDEX.read_text()
    script = ENGINE.read_text()
    assert "OpenAI" in page and "Parallel" in page
    assert "does not display dollar amounts" in page
    assert "providerActivityText" in script
    assert "Exact dollar cost is not shown" in script
    assert "$" not in script.split("function providerActivityText")[1].split("function renderWhy")[0]


def test_registration_shows_password_rules_and_resume_is_gated():
    page = INDEX.read_text()
    script = ENGINE.read_text()
    assert 'id="auth-password-rules"' in page
    assert "At least 12 characters and no more than 128 characters" in page
    assert "Create an account to save and review your investigations." in script
    assert "Before continuing, please review the" in script
    assert "Pilot Privacy Notice" in script
    assert 'minlength="12"' in page
    assert "pendingClaim" in script
    assert "investigationConsentGiven()" in script.split("var resume = pendingClaim")[1].split("}.catch")[0]


def test_mobile_and_a11y_affordances_exist():
    page = INDEX.read_text()
    css = STYLES.read_text()
    script = ENGINE.read_text()
    assert 'class="skip-link"' in page
    assert 'id="nav-mobile-toggle"' in page
    assert 'id="primary-nav"' in page
    assert ".primary-nav.is-open" in css
    assert "skip-link" in css
    assert "e.key === 'Escape'" in script
    assert "focusableIn" in script


def test_modal_focus_containment_and_text_field_focus_styles():
    page = INDEX.read_text()
    css = STYLES.read_text()
    script = ENGINE.read_text()
    assert 'role="dialog"' in page
    assert 'aria-modal="true"' in page
    assert 'aria-labelledby="auth-title"' in page
    assert 'aria-labelledby="account-title"' in page
    assert "setBackgroundInert" in script
    assert 'setAttribute(\'inert\'' in script or 'setAttribute("inert"' in script
    assert "restoreFocus" in script
    assert "dialogPanel" in script
    assert "panel.contains(current)" in script
    assert ".investigate-input:focus-visible" in css
    assert ".auth-input:focus-visible" in css
    assert "outline: none" not in css
    assert css.count("outline: 2px solid var(--accent)") >= 2
    assert ".investigate-input:focus,\n.investigate-input:focus-visible" in css or ".investigate-input:focus, .investigate-input:focus-visible" in css.replace("\n", " ")
    assert "border: 1px solid var(--accent)" in css


def test_image_evidence_separated_from_claim_truth():
    script = ENGINE.read_text()
    assert "These checks describe the uploaded file. They do not establish whether the associated claim is true." in script
    assert "image-evidence-details" in script
    assert "File identity and retention" in script


def test_operator_contact_placeholder_remains_blocker():
    notice = PRIVACY.read_text()
    assert "Operator contact not yet assigned." in notice
    assert "inviting unsupervised external users remains blocked" in notice
    assert "@" not in notice.split("Operator contact not yet assigned.")[1].split("</p>")[0]


def test_outcome_bridge_renders_without_inventing_findings():
    script = r"""
const fs = require('fs');
const vm = require('vm');

function makeEl(tag) {
  const node = {
    tagName: String(tag || 'div').toUpperCase(),
    children: [],
    style: {},
    className: '',
    _id: '',
    hidden: false,
    textContent: '',
    attributes: {},
    parent: null,
    setAttribute(name, value) {
      node.attributes[name] = String(value);
      if (name === 'id') node.id = String(value);
      if (name === 'class') node.className = String(value);
    },
    getAttribute(name) {
      if (name === 'id') return node.id || null;
      if (name === 'class') return node.className || null;
      return Object.prototype.hasOwnProperty.call(node.attributes, name) ? node.attributes[name] : null;
    },
    appendChild(child) {
      child.parent = node;
      node.children.push(child);
      return child;
    },
    remove() {
      if (!node.parent) return;
      node.parent.children = node.parent.children.filter(function (item) { return item !== node; });
      node.parent = null;
    },
    querySelector(sel) {
      return queryAll(node, sel)[0] || null;
    },
    querySelectorAll(sel) {
      return queryAll(node, sel);
    },
    focus() {},
    scrollIntoView() {}
  };
  node.classList = {
    add(name) { if ((' ' + node.className + ' ').indexOf(' ' + name + ' ') < 0) node.className = (node.className + ' ' + name).trim(); },
    remove(name) { node.className = node.className.split(/\s+/).filter(function (item) { return item && item !== name; }).join(' '); },
    toggle(name, force) {
      const on = (' ' + (node.className || '') + ' ').indexOf(' ' + name + ' ') >= 0;
      if (force === true || (!on && force !== false)) node.classList.add(name);
      else node.classList.remove(name);
    }
  };
  Object.defineProperty(node, 'id', {
    get() { return node._id; },
    set(value) { node._id = String(value || ''); if (node._id) byId[node._id] = node; }
  });
  return node;
}

function matches(node, sel) {
  if (!sel) return false;
  if (sel.charAt(0) === '#') return node.id === sel.slice(1);
  if (sel.charAt(0) === '.') return (' ' + (node.className || '') + ' ').indexOf(' ' + sel.slice(1) + ' ') >= 0;
  return node.tagName.toLowerCase() === sel.toLowerCase();
}

function queryAll(root, sel) {
  const out = [];
  function walk(node) {
    if (!node) return;
    if (matches(node, sel)) out.push(node);
    (node.children || []).forEach(walk);
  }
  (root.children || []).forEach(walk);
  return out;
}

const byId = {};
const extras = {};
function querySelector(sel) {
  if (typeof sel === 'string' && sel.charAt(0) === '#') {
    const id = sel.slice(1);
    if (!byId[id]) byId[id] = makeEl('div');
    byId[id].id = id;
    return byId[id];
  }
  if (!extras[sel]) extras[sel] = makeEl('div');
  return extras[sel];
}

const sandbox = {
  console, URL, JSON, Math, Date, Promise, setTimeout, clearTimeout,
  scrollTo() {},
};
sandbox.window = sandbox;
sandbox.document = {
  readyState: 'loading',
  addEventListener() {},
  querySelector,
  querySelectorAll() { return []; },
  getElementById(id) { return querySelector('#' + id); },
  createElement(tag) { return makeEl(tag); }
};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), sandbox);

byId['results-body'] = makeEl('div');
byId['results-body'].id = 'results-body';
byId['results-assessment'] = makeEl('div');
byId['results-assessment'].id = 'results-assessment';
byId['results-basis'] = makeEl('div');
byId['results-basis'].id = 'results-basis';
byId['results-claim-text'] = makeEl('p');
byId['results-claim-text'].id = 'results-claim-text';
byId['results-mode-tag'] = makeEl('span');
byId['results-mode-tag'].id = 'results-mode-tag';
byId['results-mode-note'] = makeEl('p');
byId['results-mode-note'].id = 'results-mode-note';
byId['results-provider-activity'] = makeEl('p');
byId['results-provider-activity'].id = 'results-provider-activity';
byId['why-toggle'] = makeEl('button');
byId['why-toggle'].id = 'why-toggle';
extras['.claim-card'] = makeEl('div');

const validated = sandbox.RC.reasoning.validate({
  assessment: 'UNRESOLVED',
  findings: [],
  originalMaterial: { established: false, description: '', source: null },
  why: { supporting: '', contradicting: '', sourceQuality: '', timeline: '', uncertain: 'x', choice: 'y' },
  uncertainty: ['x']
}, 2);

sandbox.RC.ui.render({
  input: 'Warm water cures diabetes.',
  live: true,
  provider: 'Parallel Search',
  kind: 'claim',
  understanding: {
    primaryClaim: 'Warm water cures diabetes.',
    verifiablePoints: ['warm water cures diabetes'],
    excluded: [],
    hasFactualClaim: true
  },
  sources: [
    {
      url: 'https://www.nih.gov/example',
      title: 'NIH page',
      snippet: 'No evidence.',
      publishedAt: '2024-01-02',
      quality: { tier: 'HIGH', reason: 'Government domain — treated as an official primary source.' }
    },
    {
      url: 'https://unknown.example/post',
      title: 'Unknown',
      snippet: 'Maybe.',
      publishedAt: null,
      quality: { tier: 'UNKNOWN', reason: 'Publisher not recognised, so its editorial standards cannot be assessed.' }
    }
  ],
  independence: {
    totalSources: 2,
    uniqueHostCount: 2,
    independentCount: 2,
    note: 'No same-publisher groups detected.',
    hostGroups: [],
    originGroups: [],
    repeatedIndexes: [],
    uncertainIndexes: [],
    repeatedReason: {},
    uncertainReason: {}
  },
  timeline: { entries: [{ date: '2024-01-02', desc: 'NIH page', certainty: 'provider-reported', dateType: 'unspecified' }], missingCount: 1, missingIndexes: [1], earliest: null },
  errors: [],
  searchFailed: false,
  result: validated
});

function walk(node, acc) {
  if (!node) return acc;
  if (node.textContent) acc.push(node.textContent);
  (node.children || []).forEach(function (child) { walk(child, acc); });
  return acc;
}

const card = walk(extras['.claim-card'], []).join('\n');
const activity = byId['results-provider-activity'].textContent;
process.stdout.write(JSON.stringify({
  assessment: byId['results-assessment'].textContent,
  bridge: card,
  activity: activity,
  hasHigh: card.indexOf('high') >= 0,
  hasIndependent: card.indexOf('independent') >= 0,
  hasVerifiedLimit: card.indexOf('Verified and Partially verified are not confirmed') >= 0,
  unresolved: card.indexOf('Unresolved') >= 0,
  openai: activity.indexOf('OpenAI claim extraction ran') >= 0,
  parallel: activity.indexOf('Parallel search returned 2 stored source(s)') >= 0,
  noDollar: activity.indexOf('$') < 0
}));
"""
    completed = subprocess.run(
        ["node", "-e", script, str(ENGINE)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    body = json.loads(completed.stdout)
    assert body["assessment"] == "Unresolved"
    assert body["hasHigh"] is True
    assert body["hasIndependent"] is True
    assert body["hasVerifiedLimit"] is True
    assert body["unresolved"] is True
    assert body["openai"] is True
    assert body["parallel"] is True
    assert body["noDollar"] is True
