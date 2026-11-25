"""Frontend Content Credentials presentation for sealed provenance.

Temporary fixtures only. The live ledger is not opened.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENGINE = ROOT / "frontend" / "engine.js"
STYLES = ROOT / "frontend" / "styles.css"

OUTCOME_TEXT = {
    "VERIFIED": "Verified",
    "PARTIALLY_VERIFIED": "Partially verified",
    "CONTRADICTED": "Contradicted",
    "INSUFFICIENT_EVIDENCE": "Insufficient evidence",
    "POTENTIAL_MANIPULATION": "Potential manipulation",
    "UNRESOLVED": "Unresolved",
}

_PROVENANCE_SCRIPT = r"""
const fs = require('fs');
const vm = require('vm');

const byId = {};
const extras = {};

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
      if (name === 'data-provenance-status') node['data-provenance-status'] = String(value);
      if (name === 'data-availability') node['data-availability'] = String(value);
      if (name === 'aria-expanded') node['aria-expanded'] = String(value);
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
      const on = (' ' + node.className + ' ').indexOf(' ' + name + ' ') >= 0;
      if (force === true || (!on && force !== false)) node.classList.add(name);
      else node.classList.remove(name);
    }
  };
  Object.defineProperty(node, 'id', {
    get() { return node._id; },
    set(value) {
      node._id = String(value || '');
      if (node._id) byId[node._id] = node;
    }
  });
  return node;
}

function matches(node, sel) {
  if (!sel) return false;
  if (sel.charAt(0) === '#') return node.id === sel.slice(1);
  if (sel.charAt(0) === '.') {
    return (' ' + (node.className || '') + ' ').indexOf(' ' + sel.slice(1) + ' ') >= 0;
  }
  if (sel.indexOf('[') >= 0) {
    const match = /^([a-z0-9-]*)\[([^=\]]+)(?:=\"([^\"]*)\")?\]$/i.exec(sel);
    if (!match) return false;
    if (match[1] && node.tagName.toLowerCase() !== match[1].toLowerCase()) return false;
    const value = node.getAttribute(match[2]);
    if (match[3] == null) return value != null;
    return value === match[3];
  }
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
  console,
  URL,
  JSON,
  Math,
  Date,
  Promise,
  setTimeout,
  clearTimeout,
  scrollTo() {}
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

function walk(node, acc) {
  if (!node) return acc;
  if (node.textContent) acc.push(node.textContent);
  (node.children || []).forEach(function (child) { walk(child, acc); });
  return acc;
}

function bodyText() {
  return walk(byId['results-body'], []).join('\n');
}

function provenanceNode() {
  if (byId['content-credentials']) return byId['content-credentials'];
  const body = byId['results-body'];
  if (!body) return null;
  return queryAll(body, '#content-credentials')[0] || null;
}

function provenanceText() {
  return walk(provenanceNode(), []).join('\n');
}

function statusLabel() {
  const node = provenanceNode();
  if (!node) return '';
  const labels = queryAll(node, '.provenance-label');
  return labels[0] ? labels[0].textContent : '';
}

function statusTone() {
  const node = provenanceNode();
  if (!node) return '';
  const statuses = queryAll(node, '.provenance-status');
  return statuses[0] ? statuses[0].getAttribute('data-provenance-status') || '' : '';
}

function htmlChildCount() {
  const node = provenanceNode();
  if (!node) return 0;
  let count = 0;
  function scan(item) {
    if (!item) return;
    if (item.tagName === 'SCRIPT' || item.tagName === 'IMG') count += 1;
    (item.children || []).forEach(scan);
  }
  scan(node);
  return count;
}

function checks(base) {
  return Object.assign({
    signature: 'valid',
    assetBinding: 'bound',
    certificateTrust: 'trusted',
    certificateValidity: 'inside_at_asserted_time',
    revocation: 'not_revoked',
    timestamp: 'trusted'
  }, base || {});
}

function image(digest) {
  return {
    sha256: digest || ('cd'.repeat(32)),
    byteLength: 12,
    mediaType: 'image/png'
  };
}

function policy() {
  return {
    releaseSequence: 4,
    activationDigest: 'ab'.repeat(32),
    suspensionDigest: 'cd'.repeat(32),
    manifestBundleSha256: 'ef'.repeat(32),
    timestampBundleSha256: '12'.repeat(32),
    rootUse: 'active',
    purpose: 'policy'
  };
}

function manifest(status, label, role, check) {
  return {
    label: label || 'urn:c2pa:active',
    role: role || 'active',
    status: status,
    checks: check || checks()
  };
}

function credential(status, options) {
  options = options || {};
  const img = image(options.digest);
  const itemChecks = options.checks || checks(
    status === 'credentials_untrusted' ? { certificateTrust: 'untrusted' } :
    status === 'credentials_invalid' ? { signature: 'invalid' } :
    status === 'credentials_malformed' ? { assetBinding: 'malformed' } : {}
  );
  const manifests = Object.prototype.hasOwnProperty.call(options, 'manifests')
    ? options.manifests
    : (status === 'no_credentials' || status === 'not_performed'
      ? []
      : [manifest(status, options.label, 'active', itemChecks)]);
  return {
    version: 'c2pa-provenance-1',
    verifiedAt: '2026-11-20T00:00:00Z',
    eventDepiction: 'not_established',
    image: options.image === undefined ? img : options.image,
    reader: { readerVersion: 'c2pa-reader-2', nativeLibraryVersion: '0.92.0' },
    policy: Object.prototype.hasOwnProperty.call(options, 'policy') ? options.policy : policy(),
    result: {
      kind: 'credential',
      status: status,
      failureCode: null,
      checks: Object.prototype.hasOwnProperty.call(options, 'resultChecks') ? options.resultChecks : (manifests.length === 1 ? itemChecks : null),
      manifests: manifests
    },
    pem: options.pem,
    path: options.path,
    latitude: options.latitude,
    privateKey: options.privateKey,
    actions: options.actions
  };
}

function technical(code, options) {
  options = options || {};
  return {
    version: 'c2pa-provenance-1',
    verifiedAt: '2026-11-20T00:00:00Z',
    eventDepiction: 'not_established',
    image: options.image === undefined ? image() : options.image,
    reader: { readerVersion: 'c2pa-reader-2', nativeLibraryVersion: '0.92.0' },
    policy: null,
    result: {
      kind: 'technical',
      status: 'verification_failed',
      failureCode: code,
      checks: null,
      manifests: []
    }
  };
}

function evidence(provenance, options) {
  options = options || {};
  const identity = options.identity || image();
  return {
    version: 'image-evidence-1',
    fileIdentity: {
      sha256: identity.sha256,
      mediaType: identity.mediaType,
      byteLength: identity.byteLength,
      assetId: 'a'.repeat(32)
    },
    receipt: {
      receivedAt: '2026-11-20T00:00:00+00:00',
      clientHashStatus: 'not_supplied',
      comparison: 'No hash was supplied by this device. The server hash is the file identity.'
    },
    retentionAtSeal: {
      retention: 'retained',
      consentVersion: 'image-upload-1',
      statement: 'When this assessment was sealed, the server was retaining this file. It may subsequently be removed when the investigation or account is deleted.'
    },
    currentFile: { availability: 'retained', checkedAt: '2026-11-20T00:01:00+00:00' },
    snapshotId: 'b'.repeat(32),
    embeddedMetadata: options.embedded || { status: 'not_extracted' },
    provenance: provenance,
    alteration: {
      documentedEvidence: options.documented || 'none_recorded',
      technicalIndicators: 'not_examined',
      originalComparison: 'no_separate_original'
    }
  };
}

function renderCase(name, provenance, options) {
  Object.keys(byId).forEach(function (key) { delete byId[key]; });
  Object.keys(extras).forEach(function (key) { delete extras[key]; });
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
  byId['why-toggle'] = makeEl('button');
  byId['why-toggle'].id = 'why-toggle';
  extras['.claim-card'] = makeEl('div');

  const validated = sandbox.RC.reasoning.validate({
    assessment: 'INSUFFICIENT_EVIDENCE',
    findings: [],
    originalMaterial: { established: false, description: '', source: null },
    why: { supporting: '', contradicting: '', sourceQuality: '', timeline: '', uncertain: '', choice: '' },
    uncertainty: [],
    imageEvidence: evidence(provenance, options)
  }, 0);

  sandbox.RC.ui.render({
    input: 'The event happened.',
    live: false,
    provider: 'none',
    understanding: { primaryClaim: 'The event happened.', verifiablePoints: [], excluded: [], hasFactualClaim: true },
    sources: [],
    independence: {
      totalSources: 0,
      uniqueHostCount: 0,
      independentCount: 0,
      note: 'No sources were retrieved.',
      hostGroups: [],
      originGroups: [],
      repeatedIndexes: [],
      uncertainIndexes: [],
      repeatedReason: {},
      uncertainReason: {}
    },
    timeline: { entries: [], missingCount: 0, missingIndexes: [], earliest: null },
    errors: [],
    result: validated
  });

  return {
    name: name,
    assessment: byId['results-assessment'].textContent,
    assessmentClass: byId['results-assessment'].className,
    label: statusLabel(),
    tone: statusTone(),
    body: bodyText(),
    provenance: provenanceText(),
    projected: validated.imageEvidence && validated.imageEvidence.provenance,
    alteration: bodyText().indexOf('This assessment did not record a cited sentence') >= 0,
    embedded: bodyText().indexOf('The server has not read embedded metadata from this file.') >= 0,
    eventText: bodyText().indexOf('Content Credentials can help establish the provenance and integrity of an image. They do not prove that the event depicted in the image actually happened.') >= 0,
    htmlChildren: htmlChildCount(),
    detailsOpen: (function () {
      const details = provenanceNode() ? queryAll(provenanceNode(), 'details') : [];
      return details[0] ? !!details[0].open : null;
    })()
  };
}

const results = {
  trusted: renderCase('trusted', credential('credentials_trusted')),
  untrusted: renderCase('untrusted', credential('credentials_untrusted')),
  invalid: renderCase('invalid', credential('credentials_invalid')),
  malformed: renderCase('malformed', credential('credentials_malformed')),
  none: renderCase('none', credential('no_credentials', { resultChecks: null, manifests: [], policy: null })),
  notPerformed: renderCase('notPerformed', credential('not_performed', { resultChecks: null, manifests: [], policy: null })),
  missing: renderCase('missing', null),
  historical: renderCase('historical', { version: 'absent', status: 'not_examined', eventDepiction: 'not_established' }),
  technical: renderCase('technical', technical('reader_timeout')),
  trustConfig: renderCase('trustConfig', technical('trust_configuration')),
  multi: renderCase('multi', credential('credentials_untrusted', {
    resultChecks: null,
    manifests: [
      manifest('credentials_trusted', 'urn:c2pa:active', 'active', checks()),
      manifest('credentials_untrusted', 'urn:c2pa:ingredient', 'ingredient', checks({ certificateTrust: 'untrusted' }))
    ]
  })),
  mismatch: renderCase('mismatch', credential('credentials_trusted', { digest: 'ab'.repeat(32) })),
  injection: renderCase('injection', credential('credentials_trusted', { label: '<script>alert(1)</script>' })),
  sensitive: renderCase('sensitive', credential('credentials_trusted', {
    pem: '-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----',
    path: '/workspace/data/trust/root.json',
    latitude: '51.507351',
    privateKey: '-----BEGIN PRIVATE KEY-----\nTUlJ\n-----END PRIVATE KEY-----',
    actions: [{ action: 'c2pa.edited' }]
  })),
  unknownStatus: renderCase('unknownStatus', {
    version: 'c2pa-provenance-1',
    verifiedAt: '2026-11-20T00:00:00Z',
    eventDepiction: 'not_established',
    image: image(),
    reader: { readerVersion: 'c2pa-reader-2', nativeLibraryVersion: '0.92.0' },
    policy: policy(),
    result: {
      kind: 'credential',
      status: 'credentials_legendary',
      failureCode: null,
      checks: checks(),
      manifests: [manifest('credentials_trusted')]
    }
  }),
  unknownCheck: renderCase('unknownCheck', credential('credentials_trusted', {
    checks: Object.assign(checks(), { signature: 'perfect' })
  })),
  malformedValue: renderCase('malformedValue', 'not-an-object'),
  emptyChecks: renderCase('emptyChecks', credential('credentials_trusted', {
    resultChecks: null,
    manifests: [manifest('credentials_trusted', 'urn:c2pa:active', 'active', checks())]
  })),
  sourceLinked: renderCase('sourceLinked', null, { documented: 'source_linked' })
};

const assessSource = fs.readFileSync(process.argv[1], 'utf8');
const assessBody = assessSource.split('function assess')[1].split('function validate')[0];
results.assessSendsOnlyToken = /assessmentToken:\s*sealed\.assessmentToken/.test(assessBody)
  && assessBody.indexOf('imageEvidence:') < 0
  && assessBody.indexOf('provenance:') < 0
  && assessBody.indexOf('primaryClaim:') < 0;
results.noInnerHtml = assessSource.indexOf('innerHTML') < 0;
results.noPlaceholder = assessSource.indexOf("c2pa: 'not_examined'") < 0
  && assessSource.indexOf('No provenance manifest was read.') < 0;
results.hasContentCredentials = assessSource.indexOf('Content Credentials') >= 0;

process.stdout.write(JSON.stringify(results));
"""


def _run():
    completed = subprocess.run(
        ["node", "-e", _PROVENANCE_SCRIPT, str(ENGINE)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    return json.loads(completed.stdout)


def test_frontend_preserves_server_provenance_and_status_labels():
    body = _run()
    assert body["assessSendsOnlyToken"] is True
    assert body["noInnerHtml"] is True
    assert body["noPlaceholder"] is True
    assert body["hasContentCredentials"] is True

    expected = {
        "trusted": ("Credential trusted", "trusted"),
        "untrusted": ("Signer not trusted", "untrusted"),
        "invalid": ("Credential invalid", "invalid"),
        "malformed": ("Credential malformed", "malformed"),
        "none": ("No credentials", "none"),
        "notPerformed": ("Not performed", "not-performed"),
        "missing": ("Not examined", "not-examined"),
        "historical": ("Not examined", "not-examined"),
        "technical": ("Technical failure", "technical"),
        "trustConfig": ("Technical failure", "technical"),
        "multi": ("Signer not trusted", "untrusted"),
        "mismatch": ("Technical failure", "technical"),
        "injection": ("Technical failure", "technical"),
        "sensitive": ("Credential trusted", "trusted"),
        "unknownStatus": ("Not recognized", "unrecognized"),
        "unknownCheck": ("Not recognized", "unrecognized"),
        "malformedValue": ("Technical failure", "technical"),
    }
    for name, (label, tone) in expected.items():
        case = body[name]
        assert case["label"] == label, name
        assert case["tone"] == tone, name
        assert case["assessment"] == OUTCOME_TEXT["INSUFFICIENT_EVIDENCE"], name
        assert "assessment-insufficient" in case["assessmentClass"], name
        assert case["eventText"] is True, name
        assert "Verified" not in case["provenance"] or label == "Credential trusted"
        assert "Contradicted" not in case["provenance"]
        assert "Potential manipulation" not in case["provenance"]
        assert case["detailsOpen"] is False or case["detailsOpen"] is None


def test_trusted_and_multi_manifest_details_are_shown_without_secrets():
    body = _run()
    trusted = body["trusted"]
    assert "urn:c2pa:active" in trusted["provenance"]
    assert "The signature checked as valid." in trusted["provenance"]
    assert "The certificate checked as trusted under the sealed policy." in trusted["provenance"]
    assert "A trusted timestamp was checked." in trusted["provenance"]
    assert "The revocation check did not report the credential as revoked." in trusted["provenance"]
    assert "This credential record is bound to the sealed file." in trusted["provenance"]
    assert trusted["projected"]["result"]["status"] == "credentials_trusted"
    assert "pem" not in trusted["projected"]
    assert "privateKey" not in json.dumps(trusted["projected"])

    multi = body["multi"]
    assert "urn:c2pa:active" in multi["provenance"]
    assert "urn:c2pa:ingredient" in multi["provenance"]
    assert "Ingredient" in multi["provenance"]
    assert multi["projected"]["result"]["status"] == "credentials_untrusted"
    assert multi["projected"]["result"]["checks"] is None

    sensitive = body["sensitive"]
    rendered = sensitive["provenance"]
    assert "BEGIN CERTIFICATE" not in rendered
    assert "PRIVATE KEY" not in rendered
    assert "/workspace/data/trust/root.json" not in rendered
    assert "51.507351" not in rendered
    assert "c2pa.edited" not in rendered
    assert "pem" not in sensitive["projected"]
    assert "path" not in sensitive["projected"]
    assert "latitude" not in sensitive["projected"]
    assert "actions" not in sensitive["projected"]


def test_failures_hide_credentials_and_do_not_invent_success():
    body = _run()
    for name in ("missing", "historical", "technical", "trustConfig", "mismatch", "injection", "malformedValue"):
        case = body[name]
        assert "The signature checked as valid." not in case["provenance"], name
        assert "urn:c2pa:active" not in case["provenance"], name
        assert "Credential trusted" not in case["provenance"], name
    assert "The reader could not finish verification." in body["technical"]["provenance"]
    assert "Trust configuration was not available." in body["trustConfig"]["provenance"]
    assert body["mismatch"]["projected"]["result"]["kind"] == "technical"
    assert body["injection"]["htmlChildren"] == 0
    assert "<script>" not in body["injection"]["provenance"]
    assert body["none"]["projected"]["result"]["status"] == "no_credentials"
    assert "No manifests were returned." in body["none"]["provenance"]
    assert "No per-check results were returned." in body["none"]["provenance"]
    assert body["emptyChecks"]["label"] == "Credential trusted"
    assert "The signature checked as valid." in body["emptyChecks"]["provenance"]


def test_assessment_banner_and_other_image_sections_remain():
    body = _run()
    trusted = body["trusted"]
    assert trusted["assessment"] == "Insufficient evidence"
    assert trusted["embedded"] is True
    assert trusted["alteration"] is True
    linked = body["sourceLinked"]
    assert "A cited stored sentence names this sealed SHA-256 and states fabrication." in linked["body"]
    assert "No technical alteration test was run." in linked["body"]
    assert "Local image metadata on this device" not in trusted["body"]


def test_styles_support_wrapping_and_keyboard_details():
    css = STYLES.read_text()
    assert "overflow-wrap: anywhere" in css
    assert ".provenance-details summary" in css
    assert "min-height: 44px" in css
    assert "@media (max-width: 640px)" in css
    script = ENGINE.read_text()
    assert "No provenance manifest was read." not in script
    assert "c2pa: 'not_examined'" not in script
    assert "data-provenance-status" in script
    assess = script.split("function assess")[1].split("function validate")[0]
    assert "assessmentToken: sealed.assessmentToken" in assess
    assert "imageEvidence:" not in assess
    assert "provenance:" not in assess
