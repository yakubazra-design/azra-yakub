/* ============================================================
   RealityCheck AI — Phase 2 investigation engine
   Layers (kept deliberately separate):
     RC.runtime    capability detection
     RC.retrieval  source retrieval providers (pluggable)
     RC.quality    source-quality framework
     RC.evidence   evidence processing (independence, timeline)
     RC.reasoning  model-backed language work
     RC.engine     orchestration
     RC.ui         rendering only
   ============================================================ */
(function () {
  'use strict';

  var RC = (window.RC = {});
  RC.version = 'phase2-0.1.0';

  /* ---------------------------------------------------------
     Small helpers
     --------------------------------------------------------- */
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  /* Local EXIF coordinates stay at two decimal places. The precise value
     is shown only after the sealed-record reveal request. */
  function roundLocalCoordinate(value) {
    if (typeof value !== 'number' || !isFinite(value)) return null;
    var negative = value < 0;
    var hundredths = Math.round(Math.abs(value) * 100);
    var rounded = hundredths / 100;
    if (rounded === 0) return 0;
    return negative ? -rounded : rounded;
  }

  function formatLocalCoordinate(value) {
    if (typeof value !== 'number' || !isFinite(value)) return 'Not available';
    var negative = value < 0;
    var hundredths = Math.round(Math.abs(value) * 100);
    var text = (hundredths / 100).toFixed(2);
    if (text === '0.00') return '0.00';
    return negative ? '-' + text : text;
  }

  function isUrl(s) {
    var t = (s || '').trim();
    if (/\s/.test(t)) return false;
    return /^https?:\/\/[^\s]+\.[^\s]+/i.test(t);
  }

  function hostOf(url) {
    try { return new URL(url).hostname.replace(/^www\./, '').toLowerCase(); }
    catch (e) { return ''; }
  }

  /* A source may be shown as a link only when it is an http or https URL.
     The same check runs on the server before the row is stored. */
  function sourceLinkUrl(value) {
    if (typeof value !== 'string') return null;
    var raw = value.trim();
    if (!raw || raw.length > 2048) return null;
    var i;
    for (i = 0; i < raw.length; i++) {
      var code = raw.charCodeAt(i);
      if (code < 33 || code === 127 || raw.charAt(i) === '\\') return null;
    }
    var match = /^([A-Za-z][A-Za-z0-9+.-]*):\/\//.exec(raw);
    if (!match) return null;
    var scheme = match[1].toLowerCase();
    if (scheme !== 'http' && scheme !== 'https') return null;
    try {
      var parsed = new URL(raw);
      if (parsed.protocol !== scheme + ':' || !parsed.hostname || parsed.port === '0') return null;
    } catch (e) {
      return null;
    }
    return raw;
  }

  function sourceAction(url, label) {
    var safe = sourceLinkUrl(url);
    if (safe) {
      var link = document.createElement('a');
      link.className = 'source-view';
      link.href = safe;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      link.textContent = label;
      return link;
    }
    var shown = typeof url === 'string' ? url.trim() : '';
    if (shown.length > 2048) shown = shown.slice(0, 2048);
    return el('span', 'source-desc', shown);
  }

  RC.sourceLinkUrl = sourceLinkUrl;
  RC.sourceAction = sourceAction;

  /* Same-origin calls to the FastAPI routes. Prompts are built on the
     server; this helper only carries structured inputs and error bodies. */
  var csrfToken = null;
  var openAuth = function () {};

  function authHeaders(headers) {
    var copy = headers || {};
    if (csrfToken) copy['X-CSRF-Token'] = csrfToken;
    return copy;
  }

  function readJsonResponse(response) {
    return response.text().then(function (text) {
      var payload = {};
      if (text) {
        try { payload = JSON.parse(text); } catch (e) { payload = {}; }
      }
      if (!response.ok) {
        throw {
          code: payload.code,
          message: payload.message || 'The request could not be completed.'
        };
      }
      return payload;
    });
  }

  function apiPost(path, body) {
    return fetch(path, {
      method: 'POST',
      headers: authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify(body)
    }).then(readJsonResponse);
  }

  function apiDelete(path, body) {
    return fetch(path, {
      method: 'DELETE',
      headers: authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify(body || {})
    }).then(readJsonResponse);
  }

  function apiPostBytes(path, bytes, headers) {
    return fetch(path, {
      method: 'POST',
      headers: authHeaders(headers || {}),
      body: bytes
    }).then(readJsonResponse);
  }

  var activeInvestigationId = null;

  function apiGet(path) {
    return fetch(path, { headers: authHeaders({}) }).then(function (response) {
      return response.text().then(function (text) {
        var payload = {};
        if (text) {
          try { payload = JSON.parse(text); } catch (e) { payload = {}; }
        }
        if (!response.ok) {
          throw {
            code: payload.code,
            message: payload.message || 'The request could not be completed.'
          };
        }
        return payload;
      });
    });
  }

  function serverEvidence() {
    return apiGet('/api/investigations/' + activeInvestigationId + '/evidence');
  }

  /* The connector supplies one date field with no type attached, and it
     has been observed to be a crawl/index date as often as a true
     publication date. Rather than call every such date "published," the
     text is checked for an explicit label; absent one, the date is kept
     but marked as unspecified rather than assumed. */
  function detectDateType(text) {
    var s = String(text || '');
    if (/\blast\s+updated\b|\bupdated\s+on\b|\bupdated:\s*\w/i.test(s)) return 'updated';
    if (/\bpublished\s+(on|:)?\s*\w|\bpublication\s+date\b|\bposted\s+on\b/i.test(s)) return 'published';
    return 'unspecified';
  }

  function tooltip(msg) {
    var t = $('#tooltip');
    if (!t) return;
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(tooltip._t);
    tooltip._t = setTimeout(function () { t.classList.remove('show'); }, 3200);
  }

  function clearTooltip() {
    var t = $('#tooltip');
    if (!t) return;
    clearTimeout(tooltip._t);
    t.classList.remove('show');
    t.textContent = '';
  }

  function syncInvestigationConsentUi() {
    var box = document.getElementById('investigation-consent');
    var btn = document.getElementById('check-btn');
    var hint = document.getElementById('consent-gate-hint');
    var given = !!(box && box.checked);
    if (btn) {
      btn.classList.toggle('is-consent-blocked', !given);
      if (given) {
        btn.removeAttribute('aria-disabled');
        btn.removeAttribute('aria-describedby');
      } else {
        btn.setAttribute('aria-disabled', 'true');
        if (hint) btn.setAttribute('aria-describedby', 'consent-gate-hint');
      }
    }
    if (hint) hint.hidden = given;
    if (given) clearTooltip();
  }

  /* ---------------------------------------------------------
     RC.runtime — what this page can actually do
     --------------------------------------------------------- */
  RC.runtime = (function () {
    var state = { resolved: false, sample: null, mcp: null };
    var waiters = [];

    function resolve(v) {
      state.resolved = true;
      state.sample = v.sample;
      state.mcp = v.mcp;
      waiters.forEach(function (fn) { try { fn(state); } catch (e) {} });
      waiters = [];
    }

    function begin() {
      fetch('/api/health').then(function (response) {
        if (!response.ok) throw new Error('health');
        return response.json();
      }).then(function (body) {
        resolve({
          sample: body && body.openaiConfigured ? { configured: true } : null,
          mcp: body && body.parallelConfigured ? { configured: true } : null
        });
      }).catch(function () {
        resolve({ sample: null, mcp: null });
      });
    }

    function ready() {
      if (state.resolved) return Promise.resolve(state);
      return new Promise(function (res) { waiters.push(res); });
    }

    return { begin: begin, ready: ready, state: state };
  })();

  /* ---------------------------------------------------------
     RC.retrieval — provider abstraction
     Every provider must implement:
        id, label, available(rt) -> bool
        searchSources(queries) -> Promise<[rawSource]>   queries: string[]
        fetchSource(url) -> Promise<{url, title, text, publishedAt}>
     A rawSource is: {url, title, snippet, publishedAt|null, dateCertainty, provider}
     --------------------------------------------------------- */
  RC.retrieval = (function () {
    var providers = {};
    var activeId = 'none';

    /* --- The null provider. Retrieves nothing and says so. --- */
    providers.none = {
      id: 'none',
      label: 'No retrieval provider connected',
      available: function () { return true; },
      searchSources: function () {
        return Promise.reject({
          code: 'no_provider',
          message: 'No retrieval provider is connected, so no sources can be searched.'
        });
      },
      fetchSource: function () {
        return Promise.reject({
          code: 'no_provider',
          message: 'No retrieval provider is connected, so the page could not be fetched.'
        });
      }
    };

    /* --- Parallel Search, via the mcp capability. --------------
       Schema confirmed against the live connector before this was
       written (web_search / web_fetch request and response shapes).
       Call contract (server addressing, callTool signature, error
       codes) taken from the platform's own mcp.d.ts, not assumed.
       ---------------------------------------------------------- */
    var PARALLEL_SERVER = 'Parallel Search';
    var sessionId = (function () {
      var s = '';
      for (var i = 0; i < 32; i++) s += Math.floor(Math.random() * 16).toString(16);
      return 'rc-' + s;
    })();

    function mcpNamespace() { return RC.runtime.state.mcp; }

    /* Provider constraint: 3-6 words per query. Never invented —
       only reshaped from what the claim-understanding stage produced. */
    function clampQuery(q) {
      var words = String(q || '').trim().split(/\s+/).filter(Boolean);
      if (words.length > 6) words = words.slice(0, 6);
      return words.join(' ');
    }

    function mcpErrorMessage(err) {
      var code = err && err.code;
      var known = {
        needs_reauth: 'Parallel Search needs to be reconnected in Settings → Connectors.',
        server_not_connected: 'Parallel Search is not connected for this view.',
        selection_required: 'More than one matching connector is available and none has been chosen.',
        blocked_by_policy: 'Parallel Search is blocked by organisation policy for this view.',
        approval_required: 'This call requires approval that has not been given.',
        server_unavailable: 'Parallel Search did not respond in time.',
        upstream_error: 'Parallel Search could not be reached just now. This is usually temporary — try the check again.',
        not_granted: 'This view was not granted connector access.',
        capability_disabled: 'Connector access is not available in this view.',
        tool_error: 'Parallel Search reported an error: ' + (err.message || 'no further detail given.'),
        not_in_manifest: 'This call is outside what the viewer allowed for this page.'
      };
      return known[code] || (err && err.message) || 'The search provider could not complete this request.';
    }

    /* Per the platform's own mcp contract: only errors stamped
       retryable:true may be retried unattended, at most once, after a
       short (optionally server-specified) delay, and only for reads —
       both calls below are reads. Everything else is surfaced as-is. */
    function withRetry(fn) {
      return fn().catch(function (err) {
        if (!err || err.retryable !== true) return Promise.reject(err);
        var wait = err.retryAfterMs || (500 + Math.floor(Math.random() * 500));
        return new Promise(function (resolve) { setTimeout(resolve, wait); }).then(fn);
      });
    }

    providers.parallel = {
      id: 'parallel',
      label: 'Parallel Search',
      available: function (rt) { return !!(rt && rt.mcp); },

      /* queries: string[] — one batched call, matching the connector's
         own design (it accepts several search_queries per call). */
      searchSources: function (queries) {
        var mcp = mcpNamespace();
        if (!mcp) {
          return Promise.reject({ code: 'no_mcp', message: 'Live investigation is currently unavailable.' });
        }
        var clamped = (queries || []).map(clampQuery).filter(Boolean).slice(0, 5);
        if (!clamped.length) return Promise.resolve([]);

        return withRetry(function () {
          return apiPost('/api/investigations/' + activeInvestigationId + '/search', {
            queries: clamped,
            sessionId: sessionId
          });
        }).then(function (payload) {
          var sources = payload && Array.isArray(payload.sources) ? payload.sources : [];
          return sources.filter(function (s) { return s && s.url; });
        }, function (err) {
          return Promise.reject({ code: err && err.code, message: mcpErrorMessage(err) });
        });
      },

      fetchSource: function (url) {
        var mcp = mcpNamespace();
        if (!mcp) {
          return Promise.reject({ code: 'no_mcp', message: 'Live investigation is currently unavailable.' });
        }
        return withRetry(function () {
          return apiPost('/api/investigations/' + activeInvestigationId + '/fetch', {});
        }).then(function (page) {
          if (!page || !page.text) {
            return Promise.reject({ code: 'fetch_empty', message: 'The page returned no usable content.' });
          }
          return {
            url: page.url || url,
            title: page.title || null,
            text: page.text,
            publishedAt: page.publishedAt || null,
            dateCertainty: page.dateCertainty || 'provider-reported',
            dateType: page.dateType || null,
            quality: page.quality
          };
        }, function (err) {
          return Promise.reject({ code: err && err.code, message: mcpErrorMessage(err) });
        });
      }
    };

    function register(p) { providers[p.id] = p; }

    function use(id) { activeId = providers[id] ? id : 'none'; return activeId; }

    function active() {
      var p = providers[activeId];
      if (p && p.available(RC.runtime.state)) return p;
      return providers.none;
    }

    function isLive() { return active().id !== 'none'; }

    return {
      register: register,
      use: use,
      active: active,
      isLive: isLive,
      list: function () { return Object.keys(providers); }
    };
  })();

  /* ---------------------------------------------------------
     RC.quality — source-quality framework
     Deterministic and explainable. No numeric score, because
     there is no methodology behind a number here.
     --------------------------------------------------------- */
  RC.quality = (function () {
    var HIGH_EXACT = [
      'who.int', 'un.org', 'europa.eu', 'worldbank.org', 'imf.org', 'oecd.org',
      'nih.gov', 'cdc.gov', 'fda.gov', 'nhs.uk', 'ecdc.europa.eu',
      'nature.com', 'science.org', 'thelancet.com', 'nejm.org', 'bmj.com',
      'jamanetwork.com', 'cell.com', 'pubmed.ncbi.nlm.nih.gov', 'ncbi.nlm.nih.gov',
      'cochranelibrary.com', 'who.europe.int', 'idf.org', 'diabetes.org',
      'pib.gov.in', 'rbi.org.in', 'icmr.gov.in', 'mohfw.gov.in'
    ];
    var MEDIUM_EXACT = [
      'reuters.com', 'apnews.com', 'bbc.com', 'bbc.co.uk', 'npr.org',
      'nytimes.com', 'washingtonpost.com', 'theguardian.com', 'ft.com',
      'economist.com', 'aljazeera.com', 'dw.com', 'france24.com',
      'thehindu.com', 'indianexpress.com', 'hindustantimes.com', 'ndtv.com',
      'timesofindia.indiatimes.com', 'livemint.com', 'scroll.in',
      'snopes.com', 'factcheck.org', 'politifact.com', 'fullfact.org',
      'altnews.in', 'boomlive.in', 'healthline.com', 'mayoclinic.org',
      'clevelandclinic.org', 'webmd.com', 'arxiv.org', 'biorxiv.org', 'medrxiv.org',
      'britannica.com'
    ];
    var LOW_EXACT = [
      'facebook.com', 'x.com', 'twitter.com', 'instagram.com', 'tiktok.com',
      'reddit.com', 'quora.com', 'pinterest.com', 'youtube.com', 'medium.com',
      'substack.com', 'blogspot.com', 'wordpress.com', 'tumblr.com',
      'whatsapp.com', 'telegram.org', 'linkedin.com'
    ];
    /* Crowd-editable structured databases: broadly reliable for simple
       factual lookups, but not editorially reviewed in the way a
       publication or agency source is. Kept as its own tier reason
       rather than folded into MEDIUM_EXACT's "established organisation"
       wording, since the basis for trust is different. */
    var STRUCTURED_DB_EXACT = ['wikidata.org', 'wikipedia.org'];
    /* An organization's own official domain, when the claim concerns
       that organization's own subject. Explicitly a primary source for
       facts about itself — not automatically independent corroboration
       of anything (independence is a separate check; see RC.evidence). */
    var PRIMARY_ORG_EXACT = ['toureiffel.paris'];

    function endsWithAny(host, list) {
      return list.some(function (d) { return host === d || host.endsWith('.' + d); });
    }

    function classify(url) {
      var host = hostOf(url);
      if (!host) return { tier: 'UNKNOWN', reason: 'No usable address for this source.' };

      if (/\.gov$/.test(host) || /\.gov\.[a-z]{2}$/.test(host) || /\.mil$/.test(host)) {
        return { tier: 'HIGH', reason: 'Government domain — treated as an official primary source.' };
      }
      if (/\.edu$/.test(host) || /\.ac\.[a-z]{2}$/.test(host) || /\.edu\.[a-z]{2}$/.test(host)) {
        return { tier: 'HIGH', reason: 'Academic institution domain.' };
      }
      if (endsWithAny(host, HIGH_EXACT)) {
        return { tier: 'HIGH', reason: 'Recognised official, intergovernmental or peer-reviewed publisher.' };
      }
      if (endsWithAny(host, PRIMARY_ORG_EXACT)) {
        return { tier: 'HIGH', reason: 'Official site of the subject itself — a primary source for facts about it, though it is not independent corroboration from an outside party.' };
      }
      if (endsWithAny(host, STRUCTURED_DB_EXACT)) {
        return { tier: 'MEDIUM', reason: 'Structured, crowd-edited knowledge database — broadly reliable for simple facts, but not an editorially reviewed publication.' };
      }
      if (endsWithAny(host, ['arxiv.org', 'biorxiv.org', 'medrxiv.org'])) {
        return { tier: 'MEDIUM', reason: 'Preprint server — not yet peer reviewed.' };
      }
      if (endsWithAny(host, MEDIUM_EXACT)) {
        return { tier: 'MEDIUM', reason: 'Established news, specialist or fact-checking organisation.' };
      }
      if (endsWithAny(host, LOW_EXACT)) {
        return { tier: 'LOW', reason: 'User-generated platform — content is not editorially verified.' };
      }
      if (/\.(blog|xyz|top|click|info)$/.test(host)) {
        return { tier: 'LOW', reason: 'Domain type commonly used for unverified content.' };
      }
      return { tier: 'UNKNOWN', reason: 'Publisher not recognised, so its editorial standards cannot be assessed.' };
    }

    var RANK = { HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
    function rank(tier) { return RANK[tier] || 0; }

    return { classify: classify, rank: rank };
  })();

  /* ---------------------------------------------------------
     RC.evidence — evidence processing
     --------------------------------------------------------- */
  RC.evidence = (function () {

    function tokens(s) {
      return new Set(
        (s || '').toLowerCase()
          .replace(/[^a-z0-9\s]/g, ' ')
          .split(/\s+/)
          .filter(function (w) { return w.length > 3; })
      );
    }

    function jaccard(a, b) {
      if (!a.size || !b.size) return 0;
      var inter = 0;
      a.forEach(function (w) { if (b.has(w)) inter++; });
      return inter / (a.size + b.size - inter);
    }

    /* Fix 3 — shared-origin/echo detection.
       Only fires on an EXPLICIT attribution phrase in the retrieved
       text ("according to WHO...", "the WHO release...", "X reported
       that..."). Never inferred from topic similarity alone — that
       would be exactly the invented-relationship failure mode this
       is meant to avoid. */
    var ORIGIN_ALIASES = {
      'who': 'who', 'world health organization': 'who', 'world health organisation': 'who'
    };

    function normaliseOrigin(name) {
      var n = String(name || '').toLowerCase()
        .replace(/[^a-z0-9\s]/g, '')
        .replace(/\b(the|report|release|news|organization|organisation|study|statement)\b/g, '')
        .replace(/\s+/g, ' ')
        .trim();
      return ORIGIN_ALIASES[n] || n;
    }

    var ORIGIN_PATTERNS = [
      /according to (?:the )?([A-Z][A-Za-z0-9&.'-]+(?:\s+[A-Z][A-Za-z0-9&.'-]+){0,4})/,
      /\bthe\s+([A-Z][A-Za-z0-9&.'-]+(?:\s+[A-Z][A-Za-z0-9&.'-]+){0,4})\s+(?:release|report|statement|study)\b/,
      /\b([A-Z][A-Za-z0-9&.'-]+(?:\s+[A-Z][A-Za-z0-9&.'-]+){0,3})\s+(?:reported|reports|announced|announces|says|said|found|finds|warns|warned)\b/
    ];

    function detectOrigin(text) {
      var s = String(text || '');
      for (var i = 0; i < ORIGIN_PATTERNS.length; i++) {
        var m = s.match(ORIGIN_PATTERNS[i]);
        if (m && m[1]) {
          var norm = normaliseOrigin(m[1]);
          if (norm && norm.length >= 2) return norm;
        }
      }
      return null;
    }

    /* Cross-domain mirror detection (e.g. a paper on its journal site
       and its PMC/repository copy). Different domains, so host-based
       grouping (Fix 1) and explicit-attribution grouping (Fix 3) both
       miss this — a title/author/DOI match is the only real signal
       available, and each is checked separately so weak, single-signal
       matches can be told apart from corroborated ones. */

    function extractDOI(text) {
      var m = String(text || '').match(/\b10\.\d{4,9}\/[^\s"'<>)]+/i);
      return m ? m[0].replace(/[.,;]+$/, '').toLowerCase() : null;
    }

    /* Strips the trailing "site name" clutter search results attach to
       titles ("... - PMC", "| Nature", "... Reuters") so the same paper
       indexed on two sites compares on its actual title, not on which
       site happened to append what. */
    function normaliseTitle(title) {
      return String(title || '')
        .replace(/\s+[-|·–—]\s*([A-Z][A-Za-z0-9.&']{1,15}(?:\s+[A-Za-z0-9.&']{1,15}){0,2})$/, '')
        .toLowerCase()
        .replace(/[^a-z0-9\s]/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();
    }

    function titleTokens(title) {
      return new Set(normaliseTitle(title).split(' ').filter(function (w) { return w.length > 2; }));
    }

    /* Author-by-line, e.g. "by B Fernando" in a search-result snippet. */
    function extractAuthor(text) {
      var m = String(text || '').match(/\bby\s+([A-Z][A-Za-z.]*\s+[A-Z][a-zA-Z'-]+)\b/);
      return m ? m[1].toLowerCase().replace(/\./g, '').trim() : null;
    }

    /* Small union-find so a source repeated by more than one signal
       (same host AND shared origin, say) still only counts once. */
    function unionFind(n) {
      var parent = [];
      for (var i = 0; i < n; i++) parent[i] = i;
      function find(x) { return parent[x] === x ? x : (parent[x] = find(parent[x])); }
      function union(a, b) { var ra = find(a), rb = find(b); if (ra !== rb) parent[Math.max(ra, rb)] = Math.min(ra, rb); }
      return { find: find, union: union };
    }

    /* Groups sources into independence clusters using several signals:
       - same normalised host (Fix 1) — a publisher is not several
         publishers just because it has several pages.
       - shared explicit origin attribution (Fix 3) — several outlets
         all citing the same named release are one underlying source,
         not several confirmations.
       - matching DOI — the strongest possible signal that two
         different domains carry the exact same paper.
       - near-identical wording (existing) — likely one copied from
         another even with no attribution phrase.
       - near-identical title, ONLY when corroborated by a second signal
         (matching author or a DOI on either side) — confidently merged.
         A title match with no corroboration is real but weaker, so it
         is surfaced as "possible shared origin, independence uncertain"
         rather than silently merged, per the instruction not to pretend
         certainty the data doesn't support.
       Different domains covering the same topic in their own words,
       with none of the above, are left alone: that is genuine
       independent reporting, not a duplicate. */
    function independence(sources) {
      var n = sources.length;
      var toks = sources.map(function (s) { return tokens(s.snippet || s.title); });
      var hosts = sources.map(function (s) { return hostOf(s.url); });
      var origins = sources.map(function (s) { return detectOrigin(s.snippet || s.title); });
      var dois = sources.map(function (s) { return extractDOI(s.snippet) || extractDOI(s.url); });
      var titleToks = sources.map(function (s) { return titleTokens(s.title); });
      var authors = sources.map(function (s) { return extractAuthor(s.snippet); });

      var uf = unionFind(n);
      var textPairs = [];
      var originPairs = [];
      var doiPairs = [];
      var uncertainPairs = [];

      for (var i = 0; i < n; i++) {
        for (var j = i + 1; j < n; j++) {
          var sameHost = hosts[i] && hosts[i] === hosts[j];
          var sameOrigin = origins[i] && origins[i] === origins[j];
          var sameDoi = dois[i] && dois[i] === dois[j];
          var sameText = jaccard(toks[i], toks[j]) >= 0.55;
          var titleSim = jaccard(titleToks[i], titleToks[j]);
          var sameTitle = titleSim >= 0.6 && titleToks[i].size >= 3;
          var sameAuthor = authors[i] && authors[i] === authors[j];

          if (sameHost) uf.union(i, j);
          if (sameOrigin) { uf.union(i, j); originPairs.push([i, j]); }
          if (sameDoi) { uf.union(i, j); doiPairs.push([i, j]); }
          if (sameText) { uf.union(i, j); textPairs.push([i, j]); }

          if (!sameHost && !sameOrigin && !sameDoi && !sameText && sameTitle) {
            if (sameAuthor) {
              /* Title match corroborated by a matching author — confident
                 merge even without a host or DOI match. */
              uf.union(i, j);
              doiPairs.push([i, j]);
            } else {
              /* Title match alone: real signal, not enough on its own. */
              uncertainPairs.push([i, j]);
            }
          }
        }
      }

      /* Host groups, reported independently of the merged clusters so
         "unique hosts" stays a separate, legible statistic. */
      var byHost = {};
      hosts.forEach(function (h, i) { if (!h) return; (byHost[h] = byHost[h] || []).push(i); });
      var hostGroups = Object.keys(byHost).map(function (h) { return { host: h, indexes: byHost[h] }; })
        .filter(function (g) { return g.indexes.length > 1; });
      var uniqueHostCount = Object.keys(byHost).length + hosts.filter(function (h) { return !h; }).length;

      var originGroups = {};
      originPairs.forEach(function (p) {
        var key = origins[p[0]];
        (originGroups[key] = originGroups[key] || new Set()).add(p[0]).add(p[1]);
      });
      var originGroupList = Object.keys(originGroups).map(function (k) {
        return { origin: k, indexes: Array.from(originGroups[k]) };
      });

      /* Final clusters from the union-find, in the original shape
         (an array of index arrays) so downstream code is unaffected. */
      var clusterMap = {};
      for (var k = 0; k < n; k++) {
        var root = uf.find(k);
        (clusterMap[root] = clusterMap[root] || []).push(k);
      }
      var clusters = Object.keys(clusterMap).map(function (r) { return clusterMap[r]; })
        .filter(function (g) { return g.length > 1; });

      var repeated = new Set();
      var reason = {};
      clusters.forEach(function (g) {
        g.slice(1).forEach(function (idx) {
          repeated.add(idx);
          var tags = [];
          if (hostGroups.some(function (hg) { return hg.indexes.indexOf(idx) >= 0 && hg.indexes.indexOf(g[0]) >= 0; })) tags.push('same publisher (' + hosts[idx] + ')');
          if (origins[idx] && origins[idx] === origins[g[0]]) tags.push('shares attributed origin (' + origins[idx] + ')');
          if (dois[idx] && dois[idx] === dois[g[0]]) tags.push('same DOI (' + dois[idx] + ')');
          if (jaccard(toks[idx], toks[g[0]]) >= 0.55) tags.push('shares near-identical wording');
          if (!tags.length && jaccard(titleToks[idx], titleToks[g[0]]) >= 0.6 && authors[idx] && authors[idx] === authors[g[0]]) {
            tags.push('same title and author (' + authors[idx] + ') — likely the same study mirrored on a different site');
          }
          reason[idx] = tags.length ? tags.join('; ') : 'grouped with source [' + g[0] + ']';
        });
      });

      /* Uncertain pairs are never merged (independentCount is untouched
         by them) — only flagged, since the signal is real but not
         corroborated enough to state a relationship with confidence. */
      var uncertainSet = new Set();
      var uncertainReason = {};
      uncertainPairs.forEach(function (p) {
        [p[1], p[0]].forEach(function (idx, k) {
          var other = k === 0 ? p[0] : p[1];
          if (repeated.has(idx)) return; /* already confidently grouped elsewhere */
          uncertainSet.add(idx);
          uncertainReason[idx] = 'Possible shared origin with [' + other + '] — titles closely match but this could not be confirmed (no matching author or identifier found) — independence uncertain.';
        });
      });

      var noteParts = [];
      if (hostGroups.length) noteParts.push(hostGroups.length + ' publisher(s) supplied more than one of the retrieved pages.');
      if (originGroupList.length) noteParts.push(originGroupList.length + ' group(s) of sources explicitly attribute their claim to the same original release or organisation.');
      if (doiPairs.length) noteParts.push(doiPairs.length + ' pair(s) of sources matched on a publication identifier, author, or title — treated as the same underlying study mirrored across sites.');
      if (uncertainSet.size) noteParts.push(uncertainSet.size + ' source(s) have a title close enough to another that they may share an origin, but this could not be confirmed — flagged rather than merged.');
      if (textPairs.length && !hostGroups.length && !originGroupList.length && !doiPairs.length) noteParts.push('Some sources share very similar wording despite different publishers, suggesting one was copied from another.');
      if (!noteParts.length) noteParts.push('No two retrieved sources appear to share a publisher, an attributed origin, or near-identical wording — treated as independent.');

      return {
        totalSources: n,
        uniqueHostCount: uniqueHostCount,
        hostGroups: hostGroups,
        originGroups: originGroupList,
        clusters: clusters,
        repeatedIndexes: Array.from(repeated),
        repeatedReason: reason,
        uncertainIndexes: Array.from(uncertainSet),
        uncertainReason: uncertainReason,
        independentCount: clusters.length ? (n - repeated.size) : n,
        note: noteParts.join(' ')
      };
    }

    /* Dates only ever come from what a source actually supplied.
       Nothing is inferred to fill a gap. */
    function buildTimeline(sources) {
      var entries = [];
      var missing = [];

      sources.forEach(function (s, i) {
        if (s.publishedAt) {
          entries.push({
            date: s.publishedAt,
            certainty: s.dateCertainty || 'confirmed',
            dateType: s.dateType || 'unspecified',
            desc: (s.title || hostOf(s.url)),
            sourceIndex: i
          });
        } else {
          missing.push(i);
        }
      });

      entries.sort(function (a, b) { return a.date < b.date ? -1 : a.date > b.date ? 1 : 0; });

      return {
        entries: entries,
        missingCount: missing.length,
        missingIndexes: missing,
        earliest: entries.length ? entries[0] : null
      };
    }

    function summarise(sources) {
      var counts = { HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
      sources.forEach(function (s) { counts[s.quality.tier]++; });
      return counts;
    }

    return {
      independence: independence,
      buildTimeline: buildTimeline,
      summarise: summarise
    };
  })();

  /* ---------------------------------------------------------
     RC.reasoning — model-backed language work.
     Every call is constrained to the material handed to it.
     --------------------------------------------------------- */
  RC.reasoning = (function () {

    function sampleFn() { return RC.runtime.state.sample; }

    function available() { return !!sampleFn(); }

    function extractClaims(input, kind) {
      var s = sampleFn();
      if (!s) return Promise.reject({ code: 'no_model', message: 'Claim analysis is unavailable in this view.' });

      var prompt =
        'You are the claim-analysis stage of an evidence-investigation tool.\n' +
        'Read the submitted ' + (kind === 'url' ? 'web page text' : 'text') + ' and identify only the factual assertions that could in principle be checked against evidence.\n\n' +
        'Rules:\n' +
        '- Opinions, predictions, questions and subjective statements are NOT factual claims.\n' +
        '- Do not evaluate whether anything is true. Only identify what is being asserted.\n' +
        '- Write each verifiable point so it can stand alone.\n' +
        '- Search queries should be short and neutral, not leading.\n\n' +
        'SUBMITTED MATERIAL:\n"""\n' + String(input).slice(0, 6000) + '\n"""\n\n' +
        'Reply with JSON only, no prose and no code fences:\n' +
        '{"hasFactualClaim":boolean,"primaryClaim":string,"verifiablePoints":[string],' +
        '"excluded":[{"text":string,"reason":string}],"searchQueries":[string]}';

      /* The prompt string above stays in this file. The request sends the
         submitted text only; the server builds and sends the prompt. */
      return apiPost('/api/investigations/' + activeInvestigationId + '/extract-claims', {
        kind: kind === 'url' ? 'url' : 'claim'
      }).then(function (r) {
        return {
          hasFactualClaim: !!r.hasFactualClaim,
          primaryClaim: r.primaryClaim || String(input).slice(0, 300),
          verifiablePoints: Array.isArray(r.verifiablePoints) ? r.verifiablePoints.slice(0, 6) : [],
          excluded: Array.isArray(r.excluded) ? r.excluded.slice(0, 5) : [],
          searchQueries: Array.isArray(r.searchQueries) ? r.searchQueries.slice(0, 5) : []
        };
      });
    }

    function assess(ctx) {
      var s = sampleFn();
      if (!s) return Promise.reject({ code: 'no_model', message: 'Assessment is unavailable in this view.' });

      var catalogue = ctx.sources.map(function (src, i) {
        return '[' + i + '] host=' + hostOf(src.url) +
          ' | quality=' + src.quality.tier +
          ' | date=' + (src.publishedAt || 'not available') +
          ' | title=' + (src.title || 'not available') +
          '\n     text: ' + (src.snippet || '').slice(0, 700);
      }).join('\n');

      /* Image bytes, camera details, location, and hashes are not assembled
         into this local prompt. The server builds the assessment prompt and
         does not receive those fields from this request. */
      var imageBlock = '';

      var prompt =
        'You are the assessment stage of an evidence-investigation tool. You must reason ONLY from the numbered sources and the image evidence (if present) below.\n\n' +
        'Absolute rules:\n' +
        '- Never introduce a source, URL, date, study or organisation that is not in the list.\n' +
        '- Refer to web sources only by their number. Refer to image evidence by name, never by a [number].\n' +
        '- Repetition is not confirmation. Sources flagged as sharing wording must not be counted as separate confirmation.\n' +
        '- Do not weigh by count. One HIGH-quality source can outweigh several LOW or UNKNOWN ones.\n' +
        '- If the evidence does not settle the question, say so. Do not manufacture certainty.\n\n' +
        'CLAIM: ' + ctx.primaryClaim + '\n' +
        'VERIFIABLE POINTS:\n' + ctx.verifiablePoints.map(function (p, i) { return (i + 1) + '. ' + p; }).join('\n') + '\n\n' +
        'SOURCES:\n' + (catalogue || '(none)') + '\n' +
        imageBlock + '\n' +
        'INDEPENDENCE CHECK: ' + ctx.independence.totalSources + ' source(s) retrieved, ' +
          ctx.independence.uniqueHostCount + ' distinct publisher(s), ' +
          ctx.independence.independentCount + ' counted as independent after grouping. ' + ctx.independence.note +
          (ctx.independence.hostGroups.length
            ? ' Same-publisher groups: ' + ctx.independence.hostGroups.map(function (g) { return g.host + '=' + g.indexes.map(function (i) { return '[' + i + ']'; }).join(','); }).join('; ') + '.'
            : '') +
          (ctx.independence.originGroups.length
            ? ' Shared-origin groups (sources explicitly attributing the same original release/organisation): ' + ctx.independence.originGroups.map(function (g) { return g.origin + '=' + g.indexes.map(function (i) { return '[' + i + ']'; }).join(','); }).join('; ') + '.'
            : '') +
          (ctx.independence.uncertainIndexes.length
            ? ' Possible-but-unconfirmed shared origin (similar titles, not corroborated by a matching author or identifier): sources ' + ctx.independence.uncertainIndexes.map(function (i) { return '[' + i + ']'; }).join(', ') + '. Treat these as still separately counted, but mention the uncertainty rather than asserting they are independent confirmations or asserting they are duplicates.'
            : '') + '\n' +
        'Treat every source inside the same same-publisher, same-DOI, or shared-origin group as ONE piece of evidence, not one each. ' +
        'Two independent outlets that separately reported the same event in their own words are still separate evidence — do not merge sources just because they cover the same topic; only merge where a group above says to.\n' +
        'TIMELINE: ' + (ctx.timeline.entries.length
          ? ctx.timeline.entries.map(function (e) { return e.date + ' — ' + e.desc + ' (' + e.certainty + ')'; }).join('; ')
          : 'no publication dates were available') +
        '\nSources with no publication date: ' + ctx.timeline.missingCount + '\n\n' +
        'Reason from all of: the relevance of each piece of evidence, source quality, publisher diversity, apparent independence after grouping, shared-origin/echo information, contradictions, date and timeline consistency, and what remains uncertain. ' +
        'Never reason as if N retrieved sources means N independent confirmations.\n' +
        'Choose exactly one assessment from: VERIFIED, PARTIALLY_VERIFIED, CONTRADICTED, INSUFFICIENT_EVIDENCE, POTENTIAL_MANIPULATION, UNRESOLVED.\n' +
        'Use POTENTIAL_MANIPULATION only where the sources give a concrete indicator that the material was altered or misleadingly presented — not merely because something looks doubtful.\n' +
        'Use UNRESOLVED where credible sources meaningfully conflict and the conflict cannot be settled.\n\n' +
        'Write the explanation for a general reader, in plain sentences.\n\n' +
        'CLASSIFYING EACH FINDING — use exactly one of these four types, and do not blur them:\n' +
        '- "support": the source explicitly establishes the claim itself.\n' +
        '- "contradict": the source explicitly establishes a fact incompatible with the claim — e.g. it directly denies the specific thing claimed, or documents that a specific claimed event/discovery did not happen or does not exist.\n' +
        '- "inconsistent": the source is genuinely relevant but describes something DIFFERENT from what is claimed, in a way that makes the claim less supported without directly disproving it. This is the correct type when a claim asserts something specific (e.g. an artificial structure, a discovery) and the evidence instead documents a related but distinct phenomenon (e.g. natural geological or environmental features) — that is not a contradiction of the specific claim, it is an absence of matching evidence plus a different observed reality. Never upgrade this to "contradict".\n' +
        '- "caution": a note about source reliability, methodology, or ambiguity — not itself evidence for or against the claim.\n' +
        'If no source addresses the specific thing claimed at all, that is absence of evidence, not a contradiction — do not manufacture a "contradict" finding to fill the gap; let the assessment be INSUFFICIENT_EVIDENCE and say so in "why.contradicting" (e.g. "no source directly addresses this claim, so nothing here contradicts it either").\n\n' +
        'Reply with JSON only, no prose and no code fences:\n' +
        '{"assessment":string,' +
        '"findings":[{"type":"support"|"contradict"|"inconsistent"|"caution","text":string,"sources":[number]}],' +
        '"originalMaterial":{"established":boolean,"description":string,"source":number|null},' +
        '"why":{"supporting":string,"contradicting":string,"sourceQuality":string,"timeline":string,"uncertain":string,"choice":string},' +
        '"uncertainty":[string]}';

      /* The prompt string above stays in this file. The server seals the
         stored claim and evidence, then builds the prompt from that
         snapshot. This request sends only the single-use token. The image
         file, when the person confirmed sending it, was uploaded earlier.
         Camera details, location, and the browser hash are not sent here. */
      return apiPost('/api/investigations/' + activeInvestigationId + '/seal', {}).then(function (sealed) {
        return apiPost('/api/investigations/' + activeInvestigationId + '/assess', {
          assessmentToken: sealed.assessmentToken
        });
      }).then(function (r) {
        return validate(r, ctx.sources.length);
      });
    }

    var VALID = ['VERIFIED', 'PARTIALLY_VERIFIED', 'CONTRADICTED',
      'INSUFFICIENT_EVIDENCE', 'POTENTIAL_MANIPULATION', 'UNRESOLVED'];
    var FINDING_TEXT = {
      literally_aligned: 'This finding uses the same wording as a cited stored sentence. That match does not verify the claim.',
      not_established: 'This finding is not established by the cited stored text.',
      invalid_reference: 'This finding cites a source that is not in the stored evidence.',
      contradicted: 'A cited stored sentence is a direct grammatical reversal of this finding. That reversal is not a broader proof.'
    };
    var LIMITATION = 'The stored source text was checked for integrity and alignment only. Semantic support was not established.';
    var CONTRADICTION_NOTE = 'The contradicted outcome records a literal negation between the primary claim and one cited stored sentence. It does not prove a broader conclusion.';
    var MANIPULATION_NOTE = 'The manipulation outcome records a fabrication statement in a cited stored sentence that names the sealed asset. It does not prove how the asset was altered.';
    var INSUFFICIENT_NOTE = 'A lack of stored evidence is not confirmation of the claim.';

    function controlledCopy(outcome) {
      if (outcome === 'CONTRADICTED') {
        return {
          why: { supporting: '', contradicting: CONTRADICTION_NOTE, sourceQuality: '', timeline: '', uncertain: '', choice: CONTRADICTION_NOTE },
          uncertainty: [CONTRADICTION_NOTE]
        };
      }
      if (outcome === 'POTENTIAL_MANIPULATION') {
        return {
          why: { supporting: '', contradicting: '', sourceQuality: '', timeline: '', uncertain: '', choice: MANIPULATION_NOTE },
          uncertainty: [MANIPULATION_NOTE]
        };
      }
      if (outcome === 'INSUFFICIENT_EVIDENCE') {
        return {
          why: { supporting: '', contradicting: '', sourceQuality: '', timeline: '', uncertain: INSUFFICIENT_NOTE, choice: 'The outcome is insufficient evidence.' },
          uncertainty: [INSUFFICIENT_NOTE]
        };
      }
      return {
        why: { supporting: '', contradicting: '', sourceQuality: '', timeline: '', uncertain: LIMITATION, choice: 'The outcome is unresolved. Stored text was not accepted as proof of the claim.' },
        uncertainty: [LIMITATION]
      };
    }

    function controlledAssessment(value) {
      if (value === 'VERIFIED' || value === 'PARTIALLY_VERIFIED') return 'UNRESOLVED';
      return VALID.indexOf(value) >= 0 ? value : 'UNRESOLVED';
    }

    /* Model finding text is not shown for a caution or alignment status.
       The replacement states the server status without repeating the claim. */
    function facingFinding(f, ok) {
      var statuses = ['invalid_reference', 'literally_aligned', 'contradicted', 'not_established'];
      var evidenceStatus = statuses.indexOf(f.evidenceStatus) >= 0 ? f.evidenceStatus : '';
      var type = 'caution';
      var text = FINDING_TEXT.not_established;
      if (evidenceStatus === 'invalid_reference') text = FINDING_TEXT.invalid_reference;
      else if (evidenceStatus === 'literally_aligned') text = FINDING_TEXT.literally_aligned;
      else if (evidenceStatus === 'contradicted') {
        type = 'contradict';
        text = FINDING_TEXT.contradicted;
      } else if (!evidenceStatus && f.type === 'contradict') {
        type = 'contradict';
        text = FINDING_TEXT.contradicted;
      }
      var finding = {
        type: type,
        text: text,
        sources: (Array.isArray(f.sources) ? f.sources : []).filter(ok)
      };
      if (evidenceStatus) {
        finding.evidenceStatus = evidenceStatus;
        finding.alignmentReason = typeof f.alignmentReason === 'string' ? f.alignmentReason : '';
      }
      return finding;
    }

    /* Anything referring to a source that was never retrieved is
       dropped rather than shown. */
    function validate(r, sourceCount) {
      var ok = function (n) { return Number.isInteger(n) && n >= 0 && n < sourceCount; };

      var assessment = controlledAssessment(r.assessment);
      if (sourceCount === 0) assessment = 'INSUFFICIENT_EVIDENCE';

      var findings = (Array.isArray(r.findings) ? r.findings : [])
        .map(function (f) { return facingFinding(f, ok); })
        .filter(function (f) { return f.text.length > 0; });

      var om = r.originalMaterial || {};
      var copy = controlledCopy(assessment);
      return {
        assessment: assessment,
        findings: findings,
        originalMaterial: {
          established: false,
          description: '',
          source: ok(om.source) ? om.source : null
        },
        why: copy.why,
        uncertainty: copy.uncertainty,
        imageEvidence: serverImageEvidence(r.imageEvidence),
        videoEvidence: serverVideoEvidence(r.videoEvidence)
      };
    }

    /* The assessment response may carry the server presentation. A browser
       metadata object, or a client-supplied hash, is not that record. */
    function serverEmbeddedMetadata(value) {
      var allowed = {
        not_performed: true,
        extraction_failed: true,
        malformed: true,
        unsupported_format: true,
        unsupported_structure: true,
        no_supported_metadata: true,
        extracted: true,
        not_extracted: true
      };
      if (!value || !allowed[value.status]) return { status: 'not_extracted' };
      var consent = value.consent || {};
      var copy = {
        status: value.status,
        consent: {
          uploadConsentVersion: typeof consent.uploadConsentVersion === 'string' ? consent.uploadConsentVersion : '',
          metadataConsentVersion: typeof consent.metadataConsentVersion === 'string' ? consent.metadataConsentVersion : '',
          metadataConsentDecision: typeof consent.metadataConsentDecision === 'string' ? consent.metadataConsentDecision : '',
          metadataConsentAt: typeof consent.metadataConsentAt === 'string' ? consent.metadataConsentAt : ''
        },
        fields: {}
      };
      if (value.status !== 'extracted' && value.status !== 'no_supported_metadata') return copy;
      var fields = value.fields || {};
      ['make', 'model', 'orientation', 'software', 'dateTime', 'dateTimeOriginal', 'dateTimeDigitized'].forEach(function (name) {
        copy.fields[name] = serverTextField(fields[name]);
      });
      copy.fields.gps = serverGpsField(fields.gps);
      return copy;
    }

    function serverTextField(field) {
      if (!field || field.status === 'absent') return { status: 'absent' };
      if (field.status !== 'present' && field.status !== 'conflict') return { status: 'malformed', values: [] };
      var values = [];
      (field.values || []).forEach(function (item) {
        if (!item || typeof item.value !== 'string' || item.value.length > 128) return;
        if (/\d{2,}\.\d{6}/.test(item.value)) return;
        values.push({ value: item.value, occurrences: serverOccurrences(item.occurrences, false) });
      });
      if (field.status === 'present' && values.length !== 1) return { status: 'malformed', values: [] };
      if (field.status === 'conflict' && values.length < 2) return { status: 'malformed', values: [] };
      return { status: field.status, values: values };
    }

    function serverGpsField(field) {
      if (!field || field.status === 'absent') return { status: 'absent' };
      if (field.status !== 'present' && field.status !== 'conflict') return { status: 'malformed', values: [] };
      var values = [];
      (field.values || []).forEach(function (item) {
        if (!item || !/^-?\d{1,3}\.\d{2}$/.test(item.latitude) || !/^-?\d{1,3}\.\d{2}$/.test(item.longitude)) return;
        values.push({
          latitude: item.latitude,
          longitude: item.longitude,
          occurrences: serverOccurrences(item.occurrences, true)
        });
      });
      if (field.status === 'present' && values.length !== 1) return { status: 'malformed', values: [] };
      if (field.status === 'conflict' && values.length < 2) return { status: 'malformed', values: [] };
      return { status: field.status, values: values };
    }

    function serverOccurrences(items, gps) {
      return (items || []).map(function (item) {
        var copy = {
          container: item && typeof item.container === 'string' ? item.container : '',
          blockIndex: item && Number.isInteger(item.blockIndex) ? item.blockIndex : 0
        };
        if (gps) copy.sourceTags = item && item.sourceTags || {};
        else copy.sourceTag = item && Number.isInteger(item.sourceTag) ? item.sourceTag : 0;
        return copy;
      });
    }

    var SHA256_TEXT = /^[0-9a-f]{64}$/;
    var PROVENANCE_TIME = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
    var MANIFEST_LABEL = /^[A-Za-z0-9:._~/#?&=%+-]{1,200}$/;
    var READER_TOKEN = /^[A-Za-z0-9._-]{1,32}$/;
    var PROVENANCE_MEDIA = { 'image/jpeg': true, 'image/png': true, 'image/gif': true, 'image/webp': true };
    var CREDENTIAL_STATUSES = {
      no_credentials: true,
      not_performed: true,
      credentials_malformed: true,
      credentials_invalid: true,
      credentials_untrusted: true,
      credentials_trusted: true
    };
    var MANIFEST_STATUSES = {
      credentials_malformed: true,
      credentials_invalid: true,
      credentials_untrusted: true,
      credentials_trusted: true
    };
    var CHECK_ENUMS = {
      signature: { valid: true, invalid: true, missing: true, not_checked: true },
      assetBinding: { bound: true, mismatch: true, missing: true, malformed: true, not_checked: true },
      certificateTrust: { trusted: true, untrusted: true, not_checked: true },
      certificateValidity: { inside_at_asserted_time: true, expired: true, outside: true, not_checked: true },
      revocation: { not_revoked: true, revoked: true, skipped: true, unknown: true, inaccessible: true, not_checked: true },
      timestamp: { trusted: true, absent: true, untrusted: true, malformed: true, outside_validity: true, not_checked: true }
    };
    var CHECK_NAMES = ['signature', 'assetBinding', 'certificateTrust', 'certificateValidity', 'revocation', 'timestamp'];
    var FAILURE_CODES = {
      activation_inconsistent: true,
      activation_record_corrupt: true,
      activation_record_missing: true,
      approval_substitution: true,
      duplicate_approver: true,
      memory_limit: true,
      no_committed_policy: true,
      policy_downgrade: true,
      policy_superseded: true,
      reader_crash: true,
      reader_timeout: true,
      reader_unavailable: true,
      root_pin_inconsistent: true,
      root_pin_unavailable: true,
      root_recovery_incomplete: true,
      root_suspended: true,
      root_suspension_unavailable: true,
      sequence_conflict: true,
      sequence_state_inconsistent: true,
      sequence_state_stale: true,
      suspension_history_unavailable: true,
      suspension_regression: true,
      suspension_state_stale: true,
      trust_configuration: true,
      unauthorized_approval: true,
      untrusted_admin_key: true,
      witness_conflict: true,
      witness_corrupt: true,
      witness_unavailable: true
    };

    function historicalProvenance() {
      return {
        version: 'absent',
        status: 'not_examined',
        eventDepiction: 'not_established'
      };
    }

    function technicalProvenance(code) {
      return {
        version: 'c2pa-provenance-1',
        eventDepiction: 'not_established',
        verifiedAt: null,
        image: null,
        reader: null,
        policy: null,
        result: {
          kind: 'technical',
          status: 'verification_failed',
          failureCode: code || null,
          checks: null,
          manifests: []
        }
      };
    }

    function unrecognizedProvenance() {
      return {
        version: 'c2pa-provenance-1',
        eventDepiction: 'not_established',
        verifiedAt: null,
        image: null,
        reader: null,
        policy: null,
        result: {
          kind: 'unrecognized',
          status: 'unrecognized',
          failureCode: null,
          checks: null,
          manifests: []
        }
      };
    }

    function projectTime(value) {
      return typeof value === 'string' && PROVENANCE_TIME.test(value) ? value : null;
    }

    function projectImage(value) {
      if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
      if (typeof value.sha256 !== 'string' || !SHA256_TEXT.test(value.sha256)) return null;
      if (typeof value.byteLength !== 'number' || value.byteLength < 0 || value.byteLength > 8388608 || Math.floor(value.byteLength) !== value.byteLength) return null;
      if (PROVENANCE_MEDIA[value.mediaType] !== true) return null;
      return { sha256: value.sha256, byteLength: value.byteLength, mediaType: value.mediaType };
    }

    function sameImage(image, identity) {
      return !!image && !!identity && image.sha256 === identity.sha256 && image.byteLength === identity.byteLength && image.mediaType === identity.mediaType;
    }

    function projectReader(value) {
      if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
      var reader = {};
      if (typeof value.readerVersion === 'string' && READER_TOKEN.test(value.readerVersion)) reader.readerVersion = value.readerVersion;
      if (typeof value.nativeLibraryVersion === 'string' && READER_TOKEN.test(value.nativeLibraryVersion)) reader.nativeLibraryVersion = value.nativeLibraryVersion;
      if (!reader.readerVersion && !reader.nativeLibraryVersion) return null;
      return reader;
    }

    function projectPolicy(value) {
      if (value == null) return { ok: true, policy: null };
      if (typeof value !== 'object' || Array.isArray(value)) return { ok: false };
      var sequence = value.releaseSequence;
      if (typeof sequence !== 'number' || sequence < 1 || sequence > 1000000000 || Math.floor(sequence) !== sequence) return { ok: false };
      var names = ['activationDigest', 'suspensionDigest', 'manifestBundleSha256', 'timestampBundleSha256'];
      var policy = { releaseSequence: sequence };
      var index;
      for (index = 0; index < names.length; index++) {
        if (typeof value[names[index]] !== 'string' || !SHA256_TEXT.test(value[names[index]])) return { ok: false };
        policy[names[index]] = value[names[index]];
      }
      if (value.rootUse !== 'active' && value.rootUse !== 'verify-only') return { ok: false };
      if (value.purpose !== 'policy' && value.purpose !== 'suspension') return { ok: false };
      policy.rootUse = value.rootUse;
      policy.purpose = value.purpose;
      return { ok: true, policy: policy };
    }

    function projectChecks(value) {
      if (value == null) return { ok: true, checks: null };
      if (typeof value !== 'object' || Array.isArray(value)) return { ok: false };
      var checks = {};
      var index;
      for (index = 0; index < CHECK_NAMES.length; index++) {
        var name = CHECK_NAMES[index];
        if (CHECK_ENUMS[name][value[name]] !== true) return { ok: false };
        checks[name] = value[name];
      }
      return { ok: true, checks: checks };
    }

    function projectManifests(value) {
      if (value == null) return { ok: true, manifests: [] };
      if (!Array.isArray(value) || value.length > 16) return { ok: false };
      var manifests = [];
      var index;
      for (index = 0; index < value.length; index++) {
        var item = value[index];
        if (!item || typeof item !== 'object' || Array.isArray(item)) return { ok: false };
        if (typeof item.label !== 'string' || !MANIFEST_LABEL.test(item.label)) return { ok: false, unsafe: true };
        if (item.role !== 'active' && item.role !== 'ingredient' && item.role !== 'unreferenced') return { ok: false };
        if (MANIFEST_STATUSES[item.status] !== true) return { ok: false };
        var checks = projectChecks(item.checks);
        if (!checks.ok || !checks.checks) return { ok: false };
        manifests.push({
          label: item.label,
          role: item.role,
          status: item.status,
          checks: checks.checks
        });
      }
      return { ok: true, manifests: manifests };
    }

    function projectTechnical(value, identity) {
      var result = value.result;
      var code = result.failureCode == null ? null : result.failureCode;
      if (code != null && FAILURE_CODES[code] !== true) return unrecognizedProvenance();
      var image = value.image == null ? null : projectImage(value.image);
      if (value.image != null && (!image || !sameImage(image, identity))) return technicalProvenance(null);
      if (result.checks != null || (result.manifests != null && (!Array.isArray(result.manifests) || result.manifests.length !== 0))) {
        return technicalProvenance(code);
      }
      var policy = projectPolicy(value.policy);
      if (!policy.ok) return technicalProvenance(code);
      return {
        version: 'c2pa-provenance-1',
        verifiedAt: projectTime(value.verifiedAt),
        eventDepiction: 'not_established',
        image: image,
        reader: projectReader(value.reader),
        policy: policy.policy,
        result: {
          kind: 'technical',
          status: 'verification_failed',
          failureCode: code,
          checks: null,
          manifests: []
        }
      };
    }

    function projectCredential(value, identity) {
      var result = value.result;
      if (result.failureCode != null) return unrecognizedProvenance();
      var image = projectImage(value.image);
      if (!image || !sameImage(image, identity)) return technicalProvenance(null);
      var manifests = projectManifests(result.manifests);
      if (!manifests.ok) return manifests.unsafe ? technicalProvenance(null) : unrecognizedProvenance();
      var checks = projectChecks(result.checks);
      if (!checks.ok) return unrecognizedProvenance();
      if ((result.status === 'no_credentials' || result.status === 'not_performed') && (checks.checks || manifests.manifests.length)) {
        return unrecognizedProvenance();
      }
      var policy = projectPolicy(value.policy);
      if (!policy.ok) return technicalProvenance(null);
      return {
        version: 'c2pa-provenance-1',
        verifiedAt: projectTime(value.verifiedAt),
        eventDepiction: 'not_established',
        image: image,
        reader: projectReader(value.reader),
        policy: policy.policy,
        result: {
          kind: 'credential',
          status: result.status,
          failureCode: null,
          checks: checks.checks,
          manifests: manifests.manifests
        }
      };
    }

    /* Keep only the public provenance fields. Extra keys, including PEM,
       paths, and coordinates, are dropped. This does not verify a manifest. */
    function serverProvenance(value, identity) {
      if (value == null) return historicalProvenance();
      if (typeof value !== 'object' || Array.isArray(value)) return technicalProvenance(null);
      if (value.version === 'absent') {
        return value.status === 'not_examined' ? historicalProvenance() : unrecognizedProvenance();
      }
      if (value.version !== 'c2pa-provenance-1' || !value.result || typeof value.result !== 'object' || Array.isArray(value.result)) {
        return technicalProvenance(null);
      }
      if (value.result.kind === 'technical' && value.result.status === 'verification_failed') {
        return projectTechnical(value, identity);
      }
      if (value.result.kind === 'credential' && CREDENTIAL_STATUSES[value.result.status] === true) {
        return projectCredential(value, identity);
      }
      return unrecognizedProvenance();
    }

    function serverImageEvidence(value) {
      var identity = value && value.fileIdentity;
      if (!value || value.version !== 'image-evidence-1' || !identity) return null;
      if (typeof identity.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(identity.sha256)) return null;
      if (typeof identity.byteLength !== 'number' || identity.byteLength < 0) return null;
      return {
        version: 'image-evidence-1',
        fileIdentity: {
          sha256: identity.sha256,
          mediaType: typeof identity.mediaType === 'string' ? identity.mediaType : '',
          byteLength: identity.byteLength,
          assetId: typeof identity.assetId === 'string' ? identity.assetId : ''
        },
        receipt: receiptFields(value.receipt),
        retentionAtSeal: retentionFields(value.retentionAtSeal),
        currentFile: currentFileFields(value.currentFile),
        snapshotId: typeof value.snapshotId === 'string' && /^[0-9a-f]{32}$/.test(value.snapshotId) ? value.snapshotId : '',
        embeddedMetadata: serverEmbeddedMetadata(value.embeddedMetadata),
        provenance: serverProvenance(value.provenance, {
          sha256: identity.sha256,
          byteLength: identity.byteLength,
          mediaType: typeof identity.mediaType === 'string' ? identity.mediaType : ''
        }),
        alteration: {
          documentedEvidence: value.alteration && value.alteration.documentedEvidence === 'source_linked'
            ? 'source_linked' : 'none_recorded',
          technicalIndicators: 'not_examined',
          originalComparison: 'no_separate_original'
        }
      };
    }

    /* Server videoEvidence only. Client-authored objects are discarded. */
    function serverVideoEvidence(value) {
      var identity = value && value.fileIdentity;
      if (!value || value.version !== 'video-evidence-1' || !identity) return null;
      if (typeof identity.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(identity.sha256)) return null;
      if (typeof identity.byteLength !== 'number' || identity.byteLength < 0) return null;
      var disclaimer = typeof value.disclaimer === 'string' && value.disclaimer
        ? value.disclaimer
        : 'This information describes the identity and technical properties of the uploaded file. It does not establish authenticity, original recording time, publication history, or the truth of any claim.';
      var receipt = value.receipt || {};
      var retention = value.retentionAtSeal || {};
      var processing = value.processing || {};
      var provenance = value.provenance || {};
      return {
        version: 'video-evidence-1',
        disclaimer: disclaimer,
        snapshotId: typeof value.snapshotId === 'string' && /^[0-9a-f]{32}$/.test(value.snapshotId) ? value.snapshotId : '',
        fileIdentity: {
          sha256: identity.sha256,
          mediaType: typeof identity.mediaType === 'string' ? identity.mediaType : '',
          byteLength: identity.byteLength,
          assetId: typeof identity.assetId === 'string' ? identity.assetId : ''
        },
        receipt: {
          receivedAt: typeof receipt.receivedAt === 'string' ? receipt.receivedAt : '',
          sealedAt: typeof receipt.sealedAt === 'string' ? receipt.sealedAt : '',
          clientHashStatus: receipt.clientHashStatus,
          comparison: typeof receipt.comparison === 'string' ? receipt.comparison : ''
        },
        retentionAtSeal: {
          retention: typeof retention.retention === 'string' ? retention.retention : '',
          consentVersion: typeof retention.consentVersion === 'string' ? retention.consentVersion : '',
          metadataConsentDecision: typeof retention.metadataConsentDecision === 'string'
            ? retention.metadataConsentDecision : '',
          statement: typeof retention.statement === 'string' ? retention.statement : ''
        },
        technicalMetadata: value.technicalMetadata && typeof value.technicalMetadata === 'object'
          ? value.technicalMetadata : { status: 'not_disclosed' },
        processing: {
          attachmentStatusAtSeal: typeof processing.attachmentStatusAtSeal === 'string'
            ? processing.attachmentStatusAtSeal : '',
          probeStatus: typeof processing.probeStatus === 'string' ? processing.probeStatus : '',
          note: typeof processing.note === 'string' ? processing.note : ''
        },
        currentFile: currentFileFields(value.currentFile),
        provenance: {
          version: typeof provenance.version === 'string' ? provenance.version : 'absent',
          status: typeof provenance.status === 'string' ? provenance.status : 'not_examined',
          note: typeof provenance.note === 'string' ? provenance.note
            : 'C2PA video verification is outside the scope of this stage.'
        },
        alteration: {
          documentedEvidence: 'none_recorded',
          technicalIndicators: 'not_examined',
          originalComparison: 'no_separate_original'
        }
      };
    }

    function receiptFields(receipt) {
      var status = receipt && receipt.clientHashStatus;
      var known = { match: true, mismatch: true, unusable: true, not_supplied: true };
      if (!known[status]) status = 'not_supplied';
      return {
        receivedAt: receipt && typeof receipt.receivedAt === 'string' ? receipt.receivedAt : '',
        clientHashStatus: status,
        comparison: receipt && typeof receipt.comparison === 'string' ? receipt.comparison : ''
      };
    }

    function retentionFields(retention) {
      return {
        retention: retention && typeof retention.retention === 'string' ? retention.retention : '',
        consentVersion: retention && typeof retention.consentVersion === 'string' ? retention.consentVersion : '',
        statement: 'When this assessment was sealed, the server was retaining this file. It may subsequently be removed when the investigation or account is deleted.'
      };
    }

    function currentFileFields(current) {
      var availability = current && current.availability;
      var known = { retained: true, subsequently_deleted: true, not_checked: true, unavailable: true };
      if (!known[availability]) availability = 'not_checked';
      return {
        availability: availability,
        checkedAt: availability === 'not_checked' ? null : (current && typeof current.checkedAt === 'string' ? current.checkedAt : null)
      };
    }

    return { available: available, extractClaims: extractClaims, assess: assess, validate: validate };
  })();

  /* ---------------------------------------------------------
     RC.engine — orchestration
     --------------------------------------------------------- */
  RC.engine = (function () {

    var STEPS = ['understand', 'search', 'assess'];

    function investigate(rawInput, onStep) {
      var kind = isUrl(rawInput) ? 'url' : 'claim';
      var report = {
        kind: kind,
        input: rawInput,
        submittedAt: new Date().toISOString().slice(0, 10),
        provider: RC.retrieval.active().label,
        live: RC.retrieval.isLive(),
        pageClaim: null,
        /* Snapshotted once, here, at the moment "Check now" is pressed —
           a different image uploaded mid-run must not retroactively
           change what this investigation is evaluating. Independent of
           RC.evidence/RC.quality/RC.evidence.buildTimeline entirely: it
           never enters the sources array and is never fed to the
           independence or quality classifiers. */
        imageEvidence: RC.image.getEvidence(),
        errors: [],
        searchFailed: false
      };

      var step = function (name, state) { if (onStep) onStep(name, state); };

      return apiPost('/api/investigations', { input: String(rawInput), kind: kind })
        .then(function (created) {
          activeInvestigationId = created.investigationId;
          var upload = RC.image.confirmedUpload();
          if (!upload) return null;
          var headers = {
            'Content-Type': 'application/octet-stream',
            'X-Image-Consent': 'image-upload-1'
          };
          if (upload.clientSha256) headers['X-Client-Sha256'] = upload.clientSha256;
          if (upload.metadataConsent) headers['X-Image-Metadata-Consent'] = 'image-metadata-1';
          return apiPostBytes(
            '/api/investigations/' + created.investigationId + '/asset',
            upload.file,
            headers
          );
        })
        .then(function (asset) {
          if (asset) report.serverAsset = asset;
          return RC.runtime.ready();
        })
        .then(function () {
          /* ---- Step 1: understand ---- */
          step('understand', 'active');

          if (!RC.reasoning.available()) {
            throw {
              code: 'no_model',
              message: 'This view cannot reach the analysis model, so no part of the investigation can run.'
            };
          }

          if (kind === 'url') {
            return RC.retrieval.active().fetchSource(rawInput)
              .then(function (page) {
                report.pageClaim = {
                  url: rawInput,
                  title: page.title || null,
                  quality: page.quality,
                  publishedAt: page.publishedAt || null
                };
                return RC.reasoning.extractClaims(page.text, 'url');
              }, function (err) {
                report.errors.push({
                  stage: 'fetch',
                  message: err && err.message ? err.message : 'The page could not be fetched.'
                });
                report.pageClaim = { url: rawInput, title: null, quality: null, publishedAt: null };
                throw {
                  code: 'fetch_failed',
                  message: 'The submitted page could not be read, so its claims could not be identified. ' +
                    'An unavailable page does not establish that its claims are false. ' +
                    'Paste the passage you want checked as text instead.'
                };
              });
          }
          return RC.reasoning.extractClaims(rawInput, 'claim');
        })
        .then(function (understanding) {
          report.understanding = understanding;
          step('understand', 'done');

          if (!understanding.hasFactualClaim) {
            return serverEvidence().then(function (payload) {
              report.sources = payload.sources || [];
              report.independence = payload.independence;
              report.timeline = payload.timeline;
              report.result = {
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
              return report;
            });
          }

          /* ---- Step 2: search ---- */
          step('search', 'active');
          var queries = understanding.searchQueries.length
            ? understanding.searchQueries
            : [understanding.primaryClaim];

          return collect(queries, report).then(function (sources) {
            report.sources = sources;
            step('search', sources.length ? 'done' : 'failed');

            /* A search call that actually errored (connector down, rate
               limited, etc.) is a technical failure, not an evidence
               finding — it must not be presented as one of the six
               assessment outcomes. A search that succeeded and simply
               found nothing is a separate, legitimate case, handled
               further below. */
            if (!sources.length && report.searchFailed) {
              throw {
                code: 'search_failed',
                message: report.errors.length
                  ? report.errors[report.errors.length - 1].message
                  : 'The source search could not be completed due to a technical problem.'
              };
            }

            /* ---- Step 3: assessment against sealed stored evidence ---- */
            step('assess', 'active');

            if (!sources.length && !report.imageEvidence) {
              report.result = {
                assessment: 'INSUFFICIENT_EVIDENCE',
                findings: [],
                originalMaterial: { established: false, description: '', source: null },
                why: {
                  supporting: 'No sources were retrieved, so nothing supports the claim here.',
                  contradicting: 'No sources were retrieved, so nothing contradicts it here either.',
                  sourceQuality: 'Not applicable — no sources were retrieved.',
                  timeline: 'Information not available.',
                  uncertain: 'Everything about this claim remains unestablished.',
                  choice: report.live
                    ? 'The search returned no usable sources, so there is no evidence to weigh.'
                    : 'No retrieval provider is connected, so no search was performed. Nothing here has been checked against evidence.'
                },
                uncertainty: [report.live
                  ? 'No sources could be retrieved for this claim.'
                  : 'No evidence was gathered. Connect a search provider to run a real investigation.']
              };
              step('assess', 'done');
              return report;
            }

            return RC.reasoning.assess({
              primaryClaim: report.understanding.primaryClaim,
              verifiablePoints: report.understanding.verifiablePoints,
              sources: sources,
              independence: report.independence,
              timeline: report.timeline,
              imageEvidence: report.imageEvidence
            }).then(function (result) {
              report.result = result;
              step('assess', 'done');
              return report;
            });
          });
        });
    }

    function collect(queries, report) {
      var provider = RC.retrieval.active();
      if (provider.id === 'none') {
        return serverEvidence().then(function (payload) {
          report.independence = payload.independence;
          report.timeline = payload.timeline;
          return [];
        });
      }

      return provider.searchSources(queries).then(function () {
        return serverEvidence();
      }).then(function (payload) {
        report.independence = payload.independence;
        report.timeline = payload.timeline;
        return payload.sources || [];
      }, function (err) {
        if (report) {
          report.searchFailed = true;
          report.errors.push({
            stage: 'search',
            message: (err && err.message) || 'The source search could not be completed.'
          });
        }
        return [];
      });
    }

    return { investigate: investigate, STEPS: STEPS };
  })();

  /* ---------------------------------------------------------
     RC.ui — rendering
     --------------------------------------------------------- */
  RC.ui = (function () {

    var LABELS = {
      VERIFIED: { text: 'Verified', cls: 'assessment-verified' },
      PARTIALLY_VERIFIED: { text: 'Partially verified', cls: 'assessment-partial' },
      CONTRADICTED: { text: 'Contradicted', cls: 'assessment-contradicted' },
      INSUFFICIENT_EVIDENCE: { text: 'Insufficient evidence', cls: 'assessment-insufficient' },
      POTENTIAL_MANIPULATION: { text: 'Potential manipulation', cls: 'assessment-manipulation' },
      UNRESOLVED: { text: 'Unresolved', cls: 'assessment-unresolved' }
    };

    var CHAIN = ['Claim', 'Evidence', 'Sources', 'Original material', 'Timeline', 'Cross-check', 'Contradictions', 'Assessment'];

    function screen(name) {
      ['home', 'investigating', 'results'].forEach(function (s) {
        var n = $('#screen-' + s);
        if (n) n.classList.toggle('hidden', s !== name);
      });
      window.scrollTo({ top: 0, behavior: 'auto' });
    }

    function stepIndex(name) { return RC.engine.STEPS.indexOf(name); }

    function markStep(name, state) {
      var i = stepIndex(name);
      if (i < 0) return;
      var item = $('.check-item[data-step="' + i + '"]');
      if (!item) return;
      item.classList.remove('active', 'done');
      if (state === 'active') item.classList.add('active');
      if (state === 'done') item.classList.add('done');
    }

    function resetSteps() {
      $$('.check-item').forEach(function (n) { n.classList.remove('active', 'done'); });
    }

    function section(title, note) {
      var head = el('div', 'block-head');
      head.style.marginBottom = '20px';
      head.style.marginTop = '48px';
      var h = el('h2', null, title);
      h.style.fontSize = '20px';
      head.appendChild(h);
      if (note) head.appendChild(el('p', null, note));
      return head;
    }

    function qualityBadge(tier) {
      return el('span', 'quality-badge quality-' + tier.toLowerCase(), tier.replace('_', ' '));
    }

    function renderSourceCard(src, index, repeatedReason, uncertainReason) {
      var card = el('div', 'source-card');
      var name = el('span', 'source-name', src.title || hostOf(src.url));
      card.appendChild(name);

      var meta = el('div', 'source-meta-row');
      meta.appendChild(el('span', 'source-date', src.publishedAt || 'Date not available'));
      meta.appendChild(qualityBadge(src.quality.tier));
      card.appendChild(meta);

      card.appendChild(el('p', 'source-desc', src.quality.reason));

      if (src.snippet) {
        var snip = el('p', 'source-desc', '“' + src.snippet.slice(0, 220).trim() + '”');
        snip.style.color = 'var(--text)';
        card.appendChild(snip);
      }

      if (repeatedReason) {
        card.appendChild(el('p', 'source-flag', 'Not counted as independent — ' + repeatedReason + '.'));
      } else if (uncertainReason) {
        card.appendChild(el('p', 'source-flag', uncertainReason));
      }

      card.appendChild(sourceAction(src.url, 'Open source [' + index + ']'));
      return card;
    }

    function renderChain(report) {
      var chain = el('div', 'chain');
      chain.style.marginTop = '24px';
      var stages = chainData(report);

      CHAIN.forEach(function (label, i) {
        if (i) chain.appendChild(el('div', 'chain-line'));
        var node = el('div', 'chain-node chain-node-detail');
        node.appendChild(el('span', 'chain-dot'));
        var box = el('div', 'chain-body');
        box.appendChild(el('span', 'chain-label', label));
        box.appendChild(el('span', 'chain-value', stages[i]));
        node.appendChild(box);
        chain.appendChild(node);
      });
      return chain;
    }

    function chainData(report) {
      var r = report.result;
      var counts = report.sources.length ? RC.evidence.summarise(report.sources) : null;
      var shownType = function (f) {
        if (f.evidenceStatus === 'literally_aligned' || f.evidenceStatus === 'not_established' || f.evidenceStatus === 'invalid_reference') {
          return 'caution';
        }
        if (f.evidenceStatus === 'contradicted' && f.type === 'support') return 'caution';
        return f.type;
      };
      var supports = r.findings.filter(function (f) { return shownType(f) === 'support'; }).length;
      var contra = r.findings.filter(function (f) { return shownType(f) === 'contradict'; }).length;
      var inconsistent = r.findings.filter(function (f) { return shownType(f) === 'inconsistent'; }).length;

      return [
        report.understanding ? report.understanding.primaryClaim : report.input,
        (supports + contra + inconsistent === 0
          ? 'No web evidence statements could be drawn'
          : supports + ' supporting, ' + contra + ' directly contradicting' + (inconsistent ? ', ' + inconsistent + ' inconsistent/counterevidence' : '')),
        counts
          ? report.sources.length + ' retrieved from ' + report.independence.uniqueHostCount + ' publisher(s) — ' + counts.HIGH + ' high, ' + counts.MEDIUM + ' medium, ' + counts.LOW + ' low, ' + counts.UNKNOWN + ' unknown'
          : 'None retrieved',
        r.originalMaterial.established
          ? r.originalMaterial.description
          : 'Could not be established from the available evidence',
        report.timeline.entries.length
          ? report.timeline.entries.length + ' dated point(s), ' + report.timeline.missingCount + ' source(s) undated'
          : 'No publication dates available',
        report.independence.note,
        contra ? contra + ' contradiction(s) recorded' : 'None recorded',
        LABELS[r.assessment].text
      ];
    }

    var DATE_TYPE_LABEL = {
      published: 'published',
      updated: 'last updated — not necessarily when the information was first published',
      unspecified: 'date reported by the source; whether this is a publish or update date is not specified'
    };

    function renderTimeline(report) {
      var ul = el('ul', 'timeline');
      if (!report.timeline.entries.length) {
        var li = el('li', 'timeline-item');
        li.appendChild(el('span', 'timeline-date', 'No dates'));
        li.appendChild(el('span', 'timeline-desc', 'No source supplied a usable date, so no timeline could be built.'));
        ul.appendChild(li);
        return ul;
      }
      report.timeline.entries.forEach(function (e) {
        var typeLabel = DATE_TYPE_LABEL[e.dateType] || DATE_TYPE_LABEL.unspecified;
        var varyNote = e.certainty === 'provider-reported' ? '; may vary between checks' : '';
        var li = el('li', 'timeline-item timeline-approx');
        li.appendChild(el('span', 'timeline-date', e.date));
        li.appendChild(el('span', 'timeline-desc', e.desc + ' (' + typeLabel + varyNote + ')'));
        ul.appendChild(li);
      });
      if (report.timeline.missingCount) {
        var m = el('li', 'timeline-item timeline-missing');
        m.appendChild(el('span', 'timeline-date', 'Undated'));
        m.appendChild(el('span', 'timeline-desc',
          report.timeline.missingCount + ' source(s) carried no date at all and were left off the timeline.'));
        ul.appendChild(m);
      }
      return ul;
    }

    function qualitySummaryText(report) {
      if (!report.sources || !report.sources.length) {
        return 'No sources were retrieved for this check, so no quality mix is available.';
      }
      var counts = RC.evidence.summarise(report.sources);
      return report.sources.length + ' source(s): ' +
        counts.HIGH + ' high, ' + counts.MEDIUM + ' medium, ' +
        counts.LOW + ' low, ' + counts.UNKNOWN + ' unknown. ' +
        'Quality tiers classify publisher type; they do not prove a claim.';
    }

    function independenceSummaryText(report) {
      if (!report.independence) {
        return 'Independence analysis was not available for this check.';
      }
      var note = report.independence.note ? (' ' + report.independence.note) : '';
      return report.independence.totalSources + ' source(s) from ' +
        report.independence.uniqueHostCount + ' publisher(s); ' +
        report.independence.independentCount +
        ' counted as independent after grouping.' + note;
    }

    function outcomeSelectionText(report) {
      var assessment = report.result && report.result.assessment;
      var liveNote = 'Verified and Partially verified are not confirmed by the current live evidence checks. When support is not established, the live result is Unresolved (or Insufficient evidence when nothing usable was retrieved).';
      if (assessment === 'INSUFFICIENT_EVIDENCE') {
        return liveNote + ' This result is Insufficient evidence because stored usable support was not available for a stronger conclusion.';
      }
      if (assessment === 'CONTRADICTED') {
        return liveNote + ' This result is Contradicted only because a cited stored sentence met the strict literal negation rule against the primary claim.';
      }
      if (assessment === 'POTENTIAL_MANIPULATION') {
        return liveNote + ' This result is Potential manipulation only because a cited stored sentence named the sealed file and stated fabrication under the strict rule.';
      }
      if (assessment === 'UNRESOLVED') {
        return liveNote + ' This result is Unresolved because stored text was not accepted as proof of the claim under the live checks.';
      }
      if (assessment === 'VERIFIED' || assessment === 'PARTIALLY_VERIFIED') {
        return 'The displayed label is part of the official vocabulary, but the live evidence checks do not currently confirm Verified or Partially verified outcomes.';
      }
      return liveNote;
    }

    function renderOutcomeBridge(report) {
      var box = el('div', 'outcome-bridge');
      box.appendChild(el('div', 'claim-label', 'How this outcome was selected'));
      box.appendChild(el('p', null, qualitySummaryText(report)));
      box.appendChild(el('p', null, independenceSummaryText(report)));
      box.appendChild(el('p', null, outcomeSelectionText(report)));
      if (report.timeline) {
        box.appendChild(el('p', null,
          report.timeline.entries && report.timeline.entries.length
            ? ('Timeline: ' + report.timeline.entries.length + ' dated point(s); ' +
              report.timeline.missingCount + ' source(s) undated. Dates are provider-reported.')
            : ('Timeline: no usable publication dates were available' +
              (report.timeline.missingCount ? (' (' + report.timeline.missingCount + ' undated).') : '.'))));
      }
      return box;
    }

    function providerActivityText(report) {
      var parts = [];
      if (report.understanding) {
        parts.push('OpenAI claim extraction ran');
      }
      if (report.kind === 'url') {
        parts.push(report.pageClaim && report.pageClaim.title !== undefined
          ? 'Parallel page extraction was attempted'
          : 'Parallel page extraction was requested');
      }
      if (report.live) {
        if (report.searchFailed) {
          parts.push('Parallel search was attempted and did not complete');
        } else if (report.sources && report.sources.length) {
          parts.push('Parallel search returned ' + report.sources.length + ' stored source(s)');
        } else if (report.understanding && report.understanding.hasFactualClaim) {
          parts.push('Parallel search completed with no usable sources');
        } else {
          parts.push('Parallel search was not required for this submission');
        }
      } else {
        parts.push('Parallel search was unavailable in this view');
      }
      if (report.result) {
        parts.push('Assessment against sealed evidence completed');
      }
      parts.push('Exact dollar cost is not shown because this app does not receive provider billing amounts.');
      return parts.join('. ') + '.';
    }

    function renderWhy(report) {
      var r = report.result;
      var panel = el('div', 'why-panel');
      panel.id = 'why-panel';
      panel.hidden = true;

      var rows = [
        ['Supporting evidence', r.why.supporting],
        ['Contradicting evidence', r.why.contradicting],
        ['Source quality', r.why.sourceQuality || qualitySummaryText(report)],
        ['Timeline consistency', r.why.timeline || (report.timeline && report.timeline.entries && report.timeline.entries.length
          ? (report.timeline.entries.length + ' dated point(s); dates are provider-reported.')
          : 'No usable publication dates were available.')],
        ['What remains uncertain', r.why.uncertain],
        ['Why this outcome', r.why.choice]
      ];

      rows.forEach(function (row) {
        if (!row[1]) return;
        var d = el('div', 'why-row why-row-stack');
        d.appendChild(el('span', 'why-k', row[0]));
        d.appendChild(el('span', 'why-v', row[1]));
        panel.appendChild(d);
      });
      return panel;
    }

    /* These three records are written by the client when no model
       assessment exists. Anything else, including a copy that reuses one
       of these sentences and adds model text, is replaced by validate(). */
    var LOCAL_RESULTS = [
      {
        why: {
          supporting: 'Information not available.',
          contradicting: 'Information not available.',
          sourceQuality: 'No sources were searched.',
          timeline: 'Information not available.',
          uncertain: 'The submission does not contain an assertion that evidence could confirm or contradict.',
          choice: 'Nothing in the submission can be checked against evidence, so no stronger assessment is possible.'
        },
        uncertainty: ['The submission reads as opinion, a question or a subjective statement rather than a factual claim.']
      },
      {
        why: {
          supporting: 'No sources were retrieved, so nothing supports the claim here.',
          contradicting: 'No sources were retrieved, so nothing contradicts it here either.',
          sourceQuality: 'Not applicable — no sources were retrieved.',
          timeline: 'Information not available.',
          uncertain: 'Everything about this claim remains unestablished.',
          choice: 'The search returned no usable sources, so there is no evidence to weigh.'
        },
        uncertainty: ['No sources could be retrieved for this claim.']
      },
      {
        why: {
          supporting: 'No sources were retrieved, so nothing supports the claim here.',
          contradicting: 'No sources were retrieved, so nothing contradicts it here either.',
          sourceQuality: 'Not applicable — no sources were retrieved.',
          timeline: 'Information not available.',
          uncertain: 'Everything about this claim remains unestablished.',
          choice: 'No retrieval provider is connected, so no search was performed. Nothing here has been checked against evidence.'
        },
        uncertainty: ['No evidence was gathered. Connect a search provider to run a real investigation.']
      }
    ];

    function isLocalInsufficient(result) {
      if (!result || result.assessment !== 'INSUFFICIENT_EVIDENCE') return false;
      if (result.findings && result.findings.length) return false;
      var material = result.originalMaterial || {};
      if (material.established !== false || material.description !== '' || material.source != null) return false;
      var why = result.why || {};
      var notes = result.uncertainty || [];
      return LOCAL_RESULTS.some(function (local) {
        var keys = ['supporting', 'contradicting', 'sourceQuality', 'timeline', 'uncertain', 'choice'];
        if (notes.length !== local.uncertainty.length) return false;
        if (keys.some(function (key) { return why[key] !== local.why[key]; })) return false;
        return notes.every(function (note, index) { return note === local.uncertainty[index]; });
      });
    }

    function commitResult(report) {
      if (!report || !report.result || isLocalInsufficient(report.result)) return;
      var count = report.sources && report.sources.length ? report.sources.length : 0;
      report.result = RC.reasoning.validate(report.result, count);
    }

    function render(report) {
      commitResult(report);
      var root = $('#results-body');
      root.textContent = '';

      var r = report.result;
      var label = LABELS[r.assessment];

      /* mode banner */
      var tag = $('#results-mode-tag');
      var note = $('#results-mode-note');
      if (report.live) {
        tag.textContent = 'Live investigation';
        tag.className = 'demo-tag live-tag';
        note.textContent = 'Sources retrieved through ' + report.provider + '.';
      } else {
        tag.textContent = 'No live investigation';
        tag.className = 'demo-tag';
        note.textContent = 'Prototype simulation — no live investigation is being performed. ' +
          'The claim was analysed, but no search provider is connected, so no sources were retrieved.';
      }

      var activity = $('#results-provider-activity');
      if (activity) {
        activity.hidden = false;
        activity.textContent = 'Provider activity: ' + providerActivityText(report);
      }

      /* claim card */
      $('#results-claim-text').textContent = '“' + (report.understanding ? report.understanding.primaryClaim : report.input) + '”';
      var av = $('#results-assessment');
      av.textContent = label.text;
      av.className = 'meta-v ' + label.cls;

      var basis = $('#results-basis');
      basis.textContent = report.sources.length
        ? report.sources.length + ' sources retrieved · ' + report.independence.uniqueHostCount + ' publishers · ' +
          report.independence.independentCount + ' apparently independent source group(s)'
        : 'No sources retrieved';

      var oldBridge = $('.claim-card .outcome-bridge');
      if (oldBridge) oldBridge.remove();
      var old = $('#why-panel');
      if (old) old.remove();
      $('.claim-card').appendChild(renderOutcomeBridge(report));
      var why = renderWhy(report);
      $('.claim-card').appendChild(why);
      var toggle = $('#why-toggle');
      toggle.setAttribute('aria-expanded', 'false');
      toggle.textContent = 'Why this assessment?';

      /* submitted page, for URL checks */
      if (report.pageClaim) {
        root.appendChild(section('The submitted page',
          'What this page asserts, kept separate from evidence found elsewhere.'));
        var pg = el('div', 'source-card');
        pg.appendChild(el('span', 'source-name', report.pageClaim.title || hostOf(report.pageClaim.url)));
        var pmeta = el('div', 'source-meta-row');
        pmeta.appendChild(el('span', 'source-date', report.pageClaim.publishedAt || 'Date not available'));
        if (report.pageClaim.quality && report.pageClaim.quality.tier) {
          pmeta.appendChild(qualityBadge(report.pageClaim.quality.tier));
        }
        pg.appendChild(pmeta);
        if (report.pageClaim.quality && report.pageClaim.quality.reason) {
          pg.appendChild(el('p', 'source-desc', report.pageClaim.quality.reason));
        }
        /* Reuses sourceAction / sourceLinkUrl: http(s) only, target=_blank, rel=noopener noreferrer. */
        pg.appendChild(sourceAction(report.pageClaim.url, 'Open submitted page'));
        root.appendChild(pg);
      }

      /* understanding */
      if (report.understanding) {
        root.appendChild(section('Understanding the claim'));
        var u = el('div', 'understanding-block');
        u.appendChild(el('div', 'claim-label', 'Primary claim'));
        u.appendChild(el('p', 'understanding-primary', report.understanding.primaryClaim));
        if (report.understanding.verifiablePoints.length) {
          u.appendChild(el('div', 'claim-label', 'Verifiable points'));
          var ol = el('ol', 'points-list');
          report.understanding.verifiablePoints.forEach(function (p) { ol.appendChild(el('li', null, p)); });
          u.appendChild(ol);
        }
        if (report.understanding.excluded.length) {
          u.appendChild(el('div', 'claim-label', 'Not treated as factual claims'));
          var ul2 = el('ul', 'points-list');
          report.understanding.excluded.forEach(function (e) {
            ul2.appendChild(el('li', null, e.text + ' — ' + e.reason));
          });
          u.appendChild(ul2);
        }
        root.appendChild(u);
      }

      /* findings */
      root.appendChild(section('What was found'));
      if (!r.findings.length) {
        root.appendChild(el('p', 'demo-note', 'No evidence statements could be drawn from the available material.'));
      } else {
        var list = el('ul', 'findings-list');
        list.style.marginTop = '20px';
        r.findings.forEach(function (f) {
          var shown = f.type;
          if (f.evidenceStatus === 'literally_aligned' || f.evidenceStatus === 'not_established' || f.evidenceStatus === 'invalid_reference') {
            shown = 'caution';
          }
          if (f.evidenceStatus === 'contradicted' && shown === 'support') shown = 'caution';
          var cls = shown === 'support' ? 'support' : shown === 'contradict' ? 'contradict' : 'caution';
          var icon = shown === 'support' ? '✓' : shown === 'contradict' ? '✕' : '⚠';
          var li = el('li', 'finding ' + cls);
          li.appendChild(el('span', 'finding-icon', icon));
          var body = el('div', 'finding-body');
          body.appendChild(el('span', null, f.text));
          if (f.sources.length) {
            body.appendChild(el('span', 'finding-refs',
              'Source' + (f.sources.length > 1 ? 's' : '') + ' ' + f.sources.map(function (n) { return '[' + n + ']'; }).join(' ')));
          }
          li.appendChild(body);
          list.appendChild(li);
        });
        root.appendChild(list);
      }

      /* original material */
      root.appendChild(section('Original material'));
      var om = el('div', 'understanding-block');
      om.appendChild(el('p', null, r.originalMaterial.established
        ? r.originalMaterial.description
        : 'Original material could not be established from the available evidence.'));
      if (r.originalMaterial.established && r.originalMaterial.source != null) {
        var src = report.sources[r.originalMaterial.source];
        if (src) om.appendChild(sourceAction(src.url, 'Open source [' + r.originalMaterial.source + ']'));
      }
      root.appendChild(om);

      /* image evidence — kept structurally separate from web sources;
         reuses the same field()-style rows as the why-panel so no new
         CSS is introduced. */
      if (report.imageEvidence) {
        var ie = report.imageEvidence;
        root.appendChild(section('Local image metadata on this device', 'This is local analysis of the file in the browser. It is not server-verified evidence, it is not the sealed file identity, and it is not the claim assessment.'));
        var ib = el('div', 'understanding-block');
        var row = function (label, value) {
          var r2 = el('div', 'why-row why-row-stack');
          r2.appendChild(el('span', 'why-k', label));
          r2.appendChild(el('span', 'why-v', value));
          return r2;
        };
        ib.appendChild(row('File', ie.fileName));
        ib.appendChild(row('Type', ie.fileType));
        ib.appendChild(row('Dimensions', ie.width && ie.height ? (ie.width + ' × ' + ie.height + ' px') : 'Not available'));
        if (ie.hasExif) {
          ib.appendChild(row('EXIF capture date', ie.captureDate || 'Not available'));
          ib.appendChild(row('Camera make / model', (ie.make || 'Not available') + ' / ' + (ie.model || 'Not available')));
          if (ie.software) ib.appendChild(row('Editing/creation software (EXIF)', ie.software + ' — indicator only, not evidence of manipulation'));
          if (ie.gpsLat != null) ib.appendChild(row('GPS (EXIF)', formatLocalCoordinate(ie.gpsLat) + ', ' + formatLocalCoordinate(ie.gpsLon)));
        } else {
          ib.appendChild(row('EXIF', 'No usable EXIF metadata found — the capture date could not be established from EXIF. This is not evidence that any particular date claim is false.'));
        }
        ib.appendChild(row('File hash (SHA-256)', (ie.sha256 || 'Not computed') + ' — calculated on this device. It is not the server file identity and does not establish when or where the picture was taken.'));
        root.appendChild(ib);
      }

      if (r.imageEvidence) {
        openEvidence = r.imageEvidence;
        root.appendChild(renderImageEvidence(r.imageEvidence));
      } else {
        openEvidence = null;
      }

      if (r.videoEvidence) {
        root.appendChild(renderVideoEvidence(r.videoEvidence));
      }

      /* evidence chain */
      root.appendChild(section('Evidence chain'));
      root.appendChild(renderChain(report));

      /* timeline */
      root.appendChild(section('Evidence timeline'));
      root.appendChild(renderTimeline(report));

      /* sources */
      root.appendChild(section('Sources'));
      if (!report.sources.length) {
        root.appendChild(el('p', 'demo-note',
          report.live
            ? 'The search returned no usable sources for this claim.'
            : 'No sources were retrieved because no search provider is connected.'));
      } else {
        root.appendChild(el('p', 'demo-note', report.independence.note +
          ' Different publishers can still repeat the same underlying report rather than confirming it separately — that is why the count above tracks apparently independent groups, not just the number of pages retrieved.'));
        var grid = el('div', 'source-grid');
        var repeated = report.independence.repeatedIndexes;
        report.sources.forEach(function (s, i) {
          grid.appendChild(renderSourceCard(s, i,
            repeated.indexOf(i) >= 0 ? report.independence.repeatedReason[i] : null,
            report.independence.uncertainIndexes.indexOf(i) >= 0 ? report.independence.uncertainReason[i] : null));
        });
        root.appendChild(grid);
      }

      /* uncertainty */
      root.appendChild(section('What remains uncertain'));
      if (!r.uncertainty.length) {
        root.appendChild(el('p', null, 'Information not available.'));
      } else {
        var uu = el('ul', 'points-list');
        r.uncertainty.forEach(function (u2) { uu.appendChild(el('li', null, u2)); });
        root.appendChild(uu);
      }

      /* errors, if any */
      if (report.errors.length) {
        root.appendChild(section('Problems during this investigation'));
        var eu = el('ul', 'points-list');
        report.errors.forEach(function (e) { eu.appendChild(el('li', null, e.message)); });
        root.appendChild(eu);
      }

      screen('results');
    }

    function renderFailure(err, input) {
      var root = $('#results-body');
      root.textContent = '';

      $('#results-claim-text').textContent = '“' + input + '”';
      var av = $('#results-assessment');
      av.textContent = 'Not completed';
      av.className = 'meta-v assessment-insufficient';
      $('#results-basis').textContent = 'Investigation stopped';

      var oldBridge = $('.claim-card .outcome-bridge');
      if (oldBridge) oldBridge.remove();
      var old = $('#why-panel');
      if (old) old.remove();

      $('#results-mode-tag').textContent = 'Investigation failed';
      $('#results-mode-tag').className = 'demo-tag';
      $('#results-mode-note').textContent = 'No assessment was produced. Nothing below is a result.';
      var activity = $('#results-provider-activity');
      if (activity) {
        activity.hidden = false;
        activity.textContent = 'Provider activity: the investigation stopped before a sealed assessment completed. Exact dollar cost is not shown because this app does not receive provider billing amounts.';
      }

      var box = el('div', 'understanding-block');
      box.appendChild(el('p', null, (err && err.message) || 'The investigation could not be completed.'));
      root.appendChild(box);
      screen('results');
    }

    function evidenceRow(label, value, id) {
      var line = el('div', 'why-row why-row-stack');
      line.appendChild(el('span', 'why-k', label));
      var shown = el('span', 'why-v', value);
      if (id) shown.id = id;
      line.appendChild(shown);
      return line;
    }

    function availabilityCopy(current) {
      var availability = current && current.availability;
      if (availability === 'retained') {
        return 'At ' + (current.checkedAt || 'the check') + ', the stored bytes matched the sealed hash. This check does not show whether the file is still stored.';
      }
      if (availability === 'subsequently_deleted') {
        return 'The file was removed after this assessment. The sealed identity is unchanged.';
      }
      if (availability === 'unavailable') {
        return 'The stored bytes could not be confirmed. This is not an authenticity finding.';
      }
      return 'Current storage was not checked.';
    }

    /* Stage 3.B approved video availability wording — do not reuse image copy. */
    function videoAvailabilityCopy(current) {
      var availability = current && current.availability;
      if (availability === 'retained') {
        return 'The sealed file was present and its file identity was checked when this presentation was generated.';
      }
      if (availability === 'subsequently_deleted') {
        return 'The sealed file identity remains recorded, but the original uploaded file is no longer retained.';
      }
      if (availability === 'unavailable') {
        return 'The sealed file could not be confirmed against the retained bytes.';
      }
      return 'Current storage was not checked.';
    }

    function copyTextToClipboard(text, button) {
      var done = function () {
        if (!button) return;
        var prior = button.textContent;
        button.textContent = 'Copied';
        window.setTimeout(function () { button.textContent = prior; }, 1200);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done).catch(function () {});
        return;
      }
      try {
        var area = document.createElement('textarea');
        area.value = text;
        area.setAttribute('readonly', '');
        area.style.position = 'absolute';
        area.style.left = '-9999px';
        document.body.appendChild(area);
        area.select();
        document.execCommand('copy');
        document.body.removeChild(area);
        done();
      } catch (err) {}
    }

    function sha256Row(label, digest, id) {
      var line = el('div', 'why-row why-row-stack video-evidence-hash-row');
      line.appendChild(el('span', 'why-k', label));
      var valueWrap = el('div', 'video-evidence-hash-value');
      var shown = el('span', 'why-v provenance-id', digest || 'Not available');
      if (id) shown.id = id;
      valueWrap.appendChild(shown);
      if (digest && /^[0-9a-f]{64}$/.test(digest)) {
        var button = el('button', 'tool-btn video-evidence-copy', 'Copy SHA-256');
        button.type = 'button';
        button.setAttribute('aria-label', 'Copy SHA-256 file identity');
        button.addEventListener('click', function () {
          copyTextToClipboard(digest, button);
        });
        valueWrap.appendChild(button);
      }
      line.appendChild(valueWrap);
      return line;
    }

    function formatVideoDuration(ms) {
      if (typeof ms !== 'number' || ms < 0 || Math.floor(ms) !== ms) return 'Not available';
      if (ms < 1000) return ms + ' ms';
      var total = Math.round(ms / 100) / 10;
      return total + ' s (' + ms + ' ms)';
    }

    function videoTechnicalBlock(tech) {
      var body = el('div', 'understanding-block');
      if (!tech || tech.status === 'not_disclosed') {
        body.appendChild(el('p', 'demo-note',
          (tech && tech.note)
            ? tech.note
            : 'Technical probe metadata is not presented because metadata consent was not accepted for this attachment.'));
        return body;
      }
      body.appendChild(evidenceRow('Duration', formatVideoDuration(tech.durationMs)));
      body.appendChild(evidenceRow(
        'Dimensions',
        (typeof tech.width === 'number' && typeof tech.height === 'number')
          ? (tech.width + ' × ' + tech.height + ' px')
          : 'Not available'
      ));
      body.appendChild(evidenceRow('Video codec', tech.videoCodec || 'Not available'));
      body.appendChild(evidenceRow(
        'Audio codec',
        tech.audioCodec == null || tech.audioCodec === ''
          ? 'None / not available'
          : String(tech.audioCodec)
      ));
      body.appendChild(el('p', 'demo-note',
        'These values are technical probe fields recorded at seal time. They do not establish when the video was originally recorded.'));
      return body;
    }

    var PROVENANCE_EVENT_TEXT = 'Content Credentials can help establish the provenance and integrity of an image. They do not prove that the event depicted in the image actually happened.';
    var PROVENANCE_PILOT_TEXT = 'Pilot Choice A: trusted C2PA credential verification is not production-ready. Technical or unavailable Content Credentials are not trusted verification. Provenance stays separate from the six claim-assessment outcomes.';
    var PROVENANCE_VIEWS = {
      not_examined: {
        tone: 'not-examined',
        label: 'Not examined',
        sentence: 'No provenance record was stored for this sealed file. This does not say the file is unsigned or untrusted.'
      },
      no_credentials: {
        tone: 'none',
        label: 'No credentials',
        sentence: 'No content credentials were found. This does not mean the file was edited.'
      },
      not_performed: {
        tone: 'not-performed',
        label: 'Not performed',
        sentence: 'Credential verification was not performed.'
      },
      credentials_trusted: {
        tone: 'trusted',
        label: 'Credential trusted',
        sentence: 'The signer credential checked as trusted under the sealed policy.'
      },
      credentials_untrusted: {
        tone: 'untrusted',
        label: 'Signer not trusted',
        sentence: 'A credential is present and the signer is not trusted under the sealed policy. This is not proof of misleading editing.'
      },
      credentials_invalid: {
        tone: 'invalid',
        label: 'Credential invalid',
        sentence: 'A credential is present and a check failed. This is a credential result.'
      },
      credentials_malformed: {
        tone: 'malformed',
        label: 'Credential malformed',
        sentence: 'The credential structure could not be read as a valid credential.'
      },
      technical: {
        tone: 'technical',
        label: 'Technical failure',
        sentence: 'Verification did not finish. This is not an invalid credential.'
      },
      unrecognized: {
        tone: 'unrecognized',
        label: 'Not recognized',
        sentence: 'The server returned a provenance status this view does not recognize.'
      }
    };
    var CHECK_COPY = {
      signature: {
        valid: 'The signature checked as valid.',
        invalid: 'The signature did not check as valid.',
        missing: 'No signature was included.',
        not_checked: 'The signature was not checked.'
      },
      certificateValidity: {
        inside_at_asserted_time: 'The certificate was inside its validity period at the asserted time.',
        expired: 'The certificate was expired.',
        outside: 'The certificate was outside its validity period.',
        not_checked: 'Certificate validity was not checked.'
      },
      certificateTrust: {
        trusted: 'The certificate checked as trusted under the sealed policy.',
        untrusted: 'The certificate did not check as trusted. This is not proof of misleading editing.',
        not_checked: 'Certificate trust was not checked.'
      },
      timestamp: {
        trusted: 'A trusted timestamp was checked.',
        absent: 'No timestamp was included.',
        untrusted: 'A timestamp is present and did not check as trusted.',
        malformed: 'The timestamp could not be read.',
        outside_validity: 'The timestamp falls outside the certificate validity window.',
        not_checked: 'The timestamp was not checked.'
      },
      revocation: {
        not_revoked: 'The revocation check did not report the credential as revoked.',
        revoked: 'The revocation check reported the credential as revoked.',
        skipped: 'Revocation checking was skipped.',
        unknown: 'The revocation result is unknown.',
        inaccessible: 'The revocation source could not be reached.',
        not_checked: 'Revocation was not checked.'
      },
      assetBinding: {
        bound: 'The credential is bound to this file.',
        mismatch: 'The credential does not bind to this file. This is not a finding that the file was edited.',
        missing: 'File binding was not included.',
        malformed: 'File binding could not be read.',
        not_checked: 'File binding was not checked.'
      }
    };
    var ROLE_TEXT = { active: 'Active manifest', ingredient: 'Ingredient', unreferenced: 'Unreferenced' };
    var SAFE_DIGEST = /^[0-9a-f]{64}$/;
    var SAFE_LABEL = /^[A-Za-z0-9:._~/#?&=%+-]{1,200}$/;
    var SAFE_TIME = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
    var SAFE_CODE = /^[a-z0-9_]{1,64}$/;

    function provenanceView(provenance) {
      if (!provenance || provenance.version === 'absent' || provenance.status === 'not_examined') return 'not_examined';
      var result = provenance.result || {};
      if (result.kind === 'technical' && result.status === 'verification_failed') return 'technical';
      if (result.kind === 'credential' && PROVENANCE_VIEWS[result.status]) return result.status;
      return 'unrecognized';
    }

    function technicalCopy(code) {
      if (code === 'reader_timeout' || code === 'reader_crash' || code === 'reader_unavailable' || code === 'memory_limit') {
        return 'The reader could not finish verification.';
      }
      if (code === 'trust_configuration') return 'Trust configuration was not available.';
      if (code) return 'The trust policy could not be confirmed.';
      return PROVENANCE_VIEWS.technical.sentence;
    }

    function provenanceRow(label, value, mono) {
      var line = el('div', 'why-row why-row-stack');
      line.appendChild(el('span', 'why-k', label));
      line.appendChild(el('span', mono ? 'why-v provenance-id' : 'why-v', value));
      return line;
    }

    function checkSentence(group, checks) {
      if (!checks || !CHECK_COPY[group]) return 'No per-check results were returned.';
      var copy = CHECK_COPY[group][checks[group]];
      return copy || 'No per-check results were returned.';
    }

    function displayChecks(provenance) {
      var result = provenance && provenance.result;
      if (!result) return null;
      if (result.checks) return result.checks;
      var manifests = result.manifests || [];
      var index;
      for (index = 0; index < manifests.length; index++) {
        if (manifests[index].role === 'active' && manifests[index].checks) return manifests[index].checks;
      }
      return null;
    }

    function renderProvenance(evidence) {
      var provenance = evidence.provenance || {};
      var viewName = provenanceView(provenance);
      var view = PROVENANCE_VIEWS[viewName];
      var wrap = el('div', 'provenance');
      wrap.id = 'content-credentials';
      wrap.appendChild(el('div', 'claim-label', 'Content Credentials'));
      wrap.appendChild(el('p', 'provenance-event', PROVENANCE_EVENT_TEXT));
      wrap.appendChild(el('p', 'demo-note', PROVENANCE_PILOT_TEXT));
      var status = el('div', 'provenance-status provenance-status-' + view.tone);
      status.setAttribute('data-provenance-status', view.tone);
      status.appendChild(el('span', 'provenance-label', view.label));
      wrap.appendChild(status);
      var sentence = view.sentence;
      if (viewName === 'technical') sentence = technicalCopy(provenance.result && provenance.result.failureCode);
      wrap.appendChild(el('p', 'demo-note', sentence));

      var identity = evidence.fileIdentity || {};
      wrap.appendChild(el('div', 'claim-label', 'Image identity'));
      wrap.appendChild(provenanceRow('SHA-256', typeof identity.sha256 === 'string' && SAFE_DIGEST.test(identity.sha256) ? identity.sha256 : 'Not available', true));
      wrap.appendChild(provenanceRow('File type', identity.mediaType === 'image/jpeg' || identity.mediaType === 'image/png' || identity.mediaType === 'image/gif' || identity.mediaType === 'image/webp' ? identity.mediaType : 'Format not recognized'));
      wrap.appendChild(provenanceRow('File size', typeof identity.byteLength === 'number' ? identity.byteLength + ' bytes' : 'Not available'));
      var verifiedAt = provenance.verifiedAt && SAFE_TIME.test(provenance.verifiedAt) ? provenance.verifiedAt : '';
      wrap.appendChild(provenanceRow('Verification time', verifiedAt || 'Verification time was not available.'));
      if (provenance.image && provenance.image.sha256 === identity.sha256) {
        wrap.appendChild(el('p', 'demo-note', 'This credential record is bound to the sealed file.'));
      }

      var showCredentials = viewName !== 'not_examined' && viewName !== 'technical' && viewName !== 'unrecognized';
      if (showCredentials) {
        wrap.appendChild(el('div', 'claim-label', 'Manifests'));
        var manifests = (provenance.result && provenance.result.manifests) || [];
        if (!manifests.length) {
          wrap.appendChild(el('p', 'demo-note', 'No manifests were returned.'));
        }
        manifests.forEach(function (item) {
          if (!item || !SAFE_LABEL.test(item.label) || !PROVENANCE_VIEWS[item.status] || !ROLE_TEXT[item.role]) return;
          var card = el('div', 'provenance-manifest');
          card.appendChild(provenanceRow('Role', ROLE_TEXT[item.role]));
          card.appendChild(provenanceRow('Credential status', PROVENANCE_VIEWS[item.status].label));
          card.appendChild(provenanceRow('Label', item.label, true));
          wrap.appendChild(card);
        });
        var checks = displayChecks(provenance);
        wrap.appendChild(el('div', 'claim-label', 'Signature verification'));
        wrap.appendChild(el('p', null, checkSentence('signature', checks)));
        wrap.appendChild(el('div', 'claim-label', 'Certificate validity'));
        wrap.appendChild(el('p', null, checkSentence('certificateValidity', checks)));
        wrap.appendChild(el('div', 'claim-label', 'Certificate trust'));
        wrap.appendChild(el('p', null, checkSentence('certificateTrust', checks)));
        wrap.appendChild(el('div', 'claim-label', 'Timestamp verification'));
        wrap.appendChild(el('p', null, checkSentence('timestamp', checks)));
        wrap.appendChild(el('div', 'claim-label', 'Revocation status'));
        wrap.appendChild(el('p', null, checkSentence('revocation', checks)));
        wrap.appendChild(el('div', 'claim-label', 'File binding'));
        wrap.appendChild(el('p', null, checkSentence('assetBinding', checks)));
      } else {
        wrap.appendChild(el('p', 'demo-note', 'No per-check results were returned.'));
      }

      if (viewName === 'technical' || viewName === 'not_examined') {
        wrap.appendChild(el('div', 'claim-label', 'Technical verification'));
        wrap.appendChild(el('p', null, viewName === 'not_examined' ? view.sentence : sentence));
      }

      var details = el('details', 'provenance-details');
      details.appendChild(el('summary', null, 'Verification details'));
      var body = el('div', 'provenance-details-body');
      var reader = provenance.reader;
      var readerVersion = reader && typeof reader.readerVersion === 'string' && /^[A-Za-z0-9._-]{1,32}$/.test(reader.readerVersion) ? reader.readerVersion : '';
      var nativeVersion = reader && typeof reader.nativeLibraryVersion === 'string' && /^[A-Za-z0-9._-]{1,32}$/.test(reader.nativeLibraryVersion) ? reader.nativeLibraryVersion : '';
      if (readerVersion || nativeVersion) {
        if (readerVersion) body.appendChild(provenanceRow('Reader', readerVersion, true));
        if (nativeVersion) body.appendChild(provenanceRow('Native library', nativeVersion, true));
      } else {
        body.appendChild(el('p', 'demo-note', 'Reader details were not returned.'));
      }
      var policy = provenance.policy;
      if (policy && SAFE_DIGEST.test(policy.activationDigest || '')) {
        body.appendChild(provenanceRow('Release sequence', String(policy.releaseSequence)));
        body.appendChild(provenanceRow('Activation digest', policy.activationDigest, true));
        if (SAFE_DIGEST.test(policy.suspensionDigest || '')) body.appendChild(provenanceRow('Suspension digest', policy.suspensionDigest, true));
        if (SAFE_DIGEST.test(policy.manifestBundleSha256 || '')) body.appendChild(provenanceRow('Manifest bundle', policy.manifestBundleSha256, true));
        if (SAFE_DIGEST.test(policy.timestampBundleSha256 || '')) body.appendChild(provenanceRow('Timestamp bundle', policy.timestampBundleSha256, true));
        body.appendChild(provenanceRow('Root use', policy.rootUse === 'verify-only' ? 'Verify only' : 'Active'));
        body.appendChild(provenanceRow('Purpose', policy.purpose === 'suspension' ? 'Suspension' : 'Policy'));
      } else {
        body.appendChild(el('p', 'demo-note', 'No trust-policy pin was stored.'));
      }
      if (showCredentials && SAFE_CODE.test(provenance.result.status)) {
        body.appendChild(provenanceRow('Server status', provenance.result.status, true));
      }
      if (viewName === 'technical' && provenance.result && SAFE_CODE.test(provenance.result.failureCode || '')) {
        body.appendChild(provenanceRow('Failure code', provenance.result.failureCode, true));
      }
      details.appendChild(body);
      wrap.appendChild(details);
      return wrap;
    }

    function renderImageEvidence(evidence) {
      var wrap = el('div', null);
      wrap.id = 'image-evidence';
      wrap.appendChild(section('Image file checks', 'These checks describe the uploaded file. They do not establish whether the associated claim is true.'));
      wrap.appendChild(el('p', 'image-evidence-summary',
        'File identity, embedded metadata, and Content Credentials are separate from the claim assessment. A matching hash or credential status does not prove that a pictured event happened.'));

      var identity = evidence.fileIdentity || {};
      var receipt = evidence.receipt || {};
      var retention = evidence.retentionAtSeal || {};
      var documented = evidence.alteration && evidence.alteration.documentedEvidence;

      var identityDetails = el('details', 'image-evidence-details');
      identityDetails.appendChild(el('summary', null, 'File identity and retention'));
      var identityBody = el('div', 'understanding-block');
      identityBody.appendChild(evidenceRow('SHA-256', identity.sha256 || '', 'image-evidence-sha256'));
      identityBody.appendChild(evidenceRow('Format', identity.mediaType || 'Not available'));
      identityBody.appendChild(evidenceRow('Size', identity.byteLength != null ? identity.byteLength + ' bytes' : 'Not available'));
      identityBody.appendChild(evidenceRow('Asset ID', identity.assetId || 'Not available'));
      identityBody.appendChild(evidenceRow('Received', receipt.receivedAt || 'Not available'));
      identityBody.appendChild(el('p', 'demo-note', 'This SHA-256 is calculated by the server from the received bytes. It does not prove originality or authenticity.'));
      identityBody.appendChild(el('div', 'claim-label', 'Client and server hash comparison'));
      identityBody.appendChild(el('p', 'demo-note', receipt.comparison || 'No hash was supplied by this device. The server hash is the file identity.'));
      identityBody.appendChild(evidenceRow('Consent version', retention.consentVersion || 'Not available'));
      identityBody.appendChild(el('p', null, retention.statement || 'When this assessment was sealed, the server was retaining this file. It may subsequently be removed when the investigation or account is deleted.'));
      var availability = evidenceRow('Availability', availabilityCopy(evidence.currentFile), 'image-evidence-availability');
      var availabilityValue = availability.querySelector('.why-v');
      if (availabilityValue) {
        availabilityValue.setAttribute('data-availability', (evidence.currentFile && evidence.currentFile.availability) || 'not_checked');
      }
      identityBody.appendChild(availability);
      identityDetails.appendChild(identityBody);
      wrap.appendChild(identityDetails);

      var metaDetails = el('details', 'image-evidence-details');
      metaDetails.appendChild(el('summary', null, 'Embedded metadata'));
      var metaBody = el('div', 'understanding-block');
      renderEmbeddedMetadata(metaBody, evidence);
      metaDetails.appendChild(metaBody);
      wrap.appendChild(metaDetails);

      var provenanceDetails = el('details', 'image-evidence-details');
      provenanceDetails.appendChild(el('summary', null, 'Content Credentials and alteration notes'));
      var provenanceBody = el('div', 'understanding-block');
      provenanceBody.appendChild(renderProvenance(evidence));
      provenanceBody.appendChild(el('div', 'claim-label', 'Alteration evidence'));
      provenanceBody.appendChild(el('p', null, documented === 'source_linked'
        ? 'A cited stored sentence names this sealed SHA-256 and states fabrication. This records what that source says. It does not confirm that the file was altered, how it was changed, or that the pictured event is false.'
        : 'This assessment did not record a cited sentence that names the sealed file and states fabrication. That is not a finding that the file is original or authentic.'));
      provenanceBody.appendChild(el('p', 'demo-note', 'No technical alteration test was run.'));
      provenanceBody.appendChild(el('p', 'demo-note', 'No separate original file was submitted. This does not mean the received file is the original.'));
      provenanceDetails.appendChild(provenanceBody);
      wrap.appendChild(provenanceDetails);
      return wrap;
    }

    function renderVideoEvidence(evidence) {
      var wrap = el('div', null);
      wrap.id = 'video-evidence';
      wrap.appendChild(section('Video evidence',
        'Server presentation of a sealed video file identity. Separate from the claim assessment and from Image evidence.'));
      wrap.appendChild(el('p', 'image-evidence-summary video-evidence-summary',
        evidence.disclaimer ||
        'This information describes the identity and technical properties of the uploaded file. It does not establish authenticity, original recording time, publication history, or the truth of any claim.'));

      var identity = evidence.fileIdentity || {};
      var receipt = evidence.receipt || {};
      var retention = evidence.retentionAtSeal || {};
      var processing = evidence.processing || {};
      var provenance = evidence.provenance || {};

      var identityDetails = el('details', 'image-evidence-details video-evidence-details');
      identityDetails.open = true;
      identityDetails.appendChild(el('summary', null, 'File identity and retention'));
      var identityBody = el('div', 'understanding-block');
      identityBody.appendChild(sha256Row('SHA-256', identity.sha256 || '', 'video-evidence-sha256'));
      identityBody.appendChild(el('p', 'demo-note',
        'This SHA-256 identifies the exact sealed file bytes only. It does not establish authenticity, originality, or when or where the video was recorded.'));
      identityBody.appendChild(evidenceRow('Media type', identity.mediaType || 'Not available'));
      identityBody.appendChild(evidenceRow('Size', identity.byteLength != null ? identity.byteLength + ' bytes' : 'Not available'));
      identityBody.appendChild(evidenceRow('Received', receipt.receivedAt || 'Not available'));
      identityBody.appendChild(evidenceRow('Sealed', receipt.sealedAt || 'Not available'));
      if (receipt.comparison) {
        identityBody.appendChild(el('div', 'claim-label', 'Client and server hash comparison'));
        identityBody.appendChild(el('p', 'demo-note', receipt.comparison));
      }
      identityBody.appendChild(evidenceRow('Upload consent', retention.consentVersion || 'Not available'));
      identityBody.appendChild(evidenceRow('Metadata consent', retention.metadataConsentDecision || 'Not available'));
      if (retention.statement) identityBody.appendChild(el('p', 'demo-note', retention.statement));
      var availability = evidenceRow('Availability', videoAvailabilityCopy(evidence.currentFile), 'video-evidence-availability');
      var availabilityValue = availability.querySelector('.why-v');
      if (availabilityValue) {
        availabilityValue.setAttribute('data-availability', (evidence.currentFile && evidence.currentFile.availability) || 'not_checked');
      }
      identityBody.appendChild(availability);
      identityDetails.appendChild(identityBody);
      wrap.appendChild(identityDetails);

      var techDetails = el('details', 'image-evidence-details video-evidence-details');
      techDetails.appendChild(el('summary', null, 'Technical metadata'));
      techDetails.appendChild(videoTechnicalBlock(evidence.technicalMetadata));
      wrap.appendChild(techDetails);

      var noteDetails = el('details', 'image-evidence-details video-evidence-details');
      noteDetails.appendChild(el('summary', null, 'Processing and provenance limits'));
      var noteBody = el('div', 'understanding-block');
      if (processing.note) noteBody.appendChild(el('p', 'demo-note', processing.note));
      noteBody.appendChild(el('p', 'demo-note',
        provenance.note || 'C2PA video verification is outside the scope of this stage.'));
      noteBody.appendChild(el('p', 'demo-note',
        'No authenticity verdict is produced from hashing, probing, retention, or sealing.'));
      noteDetails.appendChild(noteBody);
      wrap.appendChild(noteDetails);
      return wrap;
    }

    function renderEmbeddedMetadata(block, evidence) {
      var meta = evidence.embeddedMetadata || { status: 'not_extracted' };
      var sentences = {
        not_extracted: 'The server has not read embedded metadata from this file. This is not a finding that metadata is absent, and it is not evidence of manipulation.',
        not_performed: 'The server did not read embedded metadata because that separate consent was not recorded for this file. This is not a finding that metadata is absent.',
        extraction_failed: 'Embedded metadata could not be read within the reader limits. This is not a finding that metadata is absent, and it is not evidence of manipulation.',
        malformed: 'Embedded metadata could not be read safely. This is not a finding that metadata is absent, and it is not evidence of manipulation.',
        unsupported_format: 'This file format is not scanned for EXIF. This is not a finding that metadata is absent.',
        unsupported_structure: 'The file has metadata in a structure this reader does not use. This is not a finding that EXIF is absent, and it is not evidence of manipulation.',
        no_supported_metadata: 'The supported metadata blocks did not contain the camera, date, or location fields this reader stores. This is not evidence of manipulation.',
        extracted: 'These fields were read from the sealed file. They do not prove where or when the picture was taken, and they are not evidence of manipulation.'
      };
      block.appendChild(el('p', 'demo-note', sentences[meta.status] || sentences.not_extracted));
      var fields = meta.fields || {};
      ['make', 'model', 'software', 'dateTime', 'dateTimeOriginal', 'dateTimeDigitized', 'orientation'].forEach(function (name) {
        var field = fields[name];
        if (!field || field.status === 'absent') return;
        if (field.status === 'malformed') {
          block.appendChild(evidenceRow(name, 'Could not be read safely'));
          return;
        }
        (field.values || []).forEach(function (item) {
          block.appendChild(evidenceRow(name, item.value));
        });
      });
      var gps = fields.gps;
      if (gps && gps.status === 'malformed') {
        block.appendChild(evidenceRow('Location', 'Could not be read safely'));
      }
      if (gps && (gps.status === 'present' || gps.status === 'conflict')) {
        (gps.values || []).forEach(function (item) {
          block.appendChild(evidenceRow('Location', item.latitude + ', ' + item.longitude));
        });
        block.appendChild(el('p', 'demo-note', 'Precise coordinates are hidden. This rounded location is not proof of where the picture was taken.'));
        var button = el('button', 'tool-btn', 'Show precise coordinates');
        button.type = 'button';
        button.id = 'image-evidence-reveal';
        var precise = el('p', 'demo-note', '');
        precise.id = 'image-evidence-gps-precise';
        button.addEventListener('click', function () {
          if (!evidence.snapshotId || !activeInvestigationId) return;
          apiPost('/api/investigations/' + activeInvestigationId + '/image-metadata/gps', {
            snapshotId: evidence.snapshotId
          }).then(function (body) {
            var lines = (body.gps || []).map(function (item) {
              var line = item.latitude + ', ' + item.longitude;
              if (item.altitude) line += ', altitude ' + item.altitude;
              return line;
            });
            precise.textContent = lines.join(' | ');
          }).catch(function (err) {
            precise.textContent = err && err.message ? err.message : 'Precise coordinates are unavailable.';
          });
        });
        block.appendChild(button);
        block.appendChild(precise);
      }
    }

    var openEvidence = null;

    /* Updates the report already on screen after a confirmed deletion.
       It does not ask the server for a historical report. */
    function noteSealedFileDeleted() {
      var hash = document.getElementById('image-evidence-sha256');
      var availability = document.getElementById('image-evidence-availability');
      if (!hash || !availability) return false;
      var sealed = hash.textContent;
      availability.textContent = 'The file was removed after this assessment. The sealed identity is unchanged.';
      availability.setAttribute('data-availability', 'subsequently_deleted');
      hash.textContent = sealed;
      if (openEvidence && openEvidence.currentFile) {
        openEvidence.currentFile.availability = 'subsequently_deleted';
      }
      return true;
    }

    return {
      screen: screen,
      render: render,
      renderFailure: renderFailure,
      markStep: markStep,
      resetSteps: resetSteps,
      noteSealedFileDeleted: noteSealedFileDeleted
    };
  })();

  /* ---------------------------------------------------------
     Wiring
     --------------------------------------------------------- */
  /* ---------------------------------------------------------
     RC.image — Phase 4C: local image metadata investigation.
     Everything here runs in the browser against the File object
     the person selected. Nothing is uploaded, fetched, or sent to
     any connector, provider, or logging endpoint. No reverse-image
     search happens here — that requires a real connector that does
     not currently exist in this environment (see Phase 4A).
     --------------------------------------------------------- */
  RC.image = (function () {

    var currentObjectUrl = null;
    /* The most recently processed image's metadata, made available to
       RC.engine.investigate() via getEvidence(). This is the ONLY
       bridge between the two modules — nothing here ever touches
       RC.evidence, RC.quality, or the sources array. */
    var currentEvidence = null;

    function humanSize(bytes) {
      if (typeof bytes !== 'number') return 'Unknown';
      if (bytes < 1024) return bytes + ' B';
      if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
      return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    }

    function readDimensions(objectUrl) {
      return new Promise(function (resolve) {
        var img = new Image();
        img.onload = function () { resolve({ width: img.naturalWidth, height: img.naturalHeight }); };
        img.onerror = function () { resolve({ width: null, height: null }); };
        img.src = objectUrl;
      });
    }

    /* Exact-file hash only (SHA-256 of the raw bytes) via the
       browser's own SubtleCrypto — no network call. This is NOT a
       perceptual/similarity hash: it will not match a resized,
       recompressed, or edited copy of the same image. Kept for
       possible future integration with a real reverse-search
       provider, once one exists. */
    function sha256(file) {
      if (!window.crypto || !window.crypto.subtle) return Promise.resolve(null);
      return file.arrayBuffer()
        .then(function (buf) { return window.crypto.subtle.digest('SHA-256', buf); })
        .then(function (hashBuf) {
          var bytes = Array.from(new Uint8Array(hashBuf));
          return bytes.map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
        })
        .catch(function () { return null; });
    }

    /* Only exifr does the actual EXIF parsing. The page serves exifr
       7.1.3 from this origin. It reads the local File and makes no
       network request. If it isn't available, that is reported plainly
       rather than silently producing an empty result that looks the
       same as "no EXIF present." */
    function readExif(file) {
      if (!window.exifr || typeof window.exifr.parse !== 'function') {
        return Promise.resolve({ unavailable: true });
      }
      return window.exifr.parse(file, {
        tiff: true, ifd0: true, exif: true, gps: true,
        interop: false, makerNote: false, userComment: false, thumbnail: false
      }).then(function (tags) {
        return tags || {};
      }).catch(function () {
        /* A parse failure (corrupt/unsupported segment) is not the
           same claim as "no metadata" — kept distinct in the UI. */
        return { failed: true };
      });
    }

    function formatExifDate(v) {
      if (!v) return null;
      try {
        var d = (v instanceof Date) ? v : new Date(v);
        if (isNaN(d.getTime())) return String(v);
        return d.toISOString().slice(0, 19).replace('T', ' ');
      } catch (e) { return String(v); }
    }

    function buildMetadata(file, dims, exif, hash) {
      var unavailable = !!exif.unavailable;
      var failed = !!exif.failed;
      var hasExif = !unavailable && !failed && exif && Object.keys(exif).length > 0;

      var captureDate = hasExif ? (exif.DateTimeOriginal || exif.CreateDate || null) : null;
      var lat = hasExif && typeof exif.latitude === 'number' ? roundLocalCoordinate(exif.latitude) : null;
      var lon = hasExif && typeof exif.longitude === 'number' ? roundLocalCoordinate(exif.longitude) : null;

      return {
        fileName: file.name || 'Unknown file',
        fileType: file.type || 'Unknown',
        fileSize: humanSize(file.size),
        width: dims.width, height: dims.height,
        exifUnavailable: unavailable,
        exifParseFailed: failed,
        hasExif: hasExif,
        captureDate: formatExifDate(captureDate),
        make: hasExif ? (exif.Make || null) : null,
        model: hasExif ? (exif.Model || null) : null,
        orientation: hasExif && exif.Orientation != null ? exif.Orientation : null,
        software: hasExif ? (exif.Software || null) : null,
        gpsLat: lat, gpsLon: lon,
        sha256: hash
      };
    }

    function field(label, value) {
      var row = el('div', 'why-row why-row-stack');
      row.appendChild(el('span', 'why-k', label));
      row.appendChild(el('span', 'why-v', value));
      return row;
    }

    function render(container, meta) {
      container.textContent = '';
      container.style.display = '';

      container.appendChild(el('div', 'claim-label', 'Local image metadata'));
      container.appendChild(field('File type', meta.fileType));
      container.appendChild(field('File size', meta.fileSize));
      container.appendChild(field('Dimensions', meta.width && meta.height ? (meta.width + ' × ' + meta.height + ' px') : 'Not available'));

      if (meta.exifUnavailable) {
        container.appendChild(el('p', 'demo-note', 'Local metadata extraction is unavailable in this view (the metadata library did not load). File-level details above are still accurate.'));
      } else if (meta.exifParseFailed) {
        container.appendChild(el('p', 'demo-note', 'This file\u2019s metadata could not be parsed. This is not the same as confirming no metadata exists.'));
      } else if (!meta.hasExif) {
        container.appendChild(el('p', 'demo-note', 'No usable EXIF metadata found. This is common (many images strip EXIF on save or share) and is not, by itself, an indicator of manipulation.'));
      } else {
        container.appendChild(field('Capture date/time (EXIF)', meta.captureDate || 'Not available'));
        container.appendChild(field('Camera/device make', meta.make || 'Not available'));
        container.appendChild(field('Camera/device model', meta.model || 'Not available'));
        container.appendChild(field('Orientation', meta.orientation != null ? String(meta.orientation) : 'Not available'));

        var softwareRow = field('Editing/creation software (EXIF)', meta.software || 'Not available');
        container.appendChild(softwareRow);
        if (meta.software) {
          container.appendChild(el('p', 'source-flag', 'Presence of software metadata is an indicator only \u2014 it does not by itself mean this image was manipulated. Most images, edited or not, pass through some software on export.'));
        }

        container.appendChild(field('GPS coordinates (EXIF)', (meta.gpsLat != null && meta.gpsLon != null) ? (formatLocalCoordinate(meta.gpsLat) + ', ' + formatLocalCoordinate(meta.gpsLon)) : 'Not available'));
      }

      if (meta.sha256) {
        container.appendChild(field('File hash (SHA-256)', meta.sha256));
        container.appendChild(el('p', 'source-flag', 'Exact-file match only \u2014 a resized, recompressed, or edited copy of this same image will have a different hash. Calculated on this device. It is not the server file identity.'));
      } else if (meta.hashSkippedLargeFile) {
        container.appendChild(el('p', 'demo-note', 'File hash skipped for this file (large file size) to avoid a slow in-browser read.'));
      }

      container.appendChild(el('p', 'demo-note', 'Metadata is supporting evidence only. It does not by itself establish when, where, or how this image was created, and missing or stripped metadata is not evidence of manipulation.'));
    }

    var currentFile = null;
    var sendConsent = false;
    var requestToken = 0;
    var HASH_SIZE_LIMIT = 50 * 1024 * 1024; /* 50MB — above this, skip hashing rather than risk hanging the browser on a full in-memory read; EXIF parsing itself only reads header segments and stays fast regardless of file size. */

    function handleFile(file) {
      var previewImg = $('#preview-img');
      var filenameEl = $('#preview-filename');
      var previewBox = $('#image-preview');
      var metaBlock = $('#image-metadata-block');

      if (!file || file.type.indexOf('image/') !== 0) {
        tooltip('Please choose an image file.');
        return;
      }
      currentFile = file;
      sendConsent = false;
      setSendChoice(true, 'Choose whether this image may be sent with Check now. Nothing is transmitted until you confirm send and then check the claim.');

      /* Guards against a fast second selection: if the person picks
         another image before the first one's promises resolve, only
         the result matching the most recent selection may render. */
      var myToken = ++requestToken;

      if (currentObjectUrl) { URL.revokeObjectURL(currentObjectUrl); currentObjectUrl = null; }
      var objectUrl = URL.createObjectURL(file);
      currentObjectUrl = objectUrl;

      previewImg.src = objectUrl;
      filenameEl.textContent = file.name;
      previewBox.classList.add('has-image');

      metaBlock.textContent = '';
      metaBlock.style.display = '';
      metaBlock.appendChild(el('p', 'demo-note', 'Reading local metadata\u2026'));

      var hashPromise = file.size > HASH_SIZE_LIMIT ? Promise.resolve(null) : sha256(file);

      Promise.all([readDimensions(objectUrl), readExif(file), hashPromise])
        .then(function (results) {
          if (myToken !== requestToken) return; /* superseded by a later selection */
          var meta = buildMetadata(file, results[0], results[1], results[2]);
          if (file.size > HASH_SIZE_LIMIT) {
            meta.sha256 = null;
            meta.hashSkippedLargeFile = true;
          }
          currentEvidence = meta;
          render(metaBlock, meta);
        })
        .catch(function () {
          if (myToken !== requestToken) return;
          metaBlock.textContent = '';
          metaBlock.appendChild(el('p', 'demo-note', 'Local metadata could not be read for this file.'));
        });
    }

    function setSendChoice(visible, status) {
      var box = $('#image-send-choice');
      var line = $('#image-send-status');
      if (box) box.style.display = visible ? '' : 'none';
      if (line) line.textContent = status || '';
    }

    function confirmedUpload() {
      if (!sendConsent || !currentFile) return null;
      return {
        file: currentFile,
        clientSha256: currentEvidence && currentEvidence.sha256 ? currentEvidence.sha256 : '',
        metadataConsent: !!(document.getElementById('metadata-consent') && document.getElementById('metadata-consent').checked)
      };
    }

    function init() {
      var fileInput = $('#image-file-input');
      var uploadBtn = $('#upload-btn');
      var sendBtn = $('#send-image-btn');
      var keepBtn = $('#keep-image-btn');
      if (!fileInput || !uploadBtn) return;

      uploadBtn.addEventListener('click', function () { fileInput.click(); });
      fileInput.addEventListener('change', function (e) {
        var file = e.target.files && e.target.files[0];
        if (file) handleFile(file);
      });
      if (sendBtn) {
        sendBtn.addEventListener('click', function () {
          if (!currentFile) return;
          sendConsent = true;
          setSendChoice(true, 'Confirmed: this image will upload when you click Check now (after investigation consent and sign-in), including any embedded location or camera details still in the file. You can still choose to keep it on this device instead.');
        });
      }
      if (keepBtn) {
        keepBtn.addEventListener('click', function () {
          sendConsent = false;
          setSendChoice(true, 'This image stays on this device. It will not be sent.');
        });
      }
    }

    /* Snapshot, not a live reference — an investigation in progress must
       not see a different image if the person uploads a new one mid-run. */
    function getEvidence() {
      return currentEvidence ? JSON.parse(JSON.stringify(currentEvidence)) : null;
    }

    /* Resets image state for a fresh check. Revokes the object URL and
       restores the empty-preview UI so a text-only investigation after
       this never carries stale image evidence. */
    function clear() {
      currentEvidence = null;
      currentFile = null;
      sendConsent = false;
      if (currentObjectUrl) { URL.revokeObjectURL(currentObjectUrl); currentObjectUrl = null; }
      var previewBox = $('#image-preview');
      var metaBlock = $('#image-metadata-block');
      var previewImg = $('#preview-img');
      var fileInput = $('#image-file-input');
      if (previewBox) previewBox.classList.remove('has-image');
      if (previewImg) previewImg.src = '';
      if (metaBlock) { metaBlock.textContent = ''; metaBlock.style.display = 'none'; }
      if (fileInput) fileInput.value = '';
      var metadataConsent = document.getElementById('metadata-consent');
      if (metadataConsent) metadataConsent.checked = false;
      setSendChoice(false, '');
    }

      return { init: init, getEvidence: getEvidence, clear: clear, confirmedUpload: confirmedUpload };
  })();

  function providerStatusText() {
    if (!RC.runtime.state.mcp) {
      return 'Live investigation is currently unavailable. The claim will be analysed, but no sources can be retrieved in this view.';
    }
    var p = RC.retrieval.active();
    if (p.id !== 'none') return 'Searching through ' + p.label + '.';
    return 'Live investigation is currently unavailable. The claim will be analysed, but no sources can be retrieved in this view.';
  }

  var pendingClaim = null;
  var activeDialog = null;
  var dialogLastFocus = null;

  function investigationConsentGiven() {
    var box = document.getElementById('investigation-consent');
    return !!(box && box.checked);
  }

  function dialogPanel(dialog) {
    if (!dialog) return null;
    return dialog.querySelector('[role="dialog"]') || dialog;
  }

  function isFocusableCandidate(node) {
    if (!node || node.disabled) return false;
    if (node.getAttribute('aria-hidden') === 'true') return false;
    if (node.hasAttribute('hidden')) return false;
    var el = node;
    while (el && el !== document.documentElement) {
      if (el.hidden || el.hasAttribute('inert')) return false;
      if (el.getAttribute && el.getAttribute('aria-hidden') === 'true') return false;
      el = el.parentElement;
    }
    return true;
  }

  function focusableIn(root) {
    if (!root) return [];
    return Array.prototype.slice.call(root.querySelectorAll(
      'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'
    )).filter(isFocusableCandidate);
  }

  function backgroundInertTargets() {
    return [
      document.querySelector('.skip-link'),
      document.querySelector('header.nav'),
      document.getElementById('app'),
      document.querySelector('footer')
    ].filter(Boolean);
  }

  function setBackgroundInert(on) {
    backgroundInertTargets().forEach(function (node) {
      if (on) node.setAttribute('inert', '');
      else node.removeAttribute('inert');
    });
  }

  function openDialog(dialog, initialFocus) {
    if (!dialog) return;
    if (activeDialog && activeDialog !== dialog) {
      closeDialog(activeDialog, { restoreFocus: false });
    }
    if (!activeDialog) {
      dialogLastFocus = document.activeElement;
    }
    activeDialog = dialog;
    dialog.hidden = false;
    setBackgroundInert(true);
    var panel = dialogPanel(dialog);
    var target = initialFocus || focusableIn(panel)[0] || panel;
    function placeFocus() {
      if (activeDialog !== dialog || dialog.hidden) return;
      if (target && isFocusableCandidate(target) && target.focus) target.focus();
      else if (panel && panel.focus) panel.focus();
    }
    placeFocus();
    window.setTimeout(placeFocus, 0);
  }

  function closeDialog(dialog, options) {
    var opts = options || {};
    if (!dialog) return;
    dialog.hidden = true;
    if (activeDialog === dialog) activeDialog = null;
    if (!activeDialog) setBackgroundInert(false);
    if (opts.restoreFocus === false) return;
    var restore = dialogLastFocus;
    dialogLastFocus = null;
    if (restore && restore.focus && isFocusableCandidate(restore)) {
      restore.focus();
    }
  }

  function run(raw, options) {
    var opts = options || {};
    var input = (raw || '').trim();
    var field = $('#investigate-input');

    if (!input) {
      field.classList.add('shake');
      setTimeout(function () { field.classList.remove('shake'); }, 400);
      tooltip('Enter a claim or paste a URL to check.');
      field.focus();
      return;
    }
    if (/^https?:\/\//i.test(input) && !isUrl(input)) {
      tooltip('That address does not look complete. Check it and try again.');
      return;
    }
    if (!investigationConsentGiven()) {
      tooltip('Confirm the investigation consent checkbox before checking a claim.');
      var consent = document.getElementById('investigation-consent');
      if (consent && consent.focus) consent.focus();
      return;
    }
    if (!csrfToken) {
      pendingClaim = input;
      openAuth('Sign in to check a claim.');
      return;
    }

    pendingClaim = null;
    RC.ui.resetSteps();
    $('#investigating-claim-text').textContent = input;
    $('#investigating-status').textContent = providerStatusText();
    RC.ui.screen('investigating');

    RC.engine.investigate(input, RC.ui.markStep)
      .then(function (report) { RC.ui.render(report); })
      .catch(function (err) { RC.ui.renderFailure(err, input); });
  }

  function init() {
    RC.runtime.begin();
    RC.retrieval.use('parallel');
    RC.image.init();

    var navToggle = $('#nav-mobile-toggle');
    var primaryNav = $('#primary-nav');
    function setNavOpen(open) {
      if (!primaryNav || !navToggle) return;
      primaryNav.classList.toggle('is-open', open);
      navToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
      navToggle.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
      navToggle.textContent = open ? 'Close' : 'Menu';
    }
    if (navToggle && primaryNav) {
      navToggle.addEventListener('click', function () {
        setNavOpen(!primaryNav.classList.contains('is-open'));
      });
      primaryNav.querySelectorAll('a').forEach(function (link) {
        link.addEventListener('click', function () { setNavOpen(false); });
      });
    }

    $('#check-btn').addEventListener('click', function () {
      run($('#investigate-input').value);
    });

    var consentBox = document.getElementById('investigation-consent');
    if (consentBox) {
      consentBox.addEventListener('change', function () {
        syncInvestigationConsentUi();
      });
    }
    syncInvestigationConsentUi();

    $('#investigate-input').addEventListener('keydown', function (e) {
      if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') run(this.value);
    });

    $$('.example-try').forEach(function (b) {
      b.addEventListener('click', function () {
        var c = this.getAttribute('data-claim');
        $('#investigate-input').value = c;
        $('#investigate-input').focus();
        document.getElementById('investigate-panel').scrollIntoView({ behavior: 'smooth', block: 'center' });
      });
    });

    $('#url-btn').addEventListener('click', function () {
      var f = $('#investigate-input');
      f.focus();
      tooltip('Claim or URL field focused. Paste a full https:// address there.');
    });

    ['#back-btn', '#back-btn-2', '#new-check-btn'].forEach(function (sel) {
      var n = $(sel);
      if (n) n.addEventListener('click', function () {
        $('#investigate-input').value = '';
        RC.image.clear();
        var activity = $('#results-provider-activity');
        if (activity) {
          activity.hidden = true;
          activity.textContent = '';
        }
        RC.ui.screen('home');
      });
    });

    $('#why-toggle').addEventListener('click', function () {
      var panel = $('#why-panel');
      if (!panel) return;
      var open = this.getAttribute('aria-expanded') === 'true';
      this.setAttribute('aria-expanded', String(!open));
      panel.hidden = open;
      this.textContent = open ? 'Why this assessment?' : 'Hide explanation';
    });

    $('#sign-in-btn').addEventListener('click', function (e) {
      e.preventDefault();
      if (csrfToken) {
        apiPost('/api/auth/logout', {}).then(finishSignOut, finishSignOut);
        return;
      }
      pendingClaim = null;
      openAuth('');
    });

    var authMode = 'login';
    var authDialog = $('#auth-dialog');
    var authForm = $('#auth-form');
    var authError = $('#auth-error');

    function setSignedIn(on) {
      var button = $('#sign-in-btn');
      var accountBtn = $('#account-btn');
      if (button) button.textContent = on ? 'Sign out' : 'Sign in';
      if (accountBtn) accountBtn.hidden = !on;
    }

    function finishSignOut() {
      csrfToken = null;
      pendingClaim = null;
      setSignedIn(false);
      closeAccount();
    }

    function showAuthError(message) {
      authError.hidden = !message;
      authError.textContent = message || '';
    }

    function setAuthPasswordRules(visible) {
      var rules = $('#auth-password-rules');
      if (rules) rules.hidden = !visible;
      var password = $('#auth-password');
      if (password) {
        if (visible) {
          password.setAttribute('minlength', '12');
          password.setAttribute('maxlength', '128');
        }
      }
    }

    function setAuthNote(creating) {
      var note = $('#auth-note');
      if (!note) return;
      note.textContent = '';
      if (!creating) {
        note.textContent = 'Sign in to save and review your investigations.';
        return;
      }
      note.appendChild(document.createTextNode(
        'Create an account to save and review your investigations.'
      ));
      note.appendChild(document.createElement('br'));
      note.appendChild(document.createElement('br'));
      note.appendChild(document.createTextNode('Before continuing, please review the '));
      var privacyLink = el('a', null, 'Pilot Privacy Notice');
      privacyLink.href = 'privacy.html';
      note.appendChild(privacyLink);
      note.appendChild(document.createTextNode(
        ' to understand how your investigation information is processed.'
      ));
    }

    openAuth = function (message) {
      authMode = 'login';
      $('#auth-title').textContent = 'Sign in';
      $('#auth-submit').textContent = 'Sign in';
      $('#auth-switch').textContent = 'Create an account';
      $('#auth-password').setAttribute('autocomplete', 'current-password');
      setAuthNote(false);
      setAuthPasswordRules(false);
      showAuthError(message);
      clearTooltip();
      openDialog(authDialog, $('#auth-email'));
    }

    function closeAuth() {
      closeDialog(authDialog);
      showAuthError('');
      setAuthPasswordRules(false);
    }

    $('#auth-cancel').addEventListener('click', function () {
      pendingClaim = null;
      closeAuth();
    });
    authDialog.addEventListener('click', function (e) {
      if (e.target === authDialog) {
        pendingClaim = null;
        closeAuth();
      }
    });
    $('#auth-switch').addEventListener('click', function () {
      authMode = authMode === 'login' ? 'register' : 'login';
      var creating = authMode === 'register';
      $('#auth-title').textContent = creating ? 'Create an account' : 'Sign in';
      $('#auth-submit').textContent = creating ? 'Create account' : 'Sign in';
      $('#auth-switch').textContent = creating ? 'Have an account? Sign in' : 'Create an account';
      $('#auth-password').setAttribute('autocomplete', creating ? 'new-password' : 'current-password');
      setAuthNote(creating);
      setAuthPasswordRules(creating);
      showAuthError('');
      if (activeDialog === authDialog) {
        var emailField = $('#auth-email');
        if (emailField && emailField.focus) emailField.focus();
      }
    });
    authForm.addEventListener('submit', function (e) {
      e.preventDefault();
      var email = $('#auth-email').value;
      var password = $('#auth-password').value;
      var submit = $('#auth-submit');
      submit.disabled = true;
      showAuthError('');
      var start = authMode === 'register'
        ? apiPost('/api/auth/register', { email: email, password: password })
        : Promise.resolve({ ok: true });
      start.then(function () {
        return apiPost('/api/auth/login', { email: email, password: password });
      }).then(function (session) {
        csrfToken = session.csrfToken;
        setSignedIn(true);
        closeAuth();
        var resume = pendingClaim;
        pendingClaim = null;
        if (resume && investigationConsentGiven()) {
          $('#investigate-input').value = resume;
          run(resume, { resumed: true });
        }
      }).catch(function (err) {
        showAuthError((err && err.message) || 'Sign in could not be completed.');
      }).then(function () {
        submit.disabled = false;
      });
    });

    var accountDialog = $('#account-dialog');
    var accountForm = $('#account-delete-form');
    var accountError = $('#account-delete-error');
    var accountStatus = $('#account-delete-status');

    function showAccountError(message) {
      if (!accountError) return;
      accountError.hidden = !message;
      accountError.textContent = message || '';
    }

    function showAccountStatus(message) {
      if (!accountStatus) return;
      accountStatus.hidden = !message;
      accountStatus.textContent = message || '';
    }

    function openAccount() {
      if (!csrfToken) {
        openAuth('Sign in to manage your account.');
        return;
      }
      if (accountForm) accountForm.reset();
      showAccountError('');
      showAccountStatus('');
      if (accountDialog) {
        openDialog(accountDialog, $('#account-delete-password'));
      }
    }

    function closeAccount() {
      if (accountDialog) closeDialog(accountDialog);
      showAccountError('');
      showAccountStatus('');
    }

    document.addEventListener('keydown', function (e) {
      if (!activeDialog || activeDialog.hidden) return;
      if (e.key === 'Escape') {
        e.preventDefault();
        if (activeDialog === authDialog) {
          pendingClaim = null;
          closeAuth();
        } else if (activeDialog === accountDialog) {
          closeAccount();
        }
        return;
      }
      if (e.key !== 'Tab') return;
      var panel = dialogPanel(activeDialog);
      var nodes = focusableIn(panel);
      if (!nodes.length) {
        e.preventDefault();
        if (panel && panel.focus) panel.focus();
        return;
      }
      var first = nodes[0];
      var last = nodes[nodes.length - 1];
      var current = document.activeElement;
      if (!panel.contains(current)) {
        e.preventDefault();
        (e.shiftKey ? last : first).focus();
        return;
      }
      if (e.shiftKey && current === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && current === last) {
        e.preventDefault();
        first.focus();
      }
    });

    var accountBtn = $('#account-btn');
    if (accountBtn) {
      accountBtn.addEventListener('click', function (e) {
        e.preventDefault();
        openAccount();
      });
    }
    var accountCancel = $('#account-cancel');
    if (accountCancel) accountCancel.addEventListener('click', closeAccount);
    if (accountDialog) {
      accountDialog.addEventListener('click', function (e) {
        if (e.target === accountDialog) closeAccount();
      });
    }
    if (accountForm) {
      accountForm.addEventListener('submit', function (e) {
        e.preventDefault();
        if (!csrfToken) {
          showAccountError('Sign in again before deleting the account.');
          return;
        }
        var password = $('#account-delete-password').value;
        var confirmed = $('#account-delete-confirm');
        if (!confirmed || !confirmed.checked) {
          showAccountError('Confirm that you understand the deletion limits.');
          return;
        }
        var submit = $('#account-delete-submit');
        if (submit) submit.disabled = true;
        showAccountError('');
        showAccountStatus('Deleting account…');
        apiDelete('/api/auth/account', { password: password }).then(function () {
          finishSignOut();
          showAccountStatus('');
          tooltip('Your account was deleted on this server. Earlier backups and provider copies may still exist.');
          RC.ui.screen('home');
        }).catch(function (err) {
          var message = (err && err.message) || 'The account could not be deleted.';
          if (err && err.code === 'asset_cleanup_failed') {
            message = err.message || message;
          }
          showAccountStatus('');
          showAccountError(message);
        }).then(function () {
          if (submit) submit.disabled = false;
        });
      });
    }

    apiGet('/api/auth/session').then(function (session) {
      csrfToken = session.csrfToken;
      setSignedIn(true);
    }, function () {
      csrfToken = null;
      setSignedIn(false);
    });

    /* Reflect real capability state on the home panel once known. */
    RC.runtime.ready().then(function (rt) {
      var hint = $('#panel-hint');
      if (!rt.sample) {
        hint.textContent = 'Analysis model unavailable in this view.';
        return;
      }
      hint.textContent = RC.retrieval.isLive()
        ? 'Evidence first. Conclusions second.'
        : 'Live investigation is currently unavailable in this view.';
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
