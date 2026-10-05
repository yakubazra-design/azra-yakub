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

  function isUrl(s) {
    var t = (s || '').trim();
    if (/\s/.test(t)) return false;
    return /^https?:\/\/[^\s]+\.[^\s]+/i.test(t);
  }

  function hostOf(url) {
    try { return new URL(url).hostname.replace(/^www\./, '').toLowerCase(); }
    catch (e) { return ''; }
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
      if (!window.claude || typeof window.claude.use !== 'function') {
        resolve({ sample: null, mcp: null });
        return;
      }
      Promise.all([
        window.claude.use('sample').catch(function () { return null; }),
        window.claude.use('mcp').catch(function () { return null; })
      ]).then(function (r) {
        resolve({ sample: r[0], mcp: r[1] });
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

        var input = {
          objective: 'Find sources that confirm, contradict, or provide context for the claim being investigated.',
          search_queries: clamped,
          session_id: sessionId
        };

        return withRetry(function () { return mcp.callTool(PARALLEL_SERVER, 'web_search', input); }).then(function (result) {
          var payload = result && result.payload;
          var results = (payload && Array.isArray(payload.results)) ? payload.results : [];
          return results.map(function (r) {
            var text = Array.isArray(r.excerpts) ? r.excerpts.join(' ').trim() : '';
            return {
              url: r.url,
              title: r.title || null,
              snippet: text,
              publishedAt: r.publish_date || null,
              /* Parallel's own date has been observed to vary across
                 calls for the same URL, so it is shown as provider-
                 reported rather than a fixed fact. */
              dateCertainty: 'provider-reported',
              /* The connector gives one date with no type attached — it
                 can be a crawl/index date as easily as a true publish
                 date. Only an explicit label in the text upgrades it. */
              dateType: r.publish_date ? detectDateType(text + ' ' + (r.title || '')) : null,
              provider: 'Parallel Search'
            };
          }).filter(function (s) { return !!s.url; });
        }, function (err) {
          return Promise.reject({ code: err && err.code, message: mcpErrorMessage(err) });
        });
      },

      fetchSource: function (url) {
        var mcp = mcpNamespace();
        if (!mcp) {
          return Promise.reject({ code: 'no_mcp', message: 'Live investigation is currently unavailable.' });
        }
        var input = {
          urls: [url],
          objective: 'Extract the page text needed to identify the factual claims it makes.',
          full_content: true,
          session_id: sessionId
        };
        return withRetry(function () { return mcp.callTool(PARALLEL_SERVER, 'web_fetch', input); }).then(function (result) {
          var payload = result && result.payload;
          var results = (payload && Array.isArray(payload.results)) ? payload.results : [];
          var errors = (payload && Array.isArray(payload.errors)) ? payload.errors : [];

          if (!results.length) {
            return Promise.reject({
              code: 'fetch_empty',
              message: errors.length ? String(errors[0]) : 'The page returned no usable content.'
            });
          }
          var r = results[0];
          var text = r.full_content || (Array.isArray(r.excerpts) ? r.excerpts.join('\n\n') : '');
          if (!text) {
            return Promise.reject({ code: 'fetch_empty', message: 'The page returned no usable content.' });
          }
          return {
            url: r.url || url,
            title: r.title || null,
            text: text,
            publishedAt: r.publish_date || null,
            dateCertainty: 'provider-reported',
            dateType: r.publish_date ? detectDateType(text.slice(0, 2000) + ' ' + (r.title || '')) : null
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

      return s.json(prompt, { modelTier: 'default' }).then(function (r) {
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

      var imageBlock = '';
      if (ctx.imageEvidence) {
        var ie = ctx.imageEvidence;
        imageBlock =
          '\nIMAGE EVIDENCE (extracted locally from an uploaded file by the person — never sent to, or checked against, any web source; not part of the numbered SOURCES list above and must never be cited with a [number]):\n' +
          '  file=' + ie.fileName + ' | type=' + ie.fileType + ' | dimensions=' + (ie.width && ie.height ? ie.width + 'x' + ie.height : 'not available') + '\n' +
          '  EXIF capture date=' + (ie.captureDate || 'not available') + ' | camera make=' + (ie.make || 'not available') + ' | camera model=' + (ie.model || 'not available') + '\n' +
          '  orientation=' + (ie.orientation != null ? ie.orientation : 'not available') + ' | editing/creation software (EXIF)=' + (ie.software || 'not available') + '\n' +
          '  GPS=' + (ie.gpsLat != null ? ie.gpsLat.toFixed(6) + ',' + ie.gpsLon.toFixed(6) : 'not available') + ' | file hash (SHA-256)=' + (ie.sha256 || 'not computed') + '\n' +
          'Rules for image evidence, all mandatory:\n' +
          '- If an EXIF capture date IS present, you may treat it as supporting metadata evidence for a date-related claim, but it is self-reported by the file and can be edited or wrong — do not treat it as proof on its own, especially with no corroborating web source.\n' +
          '- If an EXIF capture date is NOT available, say exactly that the capture date could not be established from EXIF — this is an absence of one kind of evidence, never itself evidence that the claimed date is wrong. Never phrase it as "the photo was not taken in [year]".\n' +
          '- Missing or stripped EXIF, or the presence of editing-software metadata, is never itself evidence of manipulation — do not use POTENTIAL_MANIPULATION on this basis alone.\n' +
          '- The SHA-256 hash identifies this exact file. It establishes nothing about when or where the photo was taken.\n' +
          '- Keep "no EXIF date available" and "no web source dated this" as two distinct statements if both apply. Never merge them into one sentence that blurs which kind of evidence was checked.\n';
      }

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

      return s.json(prompt, { modelTier: 'complex' }).then(function (r) {
        return validate(r, ctx.sources.length);
      });
    }

    var VALID = ['VERIFIED', 'PARTIALLY_VERIFIED', 'CONTRADICTED',
      'INSUFFICIENT_EVIDENCE', 'POTENTIAL_MANIPULATION', 'UNRESOLVED'];

    /* Anything referring to a source that was never retrieved is
       dropped rather than shown. */
    function validate(r, sourceCount) {
      var ok = function (n) { return Number.isInteger(n) && n >= 0 && n < sourceCount; };

      var assessment = VALID.indexOf(r.assessment) >= 0 ? r.assessment : 'UNRESOLVED';
      if (sourceCount === 0) assessment = 'INSUFFICIENT_EVIDENCE';

      var findings = (Array.isArray(r.findings) ? r.findings : [])
        .map(function (f) {
          return {
            type: ['support', 'contradict', 'inconsistent', 'caution'].indexOf(f.type) >= 0 ? f.type : 'caution',
            text: String(f.text || '').trim(),
            sources: (Array.isArray(f.sources) ? f.sources : []).filter(ok)
          };
        })
        .filter(function (f) { return f.text.length > 0; });

      var om = r.originalMaterial || {};
      var original = {
        established: !!om.established && ok(om.source),
        description: String(om.description || '').trim(),
        source: ok(om.source) ? om.source : null
      };

      var why = r.why || {};
      return {
        assessment: assessment,
        findings: findings,
        originalMaterial: original,
        why: {
          supporting: String(why.supporting || '').trim(),
          contradicting: String(why.contradicting || '').trim(),
          sourceQuality: String(why.sourceQuality || '').trim(),
          timeline: String(why.timeline || '').trim(),
          uncertain: String(why.uncertain || '').trim(),
          choice: String(why.choice || '').trim()
        },
        uncertainty: (Array.isArray(r.uncertainty) ? r.uncertainty : [])
          .map(function (u) { return String(u).trim(); })
          .filter(Boolean)
      };
    }

    return { available: available, extractClaims: extractClaims, assess: assess };
  })();

  /* ---------------------------------------------------------
     RC.engine — orchestration
     --------------------------------------------------------- */
  RC.engine = (function () {

    var STEPS = ['understand', 'search', 'original', 'dates', 'contradictions', 'assess'];

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

      return RC.runtime.ready()
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
                  quality: RC.quality.classify(rawInput),
                  publishedAt: page.publishedAt || null
                };
                return RC.reasoning.extractClaims(page.text, 'url');
              }, function (err) {
                report.errors.push({
                  stage: 'fetch',
                  message: err && err.message ? err.message : 'The page could not be fetched.'
                });
                report.pageClaim = { url: rawInput, title: null, quality: RC.quality.classify(rawInput), publishedAt: null };
                throw {
                  code: 'fetch_failed',
                  message: 'The submitted page could not be read, so its claims could not be identified. ' +
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
            report.sources = [];
            report.independence = RC.evidence.independence([]);
            report.timeline = RC.evidence.buildTimeline([]);
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

            /* ---- Step 3: original material ---- */
            step('original', 'active');
            /* ---- Step 4: dates ---- */
            report.timeline = RC.evidence.buildTimeline(sources);
            step('original', 'done');

            step('dates', 'active');
            step('dates', 'done');

            /* ---- Step 5: cross-check ---- */
            step('contradictions', 'active');
            report.independence = RC.evidence.independence(sources);
            step('contradictions', 'done');

            /* ---- Step 6: assessment ---- */
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
      if (provider.id === 'none') return Promise.resolve([]);

      return provider.searchSources(queries).then(function (raw) {
        var seen = {};
        var out = [];
        (raw || []).forEach(function (r) {
          if (!r || !r.url || seen[r.url]) return;
          seen[r.url] = true;
          out.push({
            url: r.url,
            title: r.title || null,
            snippet: r.snippet || '',
            publishedAt: r.publishedAt || null,
            dateCertainty: r.dateCertainty || 'confirmed',
            dateType: r.dateType || null,
            provider: r.provider || provider.id,
            quality: RC.quality.classify(r.url)
          });
        });
        out.sort(function (a, b) { return RC.quality.rank(b.quality.tier) - RC.quality.rank(a.quality.tier); });
        return out.slice(0, 12);
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

      var link = document.createElement('a');
      link.className = 'source-view';
      link.href = src.url;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      link.textContent = 'Open source [' + index + ']';
      card.appendChild(link);
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
      var supports = r.findings.filter(function (f) { return f.type === 'support'; }).length;
      var contra = r.findings.filter(function (f) { return f.type === 'contradict'; }).length;
      var inconsistent = r.findings.filter(function (f) { return f.type === 'inconsistent'; }).length;

      return [
        report.understanding ? report.understanding.primaryClaim : report.input,
        (supports + contra + inconsistent === 0
          ? 'No web evidence statements could be drawn'
          : supports + ' supporting, ' + contra + ' directly contradicting' + (inconsistent ? ', ' + inconsistent + ' inconsistent/counterevidence' : '')) +
          (report.imageEvidence
            ? '. Separately: image evidence — ' + (report.imageEvidence.hasExif ? 'EXIF present' : 'no usable EXIF (capture date not established)')
            : ''),
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

    function renderWhy(report) {
      var r = report.result;
      var panel = el('div', 'why-panel');
      panel.id = 'why-panel';
      panel.hidden = true;

      var rows = [
        ['Supporting evidence', r.why.supporting],
        ['Contradicting evidence', r.why.contradicting],
        ['Source quality', r.why.sourceQuality],
        ['Timeline consistency', r.why.timeline],
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

    function render(report) {
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

      var old = $('#why-panel');
      if (old) old.remove();
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
        pmeta.appendChild(qualityBadge(report.pageClaim.quality.tier));
        pg.appendChild(pmeta);
        pg.appendChild(el('p', 'source-desc', report.pageClaim.quality.reason));
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
          var cls = f.type === 'support' ? 'support' : f.type === 'contradict' ? 'contradict' : 'caution';
          var icon = f.type === 'support' ? '✓' : f.type === 'contradict' ? '✕' : '⚠';
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
        var a = document.createElement('a');
        a.className = 'source-view';
        a.href = src.url; a.target = '_blank'; a.rel = 'noopener noreferrer';
        a.textContent = 'Open source [' + r.originalMaterial.source + ']';
        om.appendChild(a);
      }
      root.appendChild(om);

      /* image evidence — kept structurally separate from web sources;
         reuses the same field()-style rows as the why-panel so no new
         CSS is introduced. */
      if (report.imageEvidence) {
        var ie = report.imageEvidence;
        root.appendChild(section('Image evidence', 'Extracted locally from the uploaded file. Never checked against, or sent to, any web source.'));
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
          if (ie.gpsLat != null) ib.appendChild(row('GPS (EXIF)', ie.gpsLat.toFixed(6) + ', ' + ie.gpsLon.toFixed(6)));
        } else {
          ib.appendChild(row('EXIF', 'No usable EXIF metadata found — the capture date could not be established from EXIF. This is not evidence that any particular date claim is false.'));
        }
        ib.appendChild(row('File hash (SHA-256)', (ie.sha256 || 'Not computed') + ' — identifies this exact file only; does not establish when or where it was taken.'));
        root.appendChild(ib);
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

      var old = $('#why-panel');
      if (old) old.remove();

      $('#results-mode-tag').textContent = 'Investigation failed';
      $('#results-mode-tag').className = 'demo-tag';
      $('#results-mode-note').textContent = 'No assessment was produced. Nothing below is a result.';

      var box = el('div', 'understanding-block');
      box.appendChild(el('p', null, (err && err.message) || 'The investigation could not be completed.'));
      root.appendChild(box);
      screen('results');
    }

    return {
      screen: screen,
      render: render,
      renderFailure: renderFailure,
      markStep: markStep,
      resetSteps: resetSteps
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

    /* Only exifr does the actual EXIF parsing (loaded from the CDN as
       a plain browser library, operating on the local File — it makes
       no network request itself). If it isn't available, that is
       reported plainly rather than silently producing an empty result
       that looks the same as "no EXIF present." */
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
      var lat = hasExif && typeof exif.latitude === 'number' ? exif.latitude : null;
      var lon = hasExif && typeof exif.longitude === 'number' ? exif.longitude : null;

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

        container.appendChild(field('GPS coordinates (EXIF)', (meta.gpsLat != null && meta.gpsLon != null) ? (meta.gpsLat.toFixed(6) + ', ' + meta.gpsLon.toFixed(6)) : 'Not available'));
      }

      if (meta.sha256) {
        container.appendChild(field('File hash (SHA-256)', meta.sha256));
        container.appendChild(el('p', 'source-flag', 'Exact-file match only \u2014 a resized, recompressed, or edited copy of this same image will have a different hash. Computed locally; not sent anywhere.'));
      } else if (meta.hashSkippedLargeFile) {
        container.appendChild(el('p', 'demo-note', 'File hash skipped for this file (large file size) to avoid a slow in-browser read.'));
      }

      container.appendChild(el('p', 'demo-note', 'Metadata is supporting evidence only. It does not by itself establish when, where, or how this image was created, and missing or stripped metadata is not evidence of manipulation.'));
    }

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

    function init() {
      var fileInput = $('#image-file-input');
      var uploadBtn = $('#upload-btn');
      if (!fileInput || !uploadBtn) return;

      uploadBtn.addEventListener('click', function () { fileInput.click(); });
      fileInput.addEventListener('change', function (e) {
        var file = e.target.files && e.target.files[0];
        if (file) handleFile(file);
      });
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
      if (currentObjectUrl) { URL.revokeObjectURL(currentObjectUrl); currentObjectUrl = null; }
      var previewBox = $('#image-preview');
      var metaBlock = $('#image-metadata-block');
      var previewImg = $('#preview-img');
      if (previewBox) previewBox.classList.remove('has-image');
      if (previewImg) previewImg.src = '';
      if (metaBlock) { metaBlock.textContent = ''; metaBlock.style.display = 'none'; }
    }

    return { init: init, getEvidence: getEvidence, clear: clear };
  })();

  function providerStatusText() {
    if (!RC.runtime.state.mcp) {
      return 'Live investigation is currently unavailable. The claim will be analysed, but no sources can be retrieved in this view.';
    }
    var p = RC.retrieval.active();
    if (p.id !== 'none') return 'Searching through ' + p.label + '.';
    return 'Live investigation is currently unavailable. The claim will be analysed, but no sources can be retrieved in this view.';
  }

  function run(raw) {
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

    $('#check-btn').addEventListener('click', function () {
      run($('#investigate-input').value);
    });

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
      tooltip('Paste the full address, starting with https://');
    });

    ['#back-btn', '#back-btn-2', '#new-check-btn'].forEach(function (sel) {
      var n = $(sel);
      if (n) n.addEventListener('click', function () {
        $('#investigate-input').value = '';
        RC.image.clear();
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
      tooltip('Accounts arrive in a later phase.');
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
