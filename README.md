# RealityCheck AI — Migration Package (Claude → Cursor)

"Evidence before conclusions." An evidence-investigation tool: submit a claim or a URL, it searches for
real sources, classifies their quality, detects duplicate/shared-origin sources, builds a timeline, and
produces one of six assessments with a full "Why this assessment?" explanation. It also supports local,
privacy-preserving image metadata (EXIF) inspection.

This package contains the **complete, current, working frontend** — nothing has been simplified, rewritten,
or stripped down for this export. Where something is Claude-specific, it's called out explicitly below
rather than silently papered over.

## How the application currently works

Everything lives in `frontend/engine.js`, organized as modules under one `window.RC` object, loaded by
`frontend/index.html` alongside `frontend/styles.css`. There is no build step — it's plain ES5-style JS,
designed to run as a single static page.

1. The person types a claim or pastes a URL, optionally attaches an image.
2. `RC.engine.investigate()` orchestrates: understand the claim → search sources → classify quality →
   check independence/shared-origin → build a timeline → assess → render.
3. Two things in this pipeline currently call out to Claude's Artifact runtime rather than a normal API
   (see **Claude-specific components** below) — everything else is ordinary JavaScript logic that will
   run unmodified anywhere.

## Completed phases (all present in this export, all working)

- **Phase 2 — Core investigation engine**: claim/URL understanding, real source retrieval via Parallel
  Search, source-quality classification (`RC.quality`), source independence and shared-origin detection
  (`RC.evidence.independence` — same-host grouping, DOI/title/author cross-domain mirror detection,
  explicit-attribution echo detection, each with an "uncertain" tier rather than false confidence),
  Evidence Timeline with honest date-type handling (`RC.evidence.buildTimeline`), the six-outcome
  assessment taxonomy, and the full Evidence Chain UI.
- **Reliability hardening**: a technical search failure (e.g. connector down) is a distinct failure
  state, never silently relabeled "Insufficient Evidence" (see `RC.engine.collect`/`investigate`,
  `report.searchFailed`). Retry-with-backoff on retryable connector errors (`withRetry`).
- **Phase 4C — Local image metadata**: client-side-only EXIF extraction via the `exifr` library (loaded
  from a CDN, never sent anywhere) — `RC.image`. Computes a local SHA-256 file hash. Never concludes
  manipulation from missing/present EXIF; always labeled as supporting evidence only.
- **Phase 4E — Image evidence wiring**: `RC.image.getEvidence()` feeds a snapshot of the local metadata
  into `RC.engine.investigate()` as `report.imageEvidence`, kept structurally separate from web sources
  (never enters `RC.evidence.independence` or `RC.quality`), with its own section in the assessment
  prompt and its own "Image evidence" block in the results UI.

## Pending / NOT implemented

- **Live Capture Verification** ("LIVE-SESSION VERIFIED" challenge/nonce workflow) — **this was only
  designed and partially coded in a prior Claude session; it was never completed, never wired into the
  UI, never tested, and was lost when that session's scratch environment reset before being saved.**
  It does not exist anywhere in this codebase. Per the instruction that this only be included if
  implemented and tested, it is correctly absent here, not silently dropped. If you want it, it needs to
  be built from scratch in Cursor — the design (nonce generation, a session record with start/receipt
  timestamps, explicit "receipt ≠ capture" wording, failure-case handling) is known and can be
  redescribed on request, but no working code for it currently exists.
- **Reverse image search** — deliberately never built. A connector-discovery pass (Phase 4A) found no
  reverse-image-search capability available in the Claude environment this was built in. Parallel Search
  is text-only. This needs a real provider (e.g. TinEye, Google Vision, Bing Visual Search) chosen and
  wired up fresh in Cursor.
- Image manipulation/deepfake detection — never implemented or claimed; out of scope by design.

## Claude-specific components — exact locations

These are the **only** places this code depends on Claude's Artifact runtime rather than a normal web
API. Everything else is portable as-is.

| What | Where (`frontend/engine.js`) | What it does |
|---|---|---|
| `window.claude.use('sample')` | line 84 | Obtains the model-reasoning capability |
| `window.claude.use('mcp')` | line 85 | Obtains the connector-calling capability |
| `mcp.callTool('Parallel Search', 'web_search', input)` | line 206 | Real web search, inside `RC.retrieval.providers.parallel.searchSources` |
| `mcp.callTool('Parallel Search', 'web_fetch', input)` | line 243 | Real page fetch, inside `.fetchSource` |
| `sample.json(prompt, {modelTier:'default'})` | line 698 | Claim-understanding call, inside `RC.reasoning.extractClaims` |
| `sample.json(prompt, {modelTier:'complex'})` | line 787 | Assessment call, inside `RC.reasoning.assess` |
| Artifact capability declaration | *(not in this file — set at publish time)* | `{"mcp":{"servers":[{"server":"Parallel Search","tools":["web_search","web_fetch"]}]},"sample":{}}` |

`RC.runtime` (top of the file) is what resolves these two capabilities at page load and exposes them as
`RC.runtime.state.sample` / `RC.runtime.state.mcp` to the rest of the app — this is the one place that
needs real replacement logic, not every call site individually.

## What must be replaced in Cursor

1. **Search/fetch.** Replace the two `mcp.callTool(...)` calls with real HTTP calls to Parallel Search's
   own API (needs a backend — browser JS calling a third-party search API directly with a secret key is
   not safe to ship). The request/response shapes are already confirmed real and documented in code
   comments right above each call site — reuse them as-is.
2. **Reasoning.** Replace the two `sample.json(...)` calls with real calls to an LLM API (OpenAI or
   otherwise) from your new backend. **The prompt strings themselves are the tested, working logic —
   copy them verbatim**; only the transport (`sample.json` → your own `fetch('/api/assess', ...)`, say)
   changes.
3. **`RC.runtime`.** Replace capability resolution with a simple check for your new backend's
   availability instead of `window.claude.use(...)`.
4. Everything else — `RC.quality`, `RC.evidence`, `RC.image`, `RC.ui`, `RC.engine`'s orchestration — is
   plain JavaScript and needs no changes to run in Cursor.

**Do not simplify or rewrite the reasoning prompts or the independence/quality logic while doing this.**
They encode a lot of iteratively-fixed edge-case handling (see the real test history referenced in code
comments — DOI/title-mirror detection, shared-origin echo detection, the technical-failure-vs-insufficient-
evidence distinction, etc.). Port them, don't "clean them up."

## Required environment variables

See `.env.example` at the project root. None of these have real values filled in — you'll need your own
keys.

- `OPENAI_API_KEY` — or whichever LLM provider you choose for the reasoning backend.
- `PARALLEL_API_KEY` — Parallel Search's own API key (the Claude MCP connector didn't require one
  visible to this code, but Parallel's direct API will).
- `PARALLEL_MCP_URL` — kept for reference; your new backend will likely call Parallel's REST API
  directly rather than its MCP endpoint.
- `OPENAI_MODEL_DEFAULT` / `OPENAI_MODEL_COMPLEX` — the two reasoning calls currently use
  `modelTier: 'default'` and `'complex'` respectively; map these to two real model names of whatever
  capability split makes sense for your provider.
- `ALLOWED_ORIGINS` — for your new backend's CORS config, once one exists.

## Project structure

```
realitycheck-ai/
├── frontend/
│   ├── index.html      — UI markup, loads styles.css + engine.js (+ exifr from a CDN)
│   ├── styles.css       — all styling (original design + every later addition)
│   └── engine.js        — the entire application logic (window.RC)
├── backend/
│   └── NO_BACKEND_YET.md — explains what needs to be built; nothing invented here
├── reference/
│   └── phase1-original-design.mhtml — the original approved visual design, for comparison
├── README.md             — this file
└── .env.example
```
