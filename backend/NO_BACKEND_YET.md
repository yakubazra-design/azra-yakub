# No backend exists in this project

This is not an oversight — RealityCheck AI has never had a conventional backend. Every "server-side"
behavior (web search/fetch, and the claim-understanding/assessment reasoning) currently runs through
Claude's own Artifact runtime capabilities, called directly from `frontend/engine.js` in the browser:

- `window.claude.use('mcp')` → `mcp.callTool('Parallel Search', 'web_search' | 'web_fetch', input)`
- `window.claude.use('sample')` → `sample.json(prompt, { modelTier })`

Neither of these exists outside a published Claude artifact. **A real backend needs to be built in
Cursor** to replace both:

1. A search/fetch endpoint — call Parallel Search's own API directly (`PARALLEL_API_KEY`), or another
   provider, from your backend rather than through Claude's MCP broker.
2. A reasoning/assessment endpoint — call an LLM API directly (e.g. OpenAI, `OPENAI_API_KEY`) with the
   same prompts currently built in `RC.reasoning` (see `frontend/engine.js`, functions `extractClaims`
   and `assess`) — those prompt strings are the real, tested logic; port them as-is into your new
   backend calls rather than rewriting them.

See the top-level `README.md` for the full list of call sites and exactly what each one needs to be
replaced with.
