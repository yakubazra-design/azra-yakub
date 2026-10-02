# Backend transport adapter

`backend/app` is a FastAPI transport adapter. It does not classify sources, score independence, build timelines, validate assessments, or read images.

It exposes:

- `GET /api/health`
- `POST /api/investigations/search` — Parallel Search MCP `web_search`
- `POST /api/investigations/fetch` — Parallel Search MCP `web_fetch`
- `POST /api/investigations/extract-claims` — OpenAI, prompt forwarded unchanged
- `POST /api/investigations/assess` — OpenAI, prompt forwarded unchanged

Parallel uses the Streamable HTTP MCP endpoint `PARALLEL_MCP_URL` (default `https://search.parallel.ai/mcp`). `PARALLEL_API_KEY` is optional and is sent only if that endpoint responds `401`.

Run from the repository root:

```bash
pip install -r backend/requirements.txt
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

The frontend still calls Claude's artifact runtime. It has not been switched to these routes yet.
