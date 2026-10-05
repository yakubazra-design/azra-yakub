# RealityCheck AI backend

FastAPI service for the migration off Claude's artifact runtime. The frontend in `frontend/` is unchanged and is not calling these routes yet.

- `GET /api/health`
- `POST /api/investigations/search`
- `POST /api/investigations/fetch`
- `POST /api/investigations/extract-claims`
- `POST /api/investigations/assess`

Search and fetch call Parallel's server-side Search and Extract APIs. Claim extraction and assessment call OpenAI with the prompts from `frontend/engine.js`. Keys are read from the repository `.env` and are never returned to the client.

Source quality, independence, timeline, and image-metadata logic stay in the frontend.

Non-live tests (mocked Parallel and OpenAI):

```
PYTHONPATH=backend python3 -m pytest backend/tests -q
```
