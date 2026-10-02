"""RealityCheck transport API.

Browser → these routes → Parallel Search MCP or OpenAI.
Evidence logic stays in the frontend.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app.config import load_settings
from backend.app.errors import AppError, RetryableUpstream, exhausted
from backend.app.openai_client import OpenAIClient
from backend.app.parallel_mcp import ParallelMcpClient, has_usable_fetch_content
from backend.app.schemas import FetchRequest, PromptRequest, SearchRequest


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = load_settings()
    app.state.settings = settings
    app.state.parallel = ParallelMcpClient(settings)
    app.state.openai = OpenAIClient(settings)
    yield
    app.state.parallel.close()
    app.state.openai.close()


app = FastAPI(title="RealityCheck AI transport", lifespan=lifespan)

_settings_for_cors = load_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=_settings_for_cors.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)


@app.exception_handler(AppError)
async def app_error_handler(_request: Request, exc: AppError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content=exc.body())


@app.exception_handler(RetryableUpstream)
async def retryable_handler(_request: Request, exc: RetryableUpstream) -> JSONResponse:
    error = exhausted(exc)
    return JSONResponse(status_code=error.status_code, content=error.body())


@app.exception_handler(RequestValidationError)
async def validation_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
    parts = []
    for err in exc.errors():
        loc = ".".join(str(item) for item in err.get("loc", []) if item != "body")
        parts.append(f"{loc}: {err.get('msg')}" if loc else str(err.get("msg")))
    message = "; ".join(parts)[:500] or "Invalid request."
    return JSONResponse(
        status_code=400,
        content={"error": {"code": "invalid_request", "message": message, "retryable": False}},
    )


@app.get("/api/health")
def health(request: Request) -> dict:
    settings = request.app.state.settings
    return {
        "status": "ok",
        "openai_configured": settings.openai_configured,
        "parallel_configured": settings.parallel_configured,
    }


@app.post("/api/investigations/search")
def search(body: SearchRequest, request: Request) -> dict:
    settings = request.app.state.settings
    payload = request.app.state.parallel.search(
        {
            "objective": body.objective,
            "search_queries": body.search_queries,
            "session_id": body.session_id,
        },
        settings.search_timeout_seconds,
    )
    return {"payload": payload}


@app.post("/api/investigations/fetch")
def fetch(body: FetchRequest, request: Request) -> JSONResponse:
    settings = request.app.state.settings
    payload = request.app.state.parallel.fetch(
        {
            "urls": body.urls,
            "objective": body.objective,
            "full_content": body.full_content,
            "session_id": body.session_id,
        },
        settings.fetch_timeout_seconds,
    )
    if not has_usable_fetch_content(payload):
        errors = payload.get("errors") or []
        detail = errors[0] if errors and isinstance(errors[0], str) and errors[0].strip() else "The page returned no usable content."
        return JSONResponse(
            status_code=502,
            content={
                "error": {"code": "fetch_empty", "message": str(detail)[:500], "retryable": False},
                "payload": payload,
            },
        )
    return JSONResponse(status_code=200, content={"payload": payload})


@app.post("/api/investigations/extract-claims")
def extract_claims(body: PromptRequest, request: Request) -> dict:
    if body.modelTier != "default":
        raise AppError(400, "invalid_request", 'modelTier must be "default" for claim extraction.', False)
    settings = request.app.state.settings
    return request.app.state.openai.extract_claims(body.prompt, settings.extract_claims_timeout_seconds)


@app.post("/api/investigations/assess")
def assess(body: PromptRequest, request: Request) -> dict:
    if body.modelTier != "complex":
        raise AppError(400, "invalid_request", 'modelTier must be "complex" for assessment.', False)
    settings = request.app.state.settings
    return request.app.state.openai.assess(body.prompt, settings.assess_timeout_seconds)
