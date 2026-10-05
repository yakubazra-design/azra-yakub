"""RealityCheck AI migration backend.

The frontend is not connected to these routes yet. Quality, independence,
timeline, and image-metadata logic remain in frontend/engine.js.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.config import Settings
from app.errors import ProviderError
from app.openai_client import OpenAIClient
from app.parallel_client import ParallelClient
from app.prompts import assess_prompt, extract_claims_prompt
from app.validation import normalise_claims, validate_assessment


class SearchRequest(BaseModel):
    queries: list[str] = Field(default_factory=list)
    sessionId: str | None = None


class FetchRequest(BaseModel):
    url: str
    sessionId: str | None = None


class ExtractClaimsRequest(BaseModel):
    input: str
    kind: str = "claim"


class AssessRequest(BaseModel):
    primaryClaim: str = ""
    verifiablePoints: list[str] = Field(default_factory=list)
    sources: list[dict] = Field(default_factory=list)
    independence: dict = Field(default_factory=dict)
    timeline: dict = Field(default_factory=dict)
    imageEvidence: dict | None = None


def create_app(
    settings: Settings | None = None,
    parallel_transport=None,
    openai_transport=None,
    retry_wait: float = 0.0,
) -> FastAPI:
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        app.state.parallel.close()
        app.state.openai.close()

    app = FastAPI(title="RealityCheck AI", version="migration-0.1.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.parallel = ParallelClient(
        settings.parallel_api_key,
        settings.parallel_api_base,
        transport=parallel_transport,
        retry_wait=retry_wait,
    )
    app.state.openai = OpenAIClient(
        settings.openai_api_key,
        settings.openai_api_base,
        transport=openai_transport,
        retry_wait=retry_wait,
    )

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_methods=["GET", "POST"],
            allow_headers=["Content-Type"],
        )

    @app.exception_handler(ProviderError)
    async def provider_error(_request: Request, exc: ProviderError):
        return JSONResponse(status_code=exc.status_code, content={"code": exc.code, "message": exc.message})

    @app.get("/api/health")
    def health():
        return {
            "status": "ok",
            "openaiConfigured": settings.openai_configured,
            "parallelConfigured": settings.parallel_configured,
        }

    @app.post("/api/investigations/search")
    def search(body: SearchRequest):
        return app.state.parallel.search(body.queries, body.sessionId)

    @app.post("/api/investigations/fetch")
    def fetch(body: FetchRequest):
        url = body.url.strip()
        if not url.startswith(("http://", "https://")):
            return JSONResponse(
                status_code=400,
                content={"code": "bad_url", "message": "A web page address is required."},
            )
        return app.state.parallel.fetch(url, body.sessionId)

    @app.post("/api/investigations/extract-claims")
    def extract_claims(body: ExtractClaimsRequest):
        kind = "url" if body.kind == "url" else "claim"
        prompt = extract_claims_prompt(body.input, kind)
        raw = app.state.openai.complete_json(
            prompt,
            settings.openai_model_default,
            "Claim analysis is unavailable in this view.",
        )
        return normalise_claims(raw, body.input)

    @app.post("/api/investigations/assess")
    def assess(body: AssessRequest):
        ctx = body.model_dump()
        prompt = assess_prompt(ctx)
        raw = app.state.openai.complete_json(
            prompt,
            settings.openai_model_complex,
            "Assessment is unavailable in this view.",
        )
        return validate_assessment(raw, len(body.sources))

    return app


app = create_app()
