"""Server configuration. Credentials stay in the environment or local .env."""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    openai_api_key: str = ""
    parallel_api_key: str = ""
    parallel_mcp_url: str = "https://search.parallel.ai/mcp"
    openai_model_default: str = "gpt-4.1-mini"
    openai_model_complex: str = "gpt-4.1"
    allowed_origins: str = ""
    parallel_api_base: str = "https://api.parallel.ai"
    openai_api_base: str = "https://api.openai.com"

    model_config = SettingsConfigDict(
        env_file=str(ROOT / ".env"),
        extra="ignore",
    )

    @property
    def openai_configured(self) -> bool:
        return bool(self.openai_api_key.strip())

    @property
    def parallel_configured(self) -> bool:
        return bool(self.parallel_api_key.strip())

    @property
    def cors_origins(self) -> list[str]:
        return [part.strip() for part in self.allowed_origins.split(",") if part.strip()]
