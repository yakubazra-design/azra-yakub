"""Server-side settings. Secrets stay in the process environment."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    openai_api_key: str = ""
    openai_model_default: str = ""
    openai_model_complex: str = ""
    parallel_api_key: str = ""
    parallel_mcp_url: str = "https://search.parallel.ai/mcp"
    allowed_origins: str = ""

    search_timeout_seconds: float = 30
    fetch_timeout_seconds: float = 30
    extract_claims_timeout_seconds: float = 30
    assess_timeout_seconds: float = 60
    retry_backoff_seconds: float = 0.75

    @property
    def openai_configured(self) -> bool:
        return bool(
            self.openai_api_key.strip()
            and self.openai_model_default.strip()
            and self.openai_model_complex.strip()
        )

    @property
    def parallel_configured(self) -> bool:
        return bool(self.parallel_mcp_url.strip())

    @property
    def cors_origins(self) -> list[str]:
        return [item.strip() for item in self.allowed_origins.split(",") if item.strip()]


def load_settings() -> Settings:
    return Settings()
