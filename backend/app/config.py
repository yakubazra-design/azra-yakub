"""Server configuration. Credentials stay in the environment or local .env."""

import ipaddress
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
    ledger_path: str = ""
    cookie_secure: bool = False
    auth_secret: str = ""
    session_ttl_seconds: int = 60 * 60 * 12
    realitycheck_env: str = "local"
    trusted_proxies: str = ""
    c2pa_trust_root: str = ""
    c2pa_trust_state_path: str = ""
    c2pa_trust_pin_path: str = ""
    c2pa_trust_caller_id: str = ""
    c2pa_witness_mac_key: str = ""
    c2pa_root_mac_key: str = ""
    # V1.2.A Secure Video Ingestion — defaults keep the feature inactive.
    video_ingest_enabled: bool = False
    video_allow_tier_b: bool = False
    # Seal-path switch only. Default True embeds verified video identity when a
    # ready video_assets row exists. False never silently omits an attached
    # video: sealing is blocked with video_seal_integration_disabled while a
    # row remains. Investigations with no video still seal normally. Does not
    # enable upload, probe, Tier B, or ingest HTTP; those stay gated by
    # video_ingest_enabled / video_allow_tier_b.
    video_seal_integration: bool = True
    ffprobe_path: str = ""

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

    @property
    def production(self) -> bool:
        return self.realitycheck_env.strip().lower() == "production"

    @property
    def trusted_proxy_addresses(self) -> tuple[frozenset[str], bool]:
        """Return the proxy addresses and whether every entry is a single IP.

        An empty list is valid. A hostname, a CIDR range, or any other token
        is not. Callers decide whether an empty list is allowed.
        """
        addresses: set[str] = set()
        for token in self.trusted_proxies.split(","):
            text = token.strip()
            if not text:
                continue
            try:
                addresses.add(ipaddress.ip_address(text).compressed)
            except ValueError:
                return frozenset(), False
        return frozenset(addresses), True

    @property
    def ledger_file(self) -> Path:
        if self.ledger_path.strip():
            return Path(self.ledger_path)
        return ROOT / "data" / "ledger.sqlite"

    @property
    def c2pa_trust_path_values(self) -> tuple[str, str, str]:
        return (
            self.c2pa_trust_root.strip(),
            self.c2pa_trust_state_path.strip(),
            self.c2pa_trust_pin_path.strip(),
        )

    @property
    def c2pa_trust_is_complete(self) -> bool:
        """A local store needs every path, the caller id, and both MAC keys."""
        return all(self.c2pa_trust_path_values) and bool(
            self.c2pa_trust_caller_id.strip()
            and self.c2pa_witness_mac_key.strip()
            and self.c2pa_root_mac_key.strip()
        )

    @property
    def c2pa_trust_remote(self) -> bool:
        """A URL or UNC path is not a local trust configuration."""
        for value in self.c2pa_trust_path_values:
            lowered = value.lower()
            if "://" in lowered or lowered.startswith("//") or lowered.startswith("\\\\"):
                return True
        return False
