"""
Configuration module for Azure-Cortex Orchestrator.

Loads settings from environment variables (with .env file support)
and exposes a validated Settings dataclass.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

# Load .env file if present (project root)
_env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=_env_path, override=False)


class ConfigError(Exception):
    """Raised when required configuration is missing or invalid."""


@dataclass
class Settings:
    """Application settings loaded from environment variables."""

    # ── OpenAI ────────────────────────────────────────────────────
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini-mini"

    # ── Azure Service Principal ───────────────────────────────────
    azure_client_id: str = ""
    azure_client_secret: str = ""
    azure_tenant_id: str = ""
    azure_subscription_id: str = ""

    # ── Cortex XDR (optional) ─────────────────────────────────────
    cortex_xdr_api_key: str = ""
    cortex_xdr_fqdn: str = ""

    # ── Safety Guardrails ─────────────────────────────────────────
    resource_group_prefix: str = "cortex-sim-"
    allowed_subscriptions: list[str] = field(default_factory=list)
    max_terraform_resources: int = 15

    # ── Observability ─────────────────────────────────────────────
    log_level: str = "INFO"

    # ── Paths ─────────────────────────────────────────────────────
    project_root: Path = field(default_factory=lambda: Path(__file__).resolve().parent.parent)
    reports_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parent / "reports")
    terraform_tmp_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parent.parent / "tmp" / "terraform")

    @property
    def has_cortex_xdr(self) -> bool:
        return bool(self.cortex_xdr_api_key and self.cortex_xdr_fqdn)

    def validate(self, dry_run: bool = False) -> None:
        """
        Validate that all required settings are present.

        Args:
            dry_run: If True, Azure credentials are not required.
        """
        errors: list[str] = []

        if not self.openai_api_key:
            errors.append("OPENAI_API_KEY is required")

        if not dry_run:
            if not self.azure_client_id:
                errors.append("AZURE_CLIENT_ID is required")
            if not self.azure_client_secret:
                errors.append("AZURE_CLIENT_SECRET is required")
            if not self.azure_tenant_id:
                errors.append("AZURE_TENANT_ID is required")
            if not self.azure_subscription_id:
                errors.append("AZURE_SUBSCRIPTION_ID is required")

        if errors:
            raise ConfigError(
                "Missing required configuration:\n" + "\n".join(f"  - {e}" for e in errors)
            )


def load_settings() -> Settings:
    """Load settings from environment variables."""
    allowed_subs_raw = os.environ.get("ALLOWED_SUBSCRIPTIONS", "")
    allowed_subs = [s.strip() for s in allowed_subs_raw.split(",") if s.strip()]

    return Settings(
        # OpenAI
        openai_api_key=os.environ.get("OPENAI_API_KEY", ""),
        openai_model=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
        # Azure
        azure_client_id=os.environ.get("AZURE_CLIENT_ID", ""),
        azure_client_secret=os.environ.get("AZURE_CLIENT_SECRET", ""),
        azure_tenant_id=os.environ.get("AZURE_TENANT_ID", ""),
        azure_subscription_id=os.environ.get("AZURE_SUBSCRIPTION_ID", ""),
        # Cortex XDR
        cortex_xdr_api_key=os.environ.get("CORTEX_XDR_API_KEY", ""),
        cortex_xdr_fqdn=os.environ.get("CORTEX_XDR_FQDN", ""),
        # Safety
        resource_group_prefix=os.environ.get("RESOURCE_GROUP_PREFIX", "cortex-sim-"),
        allowed_subscriptions=allowed_subs,
        max_terraform_resources=int(os.environ.get("MAX_TERRAFORM_RESOURCES", "15")),
        # Observability
        log_level=os.environ.get("LOG_LEVEL", "INFO"),
    )
