"""
Azure cloud provider implementation.

Wraps the existing helpers in ``azure_helpers.py`` behind the
:class:`CloudProvider` interface so that the orchestrator can treat
Azure as one of several pluggable cloud backends.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from azure_cortex_orchestrator.cloud_providers.base import CloudProvider
from azure_cortex_orchestrator.config import Settings
from azure_cortex_orchestrator.utils.azure_helpers import (
    get_credential,
    get_terraform_azure_env,
)
from azure_cortex_orchestrator.utils.observability import get_logger

logger = get_logger("cloud_providers.azure")


class AzureCloudProvider(CloudProvider):
    """Azure implementation of the :class:`CloudProvider` interface."""

    # ── Identity ──────────────────────────────────────────────────

    @property
    def provider_name(self) -> str:  # noqa: D401
        return "azure"

    # ── Authentication ────────────────────────────────────────────

    def authenticate(self, settings: Settings) -> Any:
        """Return an Azure ``ClientSecretCredential``."""
        logger.info("Authenticating to Azure via service principal")
        return get_credential(settings)

    # ── Action execution ──────────────────────────────────────────

    def execute_action(
        self,
        action: str,
        target_resource_type: str,
        parameters: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Dispatch an Azure SDK action.

        Currently a placeholder that logs the action and returns a
        success dict. Real SDK calls (delete diagnostic settings,
        list resources, etc.) will be wired in future iterations.
        """
        logger.info(
            "Executing Azure action: %s on %s", action, target_resource_type
        )
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "target_resource": target_resource_type,
            "result": "success",
            "details": f"Executed {action} on {target_resource_type}",
            "error": None,
        }

    # ── Terraform helpers ─────────────────────────────────────────

    def get_terraform_provider_block(self) -> str:
        return (
            'provider "azurerm" {\n'
            "  features {}\n"
            "}\n"
        )

    def get_terraform_env_vars(self, settings: Settings) -> dict[str, str]:
        """Delegate to the existing ``get_terraform_azure_env`` helper."""
        return get_terraform_azure_env(settings)
