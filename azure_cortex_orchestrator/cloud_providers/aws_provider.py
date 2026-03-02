"""
AWS cloud provider scaffold.

Implements the :class:`CloudProvider` interface with stub methods.
Full AWS SDK integration is planned for a future release.
"""

from __future__ import annotations

import os
from typing import Any

from azure_cortex_orchestrator.cloud_providers.base import CloudProvider
from azure_cortex_orchestrator.utils.observability import get_logger

logger = get_logger("cloud_providers.aws")


class AWSCloudProvider(CloudProvider):
    """AWS scaffold of the :class:`CloudProvider` interface."""

    # ── Identity ──────────────────────────────────────────────────

    @property
    def provider_name(self) -> str:  # noqa: D401
        return "aws"

    # ── Authentication ────────────────────────────────────────────

    def authenticate(self, settings: Any) -> Any:
        """Authenticate to AWS.  **Not yet implemented.**"""
        raise NotImplementedError("AWS provider coming soon")

    # ── Action execution ──────────────────────────────────────────

    def execute_action(
        self,
        action: str,
        target_resource_type: str,
        parameters: dict[str, Any],
    ) -> dict[str, Any]:
        """Execute an AWS action.  **Not yet implemented.**"""
        raise NotImplementedError("AWS provider coming soon")

    # ── Terraform helpers ─────────────────────────────────────────

    def get_terraform_provider_block(self) -> str:
        return (
            'provider "aws" {\n'
            '  region = var.aws_region\n'
            '}\n'
        )

    def get_terraform_env_vars(self, settings: Any) -> dict[str, str]:
        """
        Return AWS credential environment variables for Terraform.

        Values are read from *settings* attributes if available,
        falling back to ``os.environ``.
        """
        return {
            "AWS_ACCESS_KEY_ID": getattr(
                settings, "aws_access_key_id", ""
            ) or os.environ.get("AWS_ACCESS_KEY_ID", ""),
            "AWS_SECRET_ACCESS_KEY": getattr(
                settings, "aws_secret_access_key", ""
            ) or os.environ.get("AWS_SECRET_ACCESS_KEY", ""),
            "AWS_DEFAULT_REGION": getattr(
                settings, "aws_default_region", ""
            ) or os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
        }
