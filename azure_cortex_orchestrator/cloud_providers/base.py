"""
Abstract base class for cloud provider integrations.

Each cloud provider (Azure, AWS, GCP, …) implements this interface
so that the orchestrator can target multiple clouds with the same
graph and scenario definitions.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class CloudProvider(ABC):
    """
    Cloud provider abstraction layer.

    Concrete implementations wrap the SDK specifics for a given cloud
    (authentication, Terraform provider blocks, action execution).
    """

    # ── Identity ──────────────────────────────────────────────────

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Short lowercase identifier, e.g. ``"azure"`` or ``"aws"``."""
        ...

    # ── Authentication ────────────────────────────────────────────

    @abstractmethod
    def authenticate(self, settings: Any) -> Any:
        """
        Authenticate to the cloud provider using *settings*.

        Returns a provider-specific credential object that can be
        reused for subsequent SDK calls.
        """
        ...

    # ── Action execution ──────────────────────────────────────────

    @abstractmethod
    def execute_action(
        self,
        action: str,
        target_resource_type: str,
        parameters: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Execute a single simulation action against the cloud.

        Args:
            action: SDK action identifier (e.g.
                ``"monitor.diagnostic_settings.delete"``).
            target_resource_type: Cloud resource type being targeted.
            parameters: Action-specific parameters.

        Returns:
            A ``SimulationAction``-like dict with keys:
            ``timestamp``, ``action``, ``target_resource``, ``result``,
            ``details``, and optionally ``error``.
        """
        ...

    # ── Terraform helpers ─────────────────────────────────────────

    @abstractmethod
    def get_terraform_provider_block(self) -> str:
        """
        Return the HCL ``provider`` block for this cloud.

        Example (Azure)::

            provider "azurerm" {
              features {}
            }
        """
        ...

    @abstractmethod
    def get_terraform_env_vars(self, settings: Any) -> dict[str, str]:
        """
        Return environment variables that Terraform needs in order to
        authenticate to this cloud provider.

        The dict is merged into the subprocess environment when running
        ``terraform plan`` / ``terraform apply``.
        """
        ...
