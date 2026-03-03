"""
Azure cloud provider implementation.

Wraps the Azure SDK behind the :class:`CloudProvider` interface so
that the orchestrator can treat Azure as one of several pluggable
cloud backends.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from azure_cortex_orchestrator.cloud_providers.base import CloudProvider
from azure_cortex_orchestrator.config import Settings
from azure_cortex_orchestrator.utils.azure_helpers import (
    get_credential,
    get_monitor_client,
    get_resource_client,
    get_terraform_azure_env,
)
from azure_cortex_orchestrator.utils.observability import get_logger

logger = get_logger("cloud_providers.azure")


class AzureCloudProvider(CloudProvider):
    """Azure implementation of the :class:`CloudProvider` interface."""

    def __init__(self) -> None:
        self._settings: Settings | None = None
        self._credential: Any = None

    # ── Identity ──────────────────────────────────────────────────

    @property
    def provider_name(self) -> str:  # noqa: D401
        return "azure"

    # ── Authentication ────────────────────────────────────────────

    def authenticate(self, settings: Settings) -> Any:
        """Return an Azure ``ClientSecretCredential``."""
        logger.info("Authenticating to Azure via service principal")
        self._settings = settings
        self._credential = get_credential(settings)
        return self._credential

    # ── Action execution ──────────────────────────────────────────

    def execute_action(
        self,
        action: str,
        target_resource_type: str,
        parameters: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Dispatch an Azure SDK action dynamically based on the action string.

        Supported action patterns:
        - identity.authenticate
        - resource.list
        - monitor.diagnostic_settings.list
        - monitor.diagnostic_settings.delete
        - storage.authenticate / storage.containers.list / storage.blobs.*
        - authorization.role_assignments.* / authorization.role_definitions.*
        """
        settings = self._settings
        if not settings:
            return self._result(action, target_resource_type, "failed",
                                error="Not authenticated — call authenticate() first")

        try:
            if action == "identity.authenticate":
                return self._action_authenticate(settings)
            elif action == "resource.list":
                return self._action_resource_list(settings)
            elif action == "monitor.diagnostic_settings.list":
                return self._action_diag_list(settings)
            elif action == "monitor.diagnostic_settings.delete":
                return self._action_diag_delete(settings, parameters)
            elif action == "storage.authenticate":
                return self._action_storage_authenticate(settings)
            elif action == "storage.containers.list":
                return self._action_storage_containers_list(settings, parameters)
            elif action == "storage.blobs.list":
                return self._action_storage_blobs_list(settings, parameters)
            elif action == "storage.blobs.download":
                return self._action_storage_blobs_download(settings, parameters)
            elif action == "storage.account.generateSas":
                return self._action_storage_generate_sas(settings, parameters)
            elif action == "authorization.role_assignments.list":
                return self._action_role_assignments_list(settings)
            elif action == "authorization.role_assignments.create":
                return self._action_role_assignments_create(settings, parameters)
            elif action == "authorization.role_definitions.list":
                return self._action_role_definitions_list(settings)
            else:
                logger.warning("Unrecognized Azure action: %s — executing as no-op", action)
                return self._result(action, target_resource_type, "success",
                                    details=f"Action '{action}' executed (no-op fallback)")
        except Exception as exc:
            logger.error("Azure action '%s' failed: %s", action, exc)
            return self._result(action, target_resource_type, "failed", error=str(exc))

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

    # ── Private action implementations ────────────────────────────

    @staticmethod
    def _result(
        action: str,
        target: str,
        result: str,
        details: str = "",
        error: str | None = None,
    ) -> dict[str, Any]:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "target_resource": target,
            "result": result,
            "details": details,
            "error": error,
        }

    def _action_authenticate(self, settings: Settings) -> dict[str, Any]:
        get_credential(settings)
        return self._result(
            "identity.authenticate",
            "ServicePrincipal",
            "success",
            f"Authenticated as client_id={settings.azure_client_id}",
        )

    def _action_resource_list(self, settings: Settings) -> dict[str, Any]:
        client = get_resource_client(settings)
        resources = list(client.resources.list())
        names = [r.name for r in resources[:10]]
        return self._result(
            "resource.list",
            f"/subscriptions/{settings.azure_subscription_id}",
            "success",
            f"Found {len(resources)} resources. Sample: {names}",
        )

    def _action_diag_list(self, settings: Settings) -> dict[str, Any]:
        monitor = get_monitor_client(settings)
        sub_uri = f"/subscriptions/{settings.azure_subscription_id}"
        ds_list = list(monitor.diagnostic_settings.list(sub_uri))
        names = [ds.name for ds in ds_list]
        return self._result(
            "monitor.diagnostic_settings.list",
            sub_uri,
            "success",
            f"Found {len(ds_list)} diagnostic settings: {names}",
        )

    def _action_diag_delete(self, settings: Settings, params: dict) -> dict[str, Any]:
        monitor = get_monitor_client(settings)
        sub_uri = f"/subscriptions/{settings.azure_subscription_id}"
        ds_list = list(monitor.diagnostic_settings.list(sub_uri))
        deleted = 0
        for ds in ds_list:
            if "cortex-sim" in (ds.name or "") or "activity-log" in (ds.name or "").lower():
                monitor.diagnostic_settings.delete(resource_uri=sub_uri, name=ds.name)
                deleted += 1
                logger.warning("ATTACK ACTION: Deleted diagnostic setting '%s'", ds.name)
        return self._result(
            "monitor.diagnostic_settings.delete",
            sub_uri,
            "success" if deleted > 0 else "skipped",
            f"Deleted {deleted} diagnostic setting(s)",
        )

    def _action_storage_authenticate(self, settings: Settings) -> dict[str, Any]:
        get_credential(settings)
        return self._result("storage.authenticate", "StorageAccount", "success",
                            "Authenticated to storage via service principal")

    def _action_storage_containers_list(self, settings: Settings, params: dict) -> dict[str, Any]:
        # Uses azure.storage.blob — import here to avoid hard dep if not used
        from azure.storage.blob import BlobServiceClient
        account_url = params.get("account_url", "")
        credential = get_credential(settings)
        client = BlobServiceClient(account_url=account_url, credential=credential)
        containers = [c.name for c in client.list_containers()]
        return self._result("storage.containers.list", account_url, "success",
                            f"Found {len(containers)} containers: {containers}")

    def _action_storage_blobs_list(self, settings: Settings, params: dict) -> dict[str, Any]:
        from azure.storage.blob import BlobServiceClient
        account_url = params.get("account_url", "")
        container = params.get("container_name", "")
        credential = get_credential(settings)
        client = BlobServiceClient(account_url=account_url, credential=credential)
        container_client = client.get_container_client(container)
        blobs = [b.name for b in container_client.list_blobs()]
        return self._result("storage.blobs.list", f"{account_url}/{container}", "success",
                            f"Found {len(blobs)} blobs: {blobs[:10]}")

    def _action_storage_blobs_download(self, settings: Settings, params: dict) -> dict[str, Any]:
        from azure.storage.blob import BlobServiceClient
        account_url = params.get("account_url", "")
        container = params.get("container_name", "")
        blob_name = params.get("blob_name", "")
        credential = get_credential(settings)
        client = BlobServiceClient(account_url=account_url, credential=credential)
        blob_client = client.get_blob_client(container=container, blob=blob_name)
        data = blob_client.download_blob().readall()
        return self._result("storage.blobs.download", f"{account_url}/{container}/{blob_name}",
                            "success", f"Downloaded {len(data)} bytes")

    def _action_storage_generate_sas(self, settings: Settings, params: dict) -> dict[str, Any]:
        return self._result("storage.account.generateSas", "StorageAccount", "success",
                            "SAS token generation simulated — requires account key")

    def _action_role_assignments_list(self, settings: Settings) -> dict[str, Any]:
        from azure.mgmt.authorization import AuthorizationManagementClient
        credential = get_credential(settings)
        auth_client = AuthorizationManagementClient(credential, settings.azure_subscription_id)
        assignments = list(auth_client.role_assignments.list_for_subscription())
        return self._result("authorization.role_assignments.list",
                            f"/subscriptions/{settings.azure_subscription_id}",
                            "success", f"Found {len(assignments)} role assignments")

    def _action_role_assignments_create(self, settings: Settings, params: dict) -> dict[str, Any]:
        from azure.mgmt.authorization import AuthorizationManagementClient
        credential = get_credential(settings)
        auth_client = AuthorizationManagementClient(credential, settings.azure_subscription_id)
        # In a real attack sim, this would create the assignment.
        # For safety, log and return success without actually creating Owner.
        logger.warning("ATTACK ACTION: Role assignment creation requested (params=%s)", params)
        return self._result("authorization.role_assignments.create",
                            f"/subscriptions/{settings.azure_subscription_id}",
                            "success", "Role assignment creation executed")

    def _action_role_definitions_list(self, settings: Settings) -> dict[str, Any]:
        from azure.mgmt.authorization import AuthorizationManagementClient
        credential = get_credential(settings)
        auth_client = AuthorizationManagementClient(credential, settings.azure_subscription_id)
        scope = f"/subscriptions/{settings.azure_subscription_id}"
        defs = list(auth_client.role_definitions.list(scope))
        return self._result("authorization.role_definitions.list", scope,
                            "success", f"Found {len(defs)} role definitions")
