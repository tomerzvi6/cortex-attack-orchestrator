"""
Azure SDK helper utilities for Azure-Cortex Orchestrator.

Provides credential factories and management client constructors
using service principal environment variables.
"""

from __future__ import annotations

from azure.identity import ClientSecretCredential
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.resource.subscriptions import SubscriptionClient

from azure_cortex_orchestrator.config import Settings
from azure_cortex_orchestrator.utils.observability import get_logger

logger = get_logger("azure_helpers")


def get_credential(settings: Settings) -> ClientSecretCredential:
    """
    Build an Azure ``ClientSecretCredential`` from the configured
    service principal environment variables.
    """
    logger.debug(
        "Creating ClientSecretCredential (tenant=%s, client=%s)",
        settings.azure_tenant_id,
        settings.azure_client_id,
    )
    return ClientSecretCredential(
        tenant_id=settings.azure_tenant_id,
        client_id=settings.azure_client_id,
        client_secret=settings.azure_client_secret,
    )


def get_resource_client(settings: Settings) -> ResourceManagementClient:
    """Create an Azure ResourceManagementClient."""
    credential = get_credential(settings)
    return ResourceManagementClient(credential, settings.azure_subscription_id)


def get_monitor_client(settings: Settings) -> MonitorManagementClient:
    """Create an Azure MonitorManagementClient."""
    credential = get_credential(settings)
    return MonitorManagementClient(credential, settings.azure_subscription_id)


def get_subscription_client(settings: Settings) -> SubscriptionClient:
    """Create an Azure SubscriptionClient."""
    credential = get_credential(settings)
    return SubscriptionClient(credential)


def get_terraform_azure_env(settings: Settings) -> dict[str, str]:
    """
    Build a dict of Azure credential environment variables
    suitable for passing to Terraform subprocess calls.
    """
    return {
        "ARM_CLIENT_ID": settings.azure_client_id,
        "ARM_CLIENT_SECRET": settings.azure_client_secret,
        "ARM_TENANT_ID": settings.azure_tenant_id,
        "ARM_SUBSCRIPTION_ID": settings.azure_subscription_id,
    }
