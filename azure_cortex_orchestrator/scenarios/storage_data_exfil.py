"""
Scenario: Storage Account Data Exfiltration via SAS Token.

An Azure Storage Account containing sensitive data (PII) with an overly
permissive SAS token that never expires. The attacker discovers the storage
account, generates an account-level SAS token using the access keys, and
exfiltrates blob data to an external location.

MITRE ATT&CK Techniques:
- T1530     — Data from Cloud Storage
- T1567     — Exfiltration Over Web Service
- T1078.004 — Valid Accounts: Cloud Accounts
"""

from __future__ import annotations

from azure_cortex_orchestrator.scenarios.registry import Scenario, SimulationStep

SCENARIO = Scenario(
    id="storage_data_exfil",
    name="Storage Account Data Exfiltration via SAS Token",
    description=(
        "An Azure Storage Account containing sensitive data (PII) with an "
        "overly permissive SAS token that never expires. The attacker "
        "discovers the storage account, generates an account-level SAS token "
        "using the access keys, and exfiltrates blob data to an external "
        "location."
    ),
    goal_template=(
        "An Azure Storage Account with sensitive data and overly permissive "
        "access keys. The attacker uses the storage account keys to generate "
        "a SAS token and exfiltrate data from blob containers."
    ),

    # ── MITRE ATT&CK Mapping ─────────────────────────────────────
    expected_mitre_techniques=[
        {
            "id": "T1530",
            "name": "Data from Cloud Storage",
            "description": (
                "The attacker accesses data stored in cloud storage "
                "containers to collect sensitive information."
            ),
            "tactic": "Collection",
            "url": "https://attack.mitre.org/techniques/T1530/",
        },
        {
            "id": "T1567",
            "name": "Exfiltration Over Web Service",
            "description": (
                "The attacker exfiltrates blob data from the storage "
                "account to an external location via web services."
            ),
            "tactic": "Exfiltration",
            "url": "https://attack.mitre.org/techniques/T1567/",
        },
        {
            "id": "T1078.004",
            "name": "Valid Accounts: Cloud Accounts",
            "description": (
                "The attacker leverages compromised storage account "
                "access keys to authenticate and access resources."
            ),
            "tactic": "Defense Evasion",
            "url": "https://attack.mitre.org/techniques/T1078/004/",
        },
    ],

    # ── Terraform Generation Hints ────────────────────────────────
    terraform_hints={
        "resource_types": [
            "azurerm_resource_group",
            "azurerm_storage_account",
            "azurerm_storage_container",
            "azurerm_storage_blob",
            "azurerm_role_assignment",
        ],
        "misconfigurations": [
            "Storage account with public blob access enabled",
            "No lifecycle policy for access keys rotation",
            "Sensitive data stored without encryption scope",
        ],
        "region": "eastus",
    },

    # ── Simulation Steps ──────────────────────────────────────────
    simulation_steps=[
        SimulationStep(
            order=1,
            name="authenticate_with_storage_keys",
            description=(
                "Authenticate using the storage account access keys."
            ),
            azure_sdk_action="storage.authenticate",
            target_resource_type="Microsoft.Storage/storageAccounts",
        ),
        SimulationStep(
            order=2,
            name="enumerate_containers",
            description=(
                "List all blob containers in the storage account."
            ),
            azure_sdk_action="storage.containers.list",
            target_resource_type="Microsoft.Storage/storageAccounts/blobServices/containers",
        ),
        SimulationStep(
            order=3,
            name="list_blobs",
            description=(
                "Enumerate blobs in the target container to find "
                "sensitive data."
            ),
            azure_sdk_action="storage.blobs.list",
            target_resource_type="Microsoft.Storage/storageAccounts/blobServices/containers/blobs",
        ),
        SimulationStep(
            order=4,
            name="download_blobs",
            description=(
                "Download blob data (simulating exfiltration)."
            ),
            azure_sdk_action="storage.blobs.download",
            target_resource_type="Microsoft.Storage/storageAccounts/blobServices/containers/blobs",
        ),
        SimulationStep(
            order=5,
            name="generate_sas_token",
            description=(
                "Generate an account-level SAS token for persistent access."
            ),
            azure_sdk_action="storage.account.generateSas",
            target_resource_type="Microsoft.Storage/storageAccounts",
        ),
    ],

    # ── Detection Expectations ────────────────────────────────────
    detection_expectations={
        "expected_activity_log_operations": [
            "Microsoft.Storage/storageAccounts/listkeys/action",
            "Microsoft.Storage/storageAccounts/listAccountSas/action",
        ],
        "expected_alert_types": [
            "Suspicious storage account key access",
            "Anomalous data download from storage",
        ],
        "cortex_xdr_expected_alerts": [
            "Cloud Storage Data Exfiltration",
            "Suspicious Storage Key Access",
        ],
        "detection_window_minutes": 15,
    },
)
