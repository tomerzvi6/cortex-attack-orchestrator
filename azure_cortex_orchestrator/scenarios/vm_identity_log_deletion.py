"""
Scenario: VM with Over-Privileged Managed Identity — Delete Activity Logs.

An Azure Virtual Machine with an attached Managed Identity that has
'Contributor' permissions on the entire Subscription. The attacker uses
this identity to delete activity logs (diagnostic settings) to hide
their tracks.

MITRE ATT&CK Techniques:
- T1098   — Account Manipulation
- T1562.008 — Impair Defenses: Disable Cloud Logs
"""

from __future__ import annotations

from azure_cortex_orchestrator.scenarios.registry import Scenario, SimulationStep

SCENARIO = Scenario(
    id="vm_identity_log_deletion",
    name="VM Managed Identity — Delete Activity Logs",
    description=(
        "An Azure VM with a system-assigned Managed Identity that has "
        "'Contributor' role on the entire subscription. The attacker "
        "leverages this identity to delete diagnostic settings that "
        "forward Activity Logs, effectively hiding their tracks."
    ),
    goal_template=(
        "An Azure Virtual Machine with an attached Managed Identity that has "
        "'Contributor' permissions on the entire Subscription. The attacker "
        "uses this identity to delete activity logs to hide their tracks."
    ),

    # ── MITRE ATT&CK Mapping ─────────────────────────────────────
    expected_mitre_techniques=[
        {
            "id": "T1098",
            "name": "Account Manipulation",
            "description": (
                "The VM's Managed Identity is granted Contributor role at "
                "subscription scope — an over-privileged identity that can "
                "be abused for lateral movement."
            ),
            "tactic": "Persistence",
            "url": "https://attack.mitre.org/techniques/T1098/",
        },
        {
            "id": "T1562.008",
            "name": "Impair Defenses: Disable Cloud Logs",
            "description": (
                "The attacker deletes diagnostic settings that forward "
                "Azure Activity Logs, removing the audit trail."
            ),
            "tactic": "Defense Evasion",
            "url": "https://attack.mitre.org/techniques/T1562/008/",
        },
    ],

    # ── Terraform Generation Hints ────────────────────────────────
    terraform_hints={
        "resource_types": [
            "azurerm_resource_group",
            "azurerm_virtual_network",
            "azurerm_subnet",
            "azurerm_network_interface",
            "azurerm_linux_virtual_machine",
            "azurerm_role_assignment",
            "azurerm_log_analytics_workspace",
            "azurerm_monitor_diagnostic_setting",
        ],
        "role_assignments": [
            {
                "role": "Contributor",
                "scope": "subscription",
                "principal": "vm_system_assigned_identity",
            }
        ],
        "misconfigurations": [
            "System-assigned Managed Identity with Contributor on subscription",
            "Diagnostic settings forwarding Activity Logs (to be deleted by attacker)",
        ],
        "region": "eastus",
        "vm_size": "Standard_B1s",
        "os": "Ubuntu 22.04 LTS",
    },

    # ── Simulation Steps ──────────────────────────────────────────
    simulation_steps=[
        SimulationStep(
            order=1,
            name="authenticate_as_managed_identity",
            description=(
                "Authenticate using the service principal credentials "
                "(simulating what the VM's Managed Identity could do)."
            ),
            azure_sdk_action="identity.authenticate",
            target_resource_type="Microsoft.ManagedIdentity",
        ),
        SimulationStep(
            order=2,
            name="enumerate_subscription_resources",
            description=(
                "List all resources in the subscription to demonstrate "
                "the breadth of Contributor access."
            ),
            azure_sdk_action="resource.list",
            target_resource_type="Microsoft.Resources/subscriptions",
        ),
        SimulationStep(
            order=3,
            name="list_diagnostic_settings",
            description=(
                "Enumerate diagnostic settings on the subscription to "
                "find activity log forwarding configurations."
            ),
            azure_sdk_action="monitor.diagnostic_settings.list",
            target_resource_type="Microsoft.Insights/diagnosticSettings",
        ),
        SimulationStep(
            order=4,
            name="delete_diagnostic_settings",
            description=(
                "Delete the diagnostic settings that forward Activity Logs, "
                "effectively disabling the audit trail."
            ),
            azure_sdk_action="monitor.diagnostic_settings.delete",
            target_resource_type="Microsoft.Insights/diagnosticSettings",
        ),
        SimulationStep(
            order=5,
            name="verify_logs_disabled",
            description=(
                "Verify that the diagnostic settings have been successfully "
                "deleted and Activity Log forwarding is stopped."
            ),
            azure_sdk_action="monitor.diagnostic_settings.list",
            target_resource_type="Microsoft.Insights/diagnosticSettings",
        ),
    ],

    # ── Detection Expectations ────────────────────────────────────
    detection_expectations={
        "expected_activity_log_operations": [
            "Microsoft.Insights/diagnosticSettings/delete",
        ],
        "expected_alert_types": [
            "Suspicious deletion of diagnostic settings",
            "Activity log tampering detected",
        ],
        "cortex_xdr_expected_alerts": [
            "Cloud Audit Log Tampering",
            "Suspicious Identity Activity",
        ],
        "detection_window_minutes": 15,
    },
)
