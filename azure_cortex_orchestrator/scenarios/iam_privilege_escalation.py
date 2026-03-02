"""
Scenario: IAM Privilege Escalation via Custom Role.

An Azure environment with a user assigned a custom role that includes
Microsoft.Authorization/roleAssignments/write permission. The attacker
leverages this to escalate privileges by assigning themselves the Owner
role on the subscription.

MITRE ATT&CK Techniques:
- T1098.001 — Account Manipulation: Additional Cloud Credentials
- T1078.004 — Valid Accounts: Cloud Accounts
- T1548     — Abuse Elevation Control Mechanism
"""

from __future__ import annotations

from azure_cortex_orchestrator.scenarios.registry import Scenario, SimulationStep

SCENARIO = Scenario(
    id="iam_privilege_escalation",
    name="IAM Privilege Escalation via Custom Role",
    description=(
        "An Azure environment with a user assigned a custom role that "
        "includes Microsoft.Authorization/roleAssignments/write permission. "
        "The attacker leverages this to escalate privileges by assigning "
        "themselves the Owner role on the subscription."
    ),
    goal_template=(
        "An Azure user with a custom role that has roleAssignment write "
        "permissions. The attacker escalates privileges by assigning "
        "themselves the Owner role on the entire subscription."
    ),

    # ── MITRE ATT&CK Mapping ─────────────────────────────────────
    expected_mitre_techniques=[
        {
            "id": "T1098.001",
            "name": "Account Manipulation: Additional Cloud Credentials",
            "description": (
                "The attacker manipulates account permissions by creating "
                "new role assignments to gain additional cloud credentials."
            ),
            "tactic": "Persistence",
            "url": "https://attack.mitre.org/techniques/T1098/001/",
        },
        {
            "id": "T1078.004",
            "name": "Valid Accounts: Cloud Accounts",
            "description": (
                "The attacker uses a valid cloud account with a custom "
                "role to authenticate and perform privilege escalation."
            ),
            "tactic": "Defense Evasion",
            "url": "https://attack.mitre.org/techniques/T1078/004/",
        },
        {
            "id": "T1548",
            "name": "Abuse Elevation Control Mechanism",
            "description": (
                "The attacker abuses the custom role's write permission "
                "on role assignments to elevate their own privileges."
            ),
            "tactic": "Privilege Escalation",
            "url": "https://attack.mitre.org/techniques/T1548/",
        },
    ],

    # ── Terraform Generation Hints ────────────────────────────────
    terraform_hints={
        "resource_types": [
            "azurerm_resource_group",
            "azurerm_role_definition",
            "azurerm_role_assignment",
            "azurerm_user_assigned_identity",
        ],
        "misconfigurations": [
            "Custom role with Microsoft.Authorization/roleAssignments/write",
            "No PIM (Privileged Identity Management) enforcement",
            "No conditional access policies on privilege escalation",
        ],
        "region": "eastus",
    },

    # ── Simulation Steps ──────────────────────────────────────────
    simulation_steps=[
        SimulationStep(
            order=1,
            name="authenticate_as_custom_role",
            description=(
                "Authenticate using the service principal with the "
                "custom role."
            ),
            azure_sdk_action="identity.authenticate",
            target_resource_type="Microsoft.ManagedIdentity",
        ),
        SimulationStep(
            order=2,
            name="enumerate_permissions",
            description=(
                "List current role assignments and permissions to "
                "discover escalation path."
            ),
            azure_sdk_action="authorization.role_assignments.list",
            target_resource_type="Microsoft.Authorization/roleAssignments",
        ),
        SimulationStep(
            order=3,
            name="list_role_definitions",
            description=(
                "Enumerate available role definitions including Owner."
            ),
            azure_sdk_action="authorization.role_definitions.list",
            target_resource_type="Microsoft.Authorization/roleDefinitions",
        ),
        SimulationStep(
            order=4,
            name="assign_owner_role",
            description=(
                "Create a new role assignment granting Owner on the "
                "subscription."
            ),
            azure_sdk_action="authorization.role_assignments.create",
            target_resource_type="Microsoft.Authorization/roleAssignments",
        ),
        SimulationStep(
            order=5,
            name="verify_escalation",
            description=(
                "Verify the Owner role is now assigned and enumerate "
                "newly accessible resources."
            ),
            azure_sdk_action="authorization.role_assignments.list",
            target_resource_type="Microsoft.Authorization/roleAssignments",
        ),
    ],

    # ── Detection Expectations ────────────────────────────────────
    detection_expectations={
        "expected_activity_log_operations": [
            "Microsoft.Authorization/roleAssignments/write",
        ],
        "expected_alert_types": [
            "Suspicious role assignment at subscription scope",
            "Privilege escalation detected",
        ],
        "cortex_xdr_expected_alerts": [
            "Cloud IAM Privilege Escalation",
            "Suspicious Role Assignment",
        ],
        "detection_window_minutes": 10,
    },
)
