"""
Scenario: AWS IAM Privilege Escalation via Policy Attachment.

An AWS environment with an IAM user that has the iam:AttachUserPolicy
permission. The attacker leverages this to escalate privileges by
attaching the AdministratorAccess managed policy to themselves.

This is the AWS equivalent of the Azure "IAM Privilege Escalation via
Custom Role" scenario.

MITRE ATT&CK Techniques:
- T1098.001 — Account Manipulation: Additional Cloud Credentials
- T1078.004 — Valid Accounts: Cloud Accounts
- T1548     — Abuse Elevation Control Mechanism
"""

from __future__ import annotations

from azure_cortex_orchestrator.scenarios.registry import Scenario, SimulationStep

SCENARIO = Scenario(
    id="aws_iam_privilege_escalation",
    name="AWS IAM Privilege Escalation via Policy Attachment",
    description=(
        "An AWS environment with an IAM user that has the "
        "iam:AttachUserPolicy permission. The attacker leverages this "
        "to escalate privileges by attaching the AdministratorAccess "
        "managed policy to their own user."
    ),
    goal_template=(
        "An AWS IAM user with iam:AttachUserPolicy permission. The "
        "attacker escalates privileges by attaching Administrator"
        "Access to themselves, gaining full account control."
    ),
    cloud_provider="aws",

    # ── MITRE ATT&CK Mapping ─────────────────────────────────────
    expected_mitre_techniques=[
        {
            "id": "T1098.001",
            "name": "Account Manipulation: Additional Cloud Credentials",
            "description": (
                "The attacker manipulates IAM policies by attaching "
                "additional managed policies to gain elevated permissions."
            ),
            "tactic": "Persistence",
            "url": "https://attack.mitre.org/techniques/T1098/001/",
        },
        {
            "id": "T1078.004",
            "name": "Valid Accounts: Cloud Accounts",
            "description": (
                "The attacker uses a valid IAM user with overly permissive "
                "IAM management permissions to authenticate and escalate."
            ),
            "tactic": "Defense Evasion",
            "url": "https://attack.mitre.org/techniques/T1078/004/",
        },
        {
            "id": "T1548",
            "name": "Abuse Elevation Control Mechanism",
            "description": (
                "The attacker abuses the iam:AttachUserPolicy permission "
                "to attach AdministratorAccess and elevate their own privileges."
            ),
            "tactic": "Privilege Escalation",
            "url": "https://attack.mitre.org/techniques/T1548/",
        },
    ],

    # ── Terraform Generation Hints ────────────────────────────────
    terraform_hints={
        "resource_types": [
            "aws_iam_user",
            "aws_iam_access_key",
            "aws_iam_user_policy",
            "aws_iam_policy",
        ],
        "misconfigurations": [
            "IAM user with iam:AttachUserPolicy permission",
            "No SCP (Service Control Policy) preventing self-escalation",
            "No CloudTrail alert for IAM policy changes",
        ],
        "region": "us-east-1",
    },

    # ── Simulation Steps ──────────────────────────────────────────
    # Mirrors the Azure iam_privilege_escalation scenario step-for-step
    simulation_steps=[
        SimulationStep(
            order=1,
            name="authenticate_as_iam_user",
            description=(
                "Authenticate using the IAM user's access keys."
            ),
            sdk_action="sts.get_caller_identity",
            target_resource_type="AWS::IAM::User",
        ),
        SimulationStep(
            order=2,
            name="enumerate_permissions",
            description=(
                "List attached and inline policies to discover "
                "escalation path."
            ),
            sdk_action="iam.list_attached_user_policies",
            target_resource_type="AWS::IAM::Policy",
        ),
        SimulationStep(
            order=3,
            name="list_managed_policies",
            description=(
                "Enumerate available AWS managed policies including "
                "AdministratorAccess."
            ),
            sdk_action="iam.list_policies",
            target_resource_type="AWS::IAM::Policy",
        ),
        SimulationStep(
            order=4,
            name="attach_admin_policy",
            description=(
                "Attach the AdministratorAccess managed policy to "
                "the current IAM user."
            ),
            sdk_action="iam.attach_user_policy",
            target_resource_type="AWS::IAM::Policy",
        ),
        SimulationStep(
            order=5,
            name="verify_escalation",
            description=(
                "Verify that AdministratorAccess is now attached and "
                "enumerate newly accessible resources."
            ),
            sdk_action="iam.list_attached_user_policies",
            target_resource_type="AWS::IAM::Policy",
        ),
    ],

    # ── Detection Expectations ────────────────────────────────────
    detection_expectations={
        "expected_cloudtrail_operations": [
            "iam:AttachUserPolicy",
        ],
        "expected_alert_types": [
            "Suspicious IAM policy attachment",
            "Privilege escalation detected",
        ],
        "cortex_xdr_expected_alerts": [
            "Cloud IAM Privilege Escalation",
            "Suspicious IAM Policy Change",
        ],
        "detection_window_minutes": 10,
    },
)
