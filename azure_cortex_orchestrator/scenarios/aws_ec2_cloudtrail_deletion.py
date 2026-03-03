"""
Scenario: EC2 Instance Role — Delete CloudTrail Logs.

An AWS EC2 instance with an attached IAM instance profile that has
overly broad permissions (AdministratorAccess or equivalent). The
attacker uses this role to disable CloudTrail logging and delete
the trail, effectively hiding their tracks.

This is the AWS equivalent of the Azure "VM Managed Identity — Delete
Activity Logs" scenario.

MITRE ATT&CK Techniques:
- T1098   — Account Manipulation
- T1562.008 — Impair Defenses: Disable Cloud Logs
"""

from __future__ import annotations

from azure_cortex_orchestrator.scenarios.registry import Scenario, SimulationStep

SCENARIO = Scenario(
    id="aws_ec2_cloudtrail_deletion",
    name="EC2 Instance Role — Delete CloudTrail Logs",
    description=(
        "An AWS EC2 instance with an attached IAM instance profile that "
        "has overly broad permissions. The attacker leverages this role "
        "to stop CloudTrail logging and delete the trail, effectively "
        "hiding their tracks."
    ),
    goal_template=(
        "An AWS EC2 instance with an attached IAM role that has "
        "overly broad permissions. The attacker uses this role to "
        "disable and delete CloudTrail logging to hide their tracks."
    ),
    cloud_provider="aws",

    # ── MITRE ATT&CK Mapping ─────────────────────────────────────
    expected_mitre_techniques=[
        {
            "id": "T1098",
            "name": "Account Manipulation",
            "description": (
                "The EC2 instance's IAM role is granted overly broad "
                "permissions that can be abused for lateral movement "
                "and defense evasion."
            ),
            "tactic": "Persistence",
            "url": "https://attack.mitre.org/techniques/T1098/",
        },
        {
            "id": "T1562.008",
            "name": "Impair Defenses: Disable Cloud Logs",
            "description": (
                "The attacker stops CloudTrail logging and deletes "
                "the trail to remove the audit record."
            ),
            "tactic": "Defense Evasion",
            "url": "https://attack.mitre.org/techniques/T1562/008/",
        },
    ],

    # ── Terraform Generation Hints ────────────────────────────────
    terraform_hints={
        "resource_types": [
            "aws_vpc",
            "aws_subnet",
            "aws_security_group",
            "aws_instance",
            "aws_iam_role",
            "aws_iam_instance_profile",
            "aws_iam_role_policy_attachment",
            "aws_cloudtrail",
            "aws_s3_bucket",
            "aws_cloudwatch_log_group",
        ],
        "role_assignments": [
            {
                "role": "AdministratorAccess",
                "scope": "account",
                "principal": "ec2_instance_profile_role",
            }
        ],
        "misconfigurations": [
            "EC2 instance profile with AdministratorAccess policy",
            "CloudTrail trail forwarding to S3 (to be deleted by attacker)",
        ],
        "region": "us-east-1",
        "instance_type": "t3.micro",
        "os": "Amazon Linux 2023",
    },

    # ── Simulation Steps ──────────────────────────────────────────
    # Mirrors the Azure vm_identity_log_deletion scenario step-for-step
    simulation_steps=[
        SimulationStep(
            order=1,
            name="authenticate_as_instance_role",
            description=(
                "Authenticate using the IAM credentials "
                "(simulating what the EC2 instance role could do)."
            ),
            sdk_action="sts.get_caller_identity",
            target_resource_type="AWS::IAM::Role",
        ),
        SimulationStep(
            order=2,
            name="enumerate_account_resources",
            description=(
                "List resources across the account to demonstrate "
                "the breadth of the over-privileged role."
            ),
            sdk_action="resourcegroupstaggingapi.get_resources",
            target_resource_type="AWS::ResourceGroups::Group",
        ),
        SimulationStep(
            order=3,
            name="list_cloudtrail_trails",
            description=(
                "Enumerate CloudTrail trails to find active logging "
                "configurations."
            ),
            sdk_action="cloudtrail.describe_trails",
            target_resource_type="AWS::CloudTrail::Trail",
        ),
        SimulationStep(
            order=4,
            name="stop_and_delete_cloudtrail",
            description=(
                "Stop logging on the CloudTrail trail and then delete "
                "it, effectively disabling the audit trail."
            ),
            sdk_action="cloudtrail.stop_logging",
            target_resource_type="AWS::CloudTrail::Trail",
        ),
        SimulationStep(
            order=5,
            name="verify_logging_disabled",
            description=(
                "Verify that CloudTrail logging has been stopped and "
                "the trail has been deleted."
            ),
            sdk_action="cloudtrail.describe_trails",
            target_resource_type="AWS::CloudTrail::Trail",
        ),
    ],

    # ── Detection Expectations ────────────────────────────────────
    detection_expectations={
        "expected_cloudtrail_operations": [
            "cloudtrail:StopLogging",
            "cloudtrail:DeleteTrail",
        ],
        "expected_alert_types": [
            "CloudTrail logging disabled",
            "Audit trail tampering detected",
        ],
        "cortex_xdr_expected_alerts": [
            "Cloud Audit Log Tampering",
            "Suspicious CloudTrail Modification",
        ],
        "detection_window_minutes": 15,
    },
)
