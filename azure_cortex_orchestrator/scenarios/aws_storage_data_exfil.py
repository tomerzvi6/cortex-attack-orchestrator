"""
Scenario: AWS S3 Data Exfiltration via Access Keys.

An AWS S3 bucket containing sensitive data (PII) with overly permissive
access keys. The attacker discovers the storage bucket, uses the access
keys to generate pre-signed URLs, and exfiltrates object data to an
external location.

This is the AWS equivalent of the Azure "Storage Account Data Exfiltration
via SAS Token" scenario.

MITRE ATT&CK Techniques:
- T1530     — Data from Cloud Storage
- T1567     — Exfiltration Over Web Service
- T1078.004 — Valid Accounts: Cloud Accounts
"""

from __future__ import annotations

from azure_cortex_orchestrator.scenarios.registry import Scenario, SimulationStep

SCENARIO = Scenario(
    id="aws_storage_data_exfil",
    name="AWS S3 Data Exfiltration via Access Keys",
    description=(
        "An AWS S3 bucket containing sensitive data (PII) with overly "
        "permissive IAM access keys. The attacker discovers the bucket, "
        "uses compromised access keys to generate pre-signed URLs, and "
        "exfiltrates object data to an external location."
    ),
    goal_template=(
        "An AWS S3 bucket with sensitive data and overly permissive "
        "IAM access keys. The attacker uses the keys to list, download, "
        "and exfiltrate data from S3 objects via pre-signed URLs."
    ),
    cloud_provider="aws",

    # ── MITRE ATT&CK Mapping ─────────────────────────────────────
    expected_mitre_techniques=[
        {
            "id": "T1530",
            "name": "Data from Cloud Storage",
            "description": (
                "The attacker accesses data stored in S3 buckets "
                "to collect sensitive information."
            ),
            "tactic": "Collection",
            "url": "https://attack.mitre.org/techniques/T1530/",
        },
        {
            "id": "T1567",
            "name": "Exfiltration Over Web Service",
            "description": (
                "The attacker exfiltrates S3 object data to an external "
                "location using pre-signed URLs or direct downloads."
            ),
            "tactic": "Exfiltration",
            "url": "https://attack.mitre.org/techniques/T1567/",
        },
        {
            "id": "T1078.004",
            "name": "Valid Accounts: Cloud Accounts",
            "description": (
                "The attacker leverages compromised IAM access keys "
                "to authenticate and access S3 resources."
            ),
            "tactic": "Defense Evasion",
            "url": "https://attack.mitre.org/techniques/T1078/004/",
        },
    ],

    # ── Terraform Generation Hints ────────────────────────────────
    terraform_hints={
        "resource_types": [
            "aws_s3_bucket",
            "aws_s3_object",
            "aws_iam_user",
            "aws_iam_access_key",
            "aws_iam_user_policy",
        ],
        "misconfigurations": [
            "IAM user with inline policy granting full S3 access",
            "No key rotation policy enforced",
            "Sensitive data stored without server-side encryption",
        ],
        "region": "us-east-1",
    },

    # ── Simulation Steps ──────────────────────────────────────────
    # Mirrors the Azure storage_data_exfil scenario step-for-step
    simulation_steps=[
        SimulationStep(
            order=1,
            name="authenticate_with_access_keys",
            description=(
                "Authenticate using the compromised IAM access keys."
            ),
            sdk_action="sts.get_caller_identity",
            target_resource_type="AWS::IAM::User",
        ),
        SimulationStep(
            order=2,
            name="enumerate_buckets",
            description=(
                "List all S3 buckets accessible with the compromised keys."
            ),
            sdk_action="s3.list_buckets",
            target_resource_type="AWS::S3::Bucket",
        ),
        SimulationStep(
            order=3,
            name="list_objects",
            description=(
                "Enumerate objects in the target bucket to find "
                "sensitive data."
            ),
            sdk_action="s3.list_objects_v2",
            target_resource_type="AWS::S3::Bucket",
        ),
        SimulationStep(
            order=4,
            name="download_objects",
            description=(
                "Download S3 objects (simulating exfiltration)."
            ),
            sdk_action="s3.get_object",
            target_resource_type="AWS::S3::Object",
        ),
        SimulationStep(
            order=5,
            name="generate_presigned_url",
            description=(
                "Generate a pre-signed URL for persistent access to "
                "sensitive objects."
            ),
            sdk_action="s3.generate_presigned_url",
            target_resource_type="AWS::S3::Object",
        ),
    ],

    # ── Detection Expectations ────────────────────────────────────
    detection_expectations={
        "expected_cloudtrail_operations": [
            "s3:ListBucket",
            "s3:GetObject",
            "iam:ListAccessKeys",
        ],
        "expected_alert_types": [
            "Suspicious S3 data access via compromised keys",
            "Anomalous data download from S3",
        ],
        "cortex_xdr_expected_alerts": [
            "Cloud Storage Data Exfiltration",
            "Suspicious S3 Access Pattern",
        ],
        "detection_window_minutes": 15,
    },
)
