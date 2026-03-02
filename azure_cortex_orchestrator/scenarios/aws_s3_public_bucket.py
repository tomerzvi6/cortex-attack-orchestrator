"""
Scenario: AWS S3 Public Bucket Data Exposure.

An S3 bucket with public access enabled containing sensitive data.
The attacker discovers the bucket through enumeration and downloads
sensitive objects.

MITRE ATT&CK Techniques:
- T1530 — Data from Cloud Storage
- T1580 — Cloud Infrastructure Discovery
"""

from __future__ import annotations

from azure_cortex_orchestrator.scenarios.registry import Scenario, SimulationStep

SCENARIO = Scenario(
    id="aws_s3_public_bucket",
    name="AWS S3 Public Bucket Data Exposure",
    description=(
        "An S3 bucket with public access enabled containing sensitive data. "
        "The attacker discovers the bucket through enumeration and downloads "
        "sensitive objects, exploiting misconfigured bucket policies."
    ),
    goal_template=(
        "Discover a publicly accessible AWS S3 bucket, enumerate its objects, "
        "download sensitive data, and verify whether CloudTrail alerts are "
        "triggered for the unauthorized access."
    ),
    cloud_provider="aws",

    # ── MITRE ATT&CK Mapping ─────────────────────────────────────
    expected_mitre_techniques=[
        {
            "id": "T1530",
            "name": "Data from Cloud Storage",
            "description": (
                "The attacker downloads sensitive objects from a publicly "
                "accessible S3 bucket, exfiltrating data that was exposed "
                "due to misconfigured access controls."
            ),
            "tactic": "Collection",
            "url": "https://attack.mitre.org/techniques/T1530/",
        },
        {
            "id": "T1580",
            "name": "Cloud Infrastructure Discovery",
            "description": (
                "The attacker enumerates S3 buckets and their contents to "
                "identify targets with sensitive data or misconfigured "
                "permissions."
            ),
            "tactic": "Discovery",
            "url": "https://attack.mitre.org/techniques/T1580/",
        },
    ],

    # ── Terraform Generation Hints ────────────────────────────────
    terraform_hints={
        "resource_types": [
            "aws_s3_bucket",
            "aws_s3_bucket_public_access_block",
            "aws_s3_object",
            "aws_iam_role",
        ],
        "misconfigurations": [
            "S3 bucket with public-read ACL",
            "Public access block disabled (BlockPublicAcls=false, etc.)",
            "Sensitive objects uploaded without encryption",
        ],
        "region": "us-east-1",
    },

    # ── Simulation Steps ──────────────────────────────────────────
    simulation_steps=[
        SimulationStep(
            order=1,
            name="discover_public_buckets",
            description=(
                "Enumerate S3 buckets in the account and identify those "
                "with public access enabled."
            ),
            sdk_action="s3.list_buckets",
            target_resource_type="AWS::S3::Bucket",
        ),
        SimulationStep(
            order=2,
            name="enumerate_objects",
            description=(
                "List objects inside the publicly accessible bucket to "
                "identify sensitive data files."
            ),
            sdk_action="s3.list_objects_v2",
            target_resource_type="AWS::S3::Bucket",
        ),
        SimulationStep(
            order=3,
            name="download_sensitive_data",
            description=(
                "Download sensitive objects from the public bucket, "
                "simulating data exfiltration."
            ),
            sdk_action="s3.get_object",
            target_resource_type="AWS::S3::Object",
        ),
        SimulationStep(
            order=4,
            name="verify_no_cloudtrail_alert",
            description=(
                "Check whether any CloudTrail-based alerts were triggered "
                "for the unauthorized S3 access."
            ),
            sdk_action="cloudtrail.lookup_events",
            target_resource_type="AWS::CloudTrail::Trail",
        ),
    ],

    # ── Detection Expectations ────────────────────────────────────
    detection_expectations={
        "expected_cloudtrail_operations": [
            "s3:GetObject",
            "s3:ListBucket",
        ],
        "expected_alert_types": [
            "Public S3 bucket access detected",
            "Sensitive data download from S3",
        ],
        "cortex_xdr_expected_alerts": [
            "Cloud Storage Exfiltration",
            "Suspicious S3 Access Pattern",
        ],
        "detection_window_minutes": 15,
    },
)
