"""
AWS cloud provider implementation.

Implements the :class:`CloudProvider` interface using boto3 for
executing simulation actions against AWS.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from azure_cortex_orchestrator.cloud_providers.base import CloudProvider
from azure_cortex_orchestrator.utils.observability import get_logger

logger = get_logger("cloud_providers.aws")


class AWSCloudProvider(CloudProvider):
    """AWS implementation of the :class:`CloudProvider` interface."""

    def __init__(self) -> None:
        self._session: Any = None
        self._settings: Any = None

    # ── Identity ──────────────────────────────────────────────────

    @property
    def provider_name(self) -> str:  # noqa: D401
        return "aws"

    # ── Authentication ────────────────────────────────────────────

    def authenticate(self, settings: Any) -> Any:
        """
        Authenticate to AWS using boto3.

        Credentials are resolved from settings attributes or environment
        variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, etc.).
        """
        import boto3

        access_key = getattr(settings, "aws_access_key_id", "") or os.environ.get("AWS_ACCESS_KEY_ID", "")
        secret_key = getattr(settings, "aws_secret_access_key", "") or os.environ.get("AWS_SECRET_ACCESS_KEY", "")
        region = getattr(settings, "aws_default_region", "") or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

        if access_key and secret_key:
            self._session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region,
            )
        else:
            # Fall back to default credential chain (env, config, IAM role)
            self._session = boto3.Session(region_name=region)

        self._settings = settings

        # Verify credentials
        sts = self._session.client("sts")
        identity = sts.get_caller_identity()
        logger.info(
            "Authenticated to AWS: account=%s, arn=%s",
            identity["Account"],
            identity["Arn"],
        )
        return self._session

    # ── Action execution ──────────────────────────────────────────

    def execute_action(
        self,
        action: str,
        target_resource_type: str,
        parameters: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Dispatch an AWS action dynamically based on the action string.

        Supported action patterns:
        - sts.get_caller_identity
        - s3.list_buckets / s3.list_objects_v2 / s3.get_object / s3.generate_presigned_url
        - iam.list_attached_user_policies / iam.list_policies / iam.attach_user_policy
        - cloudtrail.describe_trails / cloudtrail.stop_logging / cloudtrail.lookup_events
        - resourcegroupstaggingapi.get_resources
        """
        if not self._session:
            return self._result(action, target_resource_type, "failed",
                                error="Not authenticated — call authenticate() first")

        try:
            if action == "sts.get_caller_identity":
                return self._action_sts_identity()
            elif action == "s3.list_buckets":
                return self._action_s3_list_buckets()
            elif action == "s3.list_objects_v2":
                return self._action_s3_list_objects(parameters)
            elif action == "s3.get_object":
                return self._action_s3_get_object(parameters)
            elif action == "s3.generate_presigned_url":
                return self._action_s3_presigned_url(parameters)
            elif action == "iam.list_attached_user_policies":
                return self._action_iam_list_attached_policies(parameters)
            elif action == "iam.list_policies":
                return self._action_iam_list_policies()
            elif action == "iam.attach_user_policy":
                return self._action_iam_attach_policy(parameters)
            elif action == "cloudtrail.describe_trails":
                return self._action_cloudtrail_describe()
            elif action == "cloudtrail.stop_logging":
                return self._action_cloudtrail_stop(parameters)
            elif action == "cloudtrail.lookup_events":
                return self._action_cloudtrail_lookup(parameters)
            elif action == "resourcegroupstaggingapi.get_resources":
                return self._action_tag_get_resources()
            else:
                logger.warning("Unrecognized AWS action: %s — executing as no-op", action)
                return self._result(action, target_resource_type, "success",
                                    details=f"Action '{action}' executed (no-op fallback)")
        except Exception as exc:
            logger.error("AWS action '%s' failed: %s", action, exc)
            return self._result(action, target_resource_type, "failed", error=str(exc))

    # ── Terraform helpers ─────────────────────────────────────────

    def get_terraform_provider_block(self) -> str:
        return (
            'provider "aws" {\n'
            '  region = var.aws_region\n'
            '}\n'
        )

    def get_terraform_env_vars(self, settings: Any) -> dict[str, str]:
        return {
            "AWS_ACCESS_KEY_ID": getattr(
                settings, "aws_access_key_id", ""
            ) or os.environ.get("AWS_ACCESS_KEY_ID", ""),
            "AWS_SECRET_ACCESS_KEY": getattr(
                settings, "aws_secret_access_key", ""
            ) or os.environ.get("AWS_SECRET_ACCESS_KEY", ""),
            "AWS_DEFAULT_REGION": getattr(
                settings, "aws_default_region", ""
            ) or os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
        }

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

    def _action_sts_identity(self) -> dict[str, Any]:
        sts = self._session.client("sts")
        identity = sts.get_caller_identity()
        return self._result(
            "sts.get_caller_identity", "AWS::IAM::User", "success",
            f"Account={identity['Account']}, Arn={identity['Arn']}",
        )

    def _action_s3_list_buckets(self) -> dict[str, Any]:
        s3 = self._session.client("s3")
        resp = s3.list_buckets()
        names = [b["Name"] for b in resp.get("Buckets", [])]
        return self._result(
            "s3.list_buckets", "AWS::S3::Bucket", "success",
            f"Found {len(names)} buckets: {names[:10]}",
        )

    def _action_s3_list_objects(self, params: dict) -> dict[str, Any]:
        s3 = self._session.client("s3")
        bucket = params.get("bucket_name", "")
        resp = s3.list_objects_v2(Bucket=bucket, MaxKeys=100)
        keys = [obj["Key"] for obj in resp.get("Contents", [])]
        return self._result(
            "s3.list_objects_v2", f"AWS::S3::Bucket/{bucket}", "success",
            f"Found {len(keys)} objects: {keys[:10]}",
        )

    def _action_s3_get_object(self, params: dict) -> dict[str, Any]:
        s3 = self._session.client("s3")
        bucket = params.get("bucket_name", "")
        key = params.get("object_key", "")
        resp = s3.get_object(Bucket=bucket, Key=key)
        size = resp["ContentLength"]
        logger.warning("ATTACK ACTION: Downloaded s3://%s/%s (%d bytes)", bucket, key, size)
        return self._result(
            "s3.get_object", f"s3://{bucket}/{key}", "success",
            f"Downloaded {size} bytes from s3://{bucket}/{key}",
        )

    def _action_s3_presigned_url(self, params: dict) -> dict[str, Any]:
        s3 = self._session.client("s3")
        bucket = params.get("bucket_name", "")
        key = params.get("object_key", "")
        url = s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket, "Key": key},
            ExpiresIn=3600,
        )
        return self._result(
            "s3.generate_presigned_url", f"s3://{bucket}/{key}", "success",
            f"Generated pre-signed URL (expires in 3600s): {url[:80]}...",
        )

    def _action_iam_list_attached_policies(self, params: dict) -> dict[str, Any]:
        iam = self._session.client("iam")
        user = params.get("user_name", "")
        if user:
            resp = iam.list_attached_user_policies(UserName=user)
        else:
            # List for the current caller
            sts = self._session.client("sts")
            identity = sts.get_caller_identity()
            arn = identity["Arn"]
            # Extract username from ARN if it's a user
            parts = arn.split("/")
            user = parts[-1] if len(parts) > 1 else ""
            resp = iam.list_attached_user_policies(UserName=user)
        policies = [p["PolicyName"] for p in resp.get("AttachedPolicies", [])]
        return self._result(
            "iam.list_attached_user_policies", f"AWS::IAM::User/{user}", "success",
            f"Attached policies: {policies}",
        )

    def _action_iam_list_policies(self) -> dict[str, Any]:
        iam = self._session.client("iam")
        resp = iam.list_policies(Scope="AWS", MaxItems=20)
        names = [p["PolicyName"] for p in resp.get("Policies", [])]
        return self._result(
            "iam.list_policies", "AWS::IAM::Policy", "success",
            f"Found {len(names)} AWS managed policies (sample): {names[:10]}",
        )

    def _action_iam_attach_policy(self, params: dict) -> dict[str, Any]:
        iam = self._session.client("iam")
        user = params.get("user_name", "")
        policy_arn = params.get("policy_arn", "arn:aws:iam::aws:policy/AdministratorAccess")
        logger.warning(
            "ATTACK ACTION: Attaching policy %s to user %s", policy_arn, user
        )
        iam.attach_user_policy(UserName=user, PolicyArn=policy_arn)
        return self._result(
            "iam.attach_user_policy", f"AWS::IAM::User/{user}", "success",
            f"Attached {policy_arn} to {user}",
        )

    def _action_cloudtrail_describe(self) -> dict[str, Any]:
        ct = self._session.client("cloudtrail")
        resp = ct.describe_trails()
        trails = [t["Name"] for t in resp.get("trailList", [])]
        return self._result(
            "cloudtrail.describe_trails", "AWS::CloudTrail::Trail", "success",
            f"Found {len(trails)} trails: {trails}",
        )

    def _action_cloudtrail_stop(self, params: dict) -> dict[str, Any]:
        ct = self._session.client("cloudtrail")
        # Find trails and stop them
        resp = ct.describe_trails()
        stopped = []
        for trail in resp.get("trailList", []):
            name = trail["Name"]
            if "cortex-sim" in name.lower() or not params.get("trail_name"):
                ct.stop_logging(Name=trail["TrailARN"])
                logger.warning("ATTACK ACTION: Stopped CloudTrail logging on '%s'", name)
                stopped.append(name)
        return self._result(
            "cloudtrail.stop_logging", "AWS::CloudTrail::Trail",
            "success" if stopped else "skipped",
            f"Stopped logging on {len(stopped)} trail(s): {stopped}",
        )

    def _action_cloudtrail_lookup(self, params: dict) -> dict[str, Any]:
        ct = self._session.client("cloudtrail")
        resp = ct.lookup_events(MaxResults=20)
        events = resp.get("Events", [])
        summaries = [e.get("EventName", "") for e in events[:10]]
        return self._result(
            "cloudtrail.lookup_events", "AWS::CloudTrail::Trail", "success",
            f"Found {len(events)} recent events: {summaries}",
        )

    def _action_tag_get_resources(self) -> dict[str, Any]:
        tagging = self._session.client("resourcegroupstaggingapi")
        resp = tagging.get_resources(ResourcesPerPage=50)
        resources = resp.get("ResourceTagMappingList", [])
        arns = [r["ResourceARN"] for r in resources[:10]]
        return self._result(
            "resourcegroupstaggingapi.get_resources",
            "AWS::ResourceGroups::Group", "success",
            f"Found {len(resources)} tagged resources. Sample ARNs: {arns}",
        )
