"""
System prompt for the ``generate_scenario`` LangGraph node.

Instructs the LLM to convert a free-text user prompt into a fully
structured Scenario definition — including MITRE techniques,
Terraform hints, simulation steps, and detection expectations.
"""

# Supported SDK actions that execute_simulator can dispatch.
# Organized by cloud provider.
SUPPORTED_SDK_ACTIONS: dict[str, list[str]] = {
    "azure": [
        "identity.authenticate",
        "monitor.diagnostic_settings.delete",
        "monitor.diagnostic_settings.list",
        "authorization.role_assignments.list",
        "authorization.role_assignments.create",
        "authorization.role_assignments.delete",
        "authorization.role_definitions.list",
        "storage.blob_containers.list",
        "storage.blobs.download",
        "storage.blobs.upload",
        "storage.blobs.delete",
        "compute.virtual_machines.list",
        "compute.virtual_machines.run_command",
        "network.security_groups.list",
        "network.security_groups.update",
        "keyvault.secrets.list",
        "keyvault.secrets.get",
    ],
    "aws": [
        "sts.get_caller_identity",
        "iam.list_users",
        "iam.list_roles",
        "iam.list_policies",
        "iam.create_policy",
        "iam.attach_user_policy",
        "iam.attach_role_policy",
        "iam.create_access_key",
        "iam.put_user_policy",
        "s3.list_buckets",
        "s3.get_bucket_acl",
        "s3.get_bucket_policy",
        "s3.put_bucket_policy",
        "s3.get_object",
        "s3.put_object",
        "s3.delete_object",
        "ec2.describe_instances",
        "ec2.run_instances",
        "cloudtrail.describe_trails",
        "cloudtrail.stop_logging",
        "cloudtrail.delete_trail",
    ],
}


def _format_sdk_actions() -> str:
    """Format SDK actions for inclusion in the prompt."""
    lines = []
    for provider, actions in SUPPORTED_SDK_ACTIONS.items():
        lines.append(f"  {provider}:")
        for action in actions:
            lines.append(f"    - {action}")
    return "\n".join(lines)


GENERATE_SCENARIO_SYSTEM_PROMPT = f"""\
You are a cloud security expert. The user will describe an attack scenario \
in plain English. Your job is to convert it into a fully structured scenario \
definition that can drive an automated attack simulation.

You MUST respond with valid JSON (no other text) in this exact format:
{{{{
  "id": "short_snake_case_id",
  "name": "Human Readable Scenario Name",
  "description": "2-3 sentence description of the attack",
  "goal_template": "Natural language attack goal for the LLM planner",
  "cloud_provider": "azure" or "aws",
  "expected_mitre_techniques": [
    {{{{
      "id": "T1234.001",
      "name": "Technique Name",
      "description": "How this technique applies",
      "tactic": "Tactic Name",
      "url": "https://attack.mitre.org/techniques/T1234/001/"
    }}}}
  ],
  "terraform_hints": {{{{
    "resource_types": ["azurerm_resource_group", "..."],
    "misconfigurations": ["Description of the deliberate vulnerability"],
    "region": "eastus"
  }}}},
  "simulation_steps": [
    {{{{
      "order": 1,
      "name": "step_name_snake_case",
      "description": "What this step does",
      "sdk_action": "service.action_name",
      "target_resource_type": "Microsoft.Resource/Type or AWS::Service::Resource"
    }}}}
  ],
  "detection_expectations": {{{{
    "expected_activity_log_operations": ["Microsoft.xxx/yyy/write"],
    "expected_alert_types": ["Description of expected alert"],
    "cortex_xdr_expected_alerts": ["Cortex XDR alert name"],
    "detection_window_minutes": 10
  }}}}
}}}}

CRITICAL RULES:
1. The "cloud_provider" MUST be either "azure" or "aws".
2. The "sdk_action" in simulation_steps MUST be one of these supported actions:
{_format_sdk_actions()}
3. For Azure scenarios, use "azurerm_" prefixed resource types in terraform_hints.
4. For AWS scenarios, use "aws_" prefixed resource types in terraform_hints.
5. Include 2-5 MITRE ATT&CK techniques with correct IDs.
6. Include 3-6 simulation steps in logical order.
7. Be precise with MITRE ATT&CK IDs — use the Cloud Matrix.
"""
