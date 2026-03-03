"""
LangGraph node functions for the Azure-Cortex Orchestrator.

Each node function takes the full ``OrchestratorState`` and returns
a partial dict update to be merged back into the state.
"""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader
from openai import OpenAI

from azure_cortex_orchestrator.config import Settings, load_settings
from azure_cortex_orchestrator.scenarios.registry import ScenarioRegistry
from azure_cortex_orchestrator.state import OrchestratorState
from azure_cortex_orchestrator.utils.observability import get_logger, node_logger
from azure_cortex_orchestrator.utils.reporting import ReportGenerator
from azure_cortex_orchestrator.utils.run_manifest import RunManifest
from azure_cortex_orchestrator.utils.terraform import TerraformError, TerraformRunner

# ── Module-level setup ────────────────────────────────────────────
logger = get_logger("nodes")

# Settings and OpenAI client are initialized lazily
_settings: Settings | None = None
_openai_client: OpenAI | None = None


def _get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = load_settings()
    return _settings


def _get_openai_client() -> OpenAI:
    global _openai_client
    if _openai_client is None:
        settings = _get_settings()
        _openai_client = OpenAI(api_key=settings.openai_api_key)
    return _openai_client


def _call_openai(
    system_prompt: str,
    user_prompt: str,
    model: str | None = None,
    temperature: float = 0.2,
    max_tokens: int = 4096,
    *,
    max_retries: int = 3,
    timeout_seconds: int = 120,
) -> str:
    """
    Call OpenAI chat completions with exponential backoff and timeout.

    Retries on transient errors (rate limits, server errors, timeouts).
    Raises after ``max_retries`` failures.
    """
    client = _get_openai_client()
    settings = _get_settings()

    last_exc: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            response = client.chat.completions.create(
                model=model or settings.openai_model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=temperature,
                max_tokens=max_tokens,
                timeout=timeout_seconds,
            )
            return response.choices[0].message.content or ""

        except Exception as exc:
            last_exc = exc
            # Classify the error
            err_str = str(exc).lower()
            is_transient = any(
                keyword in err_str
                for keyword in [
                    "rate limit", "429", "timeout", "timed out",
                    "server error", "500", "502", "503", "overloaded",
                    "connection", "temporarily",
                ]
            )

            if not is_transient or attempt == max_retries:
                logger.error(
                    "OpenAI call failed (attempt %d/%d, non-retriable): %s",
                    attempt, max_retries, exc,
                )
                raise

            # Exponential backoff: 2s, 4s, 8s, ...
            backoff = 2 ** attempt
            logger.warning(
                "OpenAI call failed (attempt %d/%d), retrying in %ds: %s",
                attempt, max_retries, backoff, exc,
            )
            time.sleep(backoff)

    # Should not reach here, but safeguard
    raise last_exc or RuntimeError("OpenAI call failed after retries")


def _extract_json(text: str) -> dict[str, Any]:
    """Extract JSON from a response that may contain markdown code fences."""
    # Try to find JSON in code blocks first
    json_match = re.search(r"```(?:json)?\s*\n?(.*?)```", text, re.DOTALL)
    if json_match:
        return json.loads(json_match.group(1).strip())
    # Try parsing the whole text
    return json.loads(text.strip())


def _extract_hcl(text: str) -> str:
    """Extract HCL/Terraform code from a response with markdown code fences."""
    hcl_match = re.search(r"```(?:hcl|terraform)?\s*\n?(.*?)```", text, re.DOTALL)
    if hcl_match:
        return hcl_match.group(1).strip()
    return text.strip()


# ══════════════════════════════════════════════════════════════════
#  NODE: plan_attack
# ══════════════════════════════════════════════════════════════════

PLAN_ATTACK_SYSTEM_PROMPT = """\
You are a cloud security expert specializing in Azure attack simulation and \
the MITRE ATT&CK framework (Cloud Matrix). Your task is to take a natural \
language attack goal and produce a structured attack plan.

You MUST respond with valid JSON (no other text) in this exact format:
{
  "goal": "the original goal",
  "scenario_id": "scenario identifier",
  "summary": "brief summary of the attack",
  "mitre_techniques": [
    {
      "id": "T1234",
      "name": "Technique Name",
      "tactic": "Tactic Name",
      "description": "How this technique applies to this scenario",
      "url": "https://attack.mitre.org/techniques/T1234/"
    }
  ],
  "steps": [
    {
      "step_number": 1,
      "description": "What the attacker does",
      "mitre_technique_id": "T1234",
      "mitre_technique_name": "Technique Name",
      "kill_chain_phase": "Phase",
      "details": "Technical details"
    }
  ]
}

Focus on Azure-specific cloud techniques. Be precise with MITRE ATT&CK IDs.
Include techniques for: initial access, privilege escalation, defense evasion, \
and impact as applicable.
"""


def plan_attack(state: OrchestratorState) -> dict[str, Any]:
    """
    Node: Map the attack goal to MITRE ATT&CK techniques and produce
    a structured attack plan.
    """
    with node_logger("plan_attack", state.get("run_id", "")) as log:
        goal = state["goal"]
        scenario_id = state.get("scenario_id", "")

        # Enrich prompt with scenario hints if available
        scenario_context = ""
        try:
            registry = ScenarioRegistry.get_instance()
            scenario = registry.get(scenario_id)
            scenario_context = (
                f"\n\nScenario hints:\n"
                f"- Expected techniques: {scenario.expected_mitre_techniques}\n"
                f"- Resource types involved: {scenario.terraform_hints.get('resource_types', [])}\n"
                f"- Known misconfigurations: {scenario.terraform_hints.get('misconfigurations', [])}\n"
            )
        except KeyError:
            log.debug("No scenario found for '%s', using goal only", scenario_id)

        user_prompt = (
            f"Attack Goal: {goal}\n"
            f"Scenario ID: {scenario_id}"
            f"{scenario_context}"
        )

        log.info("Calling OpenAI to generate attack plan for: %s", goal)
        response = _call_openai(PLAN_ATTACK_SYSTEM_PROMPT, user_prompt)

        try:
            attack_plan = _extract_json(response)
        except (json.JSONDecodeError, ValueError) as exc:
            log.error("Failed to parse attack plan JSON: %s", exc)
            attack_plan = {
                "goal": goal,
                "scenario_id": scenario_id,
                "summary": "Failed to generate structured plan. Raw response attached.",
                "mitre_techniques": [],
                "steps": [],
                "_raw_response": response,
            }

        log.info(
            "Attack plan generated: %d techniques, %d steps",
            len(attack_plan.get("mitre_techniques", [])),
            len(attack_plan.get("steps", [])),
        )

        return {"attack_plan": attack_plan}


# ══════════════════════════════════════════════════════════════════
#  NODE: generate_infrastructure
# ══════════════════════════════════════════════════════════════════

FIX_TERRAFORM_SYSTEM_PROMPT = """\
You are a Terraform expert. The following Terraform code failed with the error \
below. Fix the code and return ONLY the corrected HCL. Do not explain, just \
return the fixed code.
"""

GENERATE_INFRA_SYSTEM_PROMPT = """\
You are an expert Terraform developer specializing in Azure infrastructure. \
Your task is to generate complete, valid Terraform HCL code that deploys a \
*deliberately vulnerable* Azure environment for attack simulation.

Requirements:
1. Use azurerm provider ~> 3.0
2. Include proper provider configuration
3. The infrastructure must contain the specific misconfiguration described
4. Include necessary networking, compute, and identity resources
5. Add diagnostic settings / monitoring that the attacker will target
6. Tag all resources with environment="cortex-simulation"
7. Output key resource identifiers

Respond with ONLY the Terraform HCL code inside a ```hcl code block. \
No explanations outside the code block.

IMPORTANT: The code must be syntactically valid and deployable. Include \
all required fields for each resource.
"""


def generate_infrastructure(state: OrchestratorState) -> dict[str, Any]:
    """
    Node: Generate Terraform code for the vulnerable Azure environment.
    On retries, includes the previous error for self-correction.
    """
    with node_logger("generate_infrastructure", state.get("run_id", "")) as log:
        settings = _get_settings()
        attack_plan = state.get("attack_plan", {})
        deploy_retries = state.get("deploy_retries", 0)
        deploy_error = state.get("deploy_error", "")
        scenario_id = state.get("scenario_id", "")
        run_id = state.get("run_id", "unknown")

        # ── AI-assisted fix on retry ─────────────────────────────
        if deploy_retries > 0 and deploy_error:
            previous_code = state.get("terraform_code", "")
            log.info(
                "AI-assisted fix attempt #%d for Terraform error",
                deploy_retries,
            )
            fix_user_prompt = (
                f"## Failed Terraform Code\n```hcl\n{previous_code}\n```\n\n"
                f"## Error\n```\n{deploy_error}\n```"
            )
            response = _call_openai(
                FIX_TERRAFORM_SYSTEM_PROMPT,
                fix_user_prompt,
                max_tokens=8192,
            )
            terraform_code = _extract_hcl(response)
        else:
            # ── First run: generate from scratch ──────────────────
            # Load the Jinja2 base template as reference
            templates_dir = Path(__file__).resolve().parent / "templates"
            jinja_env = Environment(loader=FileSystemLoader(str(templates_dir)))

            template_context = ""
            try:
                template = jinja_env.get_template("base_infra.tf.j2")
                rendered = template.render(
                    resource_group_name=f"{settings.resource_group_prefix}{run_id[:8]}",
                    subscription_id=settings.azure_subscription_id or "SUBSCRIPTION_ID",
                    run_id=run_id,
                    location="eastus",
                    vm_name=f"sim-vm-{run_id[:8]}",
                )
                template_context = f"\n\nHere's a reference template to guide your output:\n```hcl\n{rendered}\n```"
            except Exception as exc:
                log.warning("Failed to render Jinja2 template: %s", exc)

            # Get scenario hints
            scenario_hints = ""
            try:
                registry = ScenarioRegistry.get_instance()
                scenario = registry.get(scenario_id)
                scenario_hints = (
                    f"\n\nScenario requirements:\n"
                    f"- Resources: {scenario.terraform_hints.get('resource_types', [])}\n"
                    f"- Role assignments: {scenario.terraform_hints.get('role_assignments', [])}\n"
                    f"- Misconfigurations: {scenario.terraform_hints.get('misconfigurations', [])}\n"
                    f"- Region: {scenario.terraform_hints.get('region', 'eastus')}\n"
                )
            except KeyError:
                pass

            user_prompt = (
                f"Attack Plan:\n{json.dumps(attack_plan, indent=2)}\n"
                f"{scenario_hints}"
                f"{template_context}\n\n"
                f"Subscription ID: {settings.azure_subscription_id or 'SUBSCRIPTION_ID'}\n"
                f"Resource Group Prefix: {settings.resource_group_prefix}\n"
                f"Run ID: {run_id}"
            )

            log.info(
                "Calling OpenAI to generate Terraform (first run)"
            )
            response = _call_openai(
                GENERATE_INFRA_SYSTEM_PROMPT,
                user_prompt,
                max_tokens=8192,
            )

            terraform_code = _extract_hcl(response)

        # Set up Terraform working directory
        tf_runner = TerraformRunner(
            run_id=run_id,
            base_tmp_dir=settings.terraform_tmp_dir,
            azure_env={
                "ARM_CLIENT_ID": settings.azure_client_id,
                "ARM_CLIENT_SECRET": settings.azure_client_secret,
                "ARM_TENANT_ID": settings.azure_tenant_id,
                "ARM_SUBSCRIPTION_ID": settings.azure_subscription_id,
            } if not state.get("dry_run") else {},
        )
        tf_runner.write_tf_files(terraform_code)

        log.info(
            "Terraform code generated (%d chars), written to %s",
            len(terraform_code),
            tf_runner.working_dir,
        )

        return {
            "terraform_code": terraform_code,
            "terraform_working_dir": str(tf_runner.working_dir),
            "terraform_workspace": tf_runner.workspace_name,
        }


# ══════════════════════════════════════════════════════════════════
#  NODE: safety_check
# ══════════════════════════════════════════════════════════════════

def safety_check(state: OrchestratorState) -> dict[str, Any]:
    """
    Node: Validate the Terraform plan against safety guardrails.

    Two-layer approach:
    Layer 1 (always): Regex-based static analysis of HCL source.
    Layer 2 (when possible): ``terraform plan -json`` for resolved values.

    Checks:
    1. Resource group / naming prefix.
    2. Subscription ID is in the allowlist (if configured).
    3. No tenant-level or AAD operations.
    4. Resource count doesn't exceed the maximum.
    5. (Plan JSON) Resolved values — catches dynamic refs and variables.
    """
    with node_logger("safety_check", state.get("run_id", "")) as log:
        settings = _get_settings()
        terraform_code = state.get("terraform_code", "")
        deploy_retries = state.get("deploy_retries", 0)
        violations: list[str] = []

        if deploy_retries > 0:
            log.info(
                "Re-running safety check after deploy retry #%d "
                "(AI-regenerated Terraform code)",
                deploy_retries,
            )

        if not terraform_code:
            violations.append("No Terraform code generated")
            return {
                "safety_violations": violations,
                "deploy_status": "unsafe",
            }

        # ── Layer 1: Regex-based HCL source analysis ──────────────

        # Check 1: Resource group prefix
        rg_pattern = re.findall(
            r'resource\s+"azurerm_resource_group".*?name\s*=\s*"([^"]+)"',
            terraform_code,
            re.DOTALL,
        )
        for rg_name in rg_pattern:
            if not rg_name.startswith(settings.resource_group_prefix):
                violations.append(
                    f"Resource group '{rg_name}' does not start with "
                    f"required prefix '{settings.resource_group_prefix}'"
                )

        # Check 2: Subscription allowlist
        if settings.allowed_subscriptions:
            sub_refs = re.findall(
                r'/subscriptions/([a-f0-9-]+)',
                terraform_code,
                re.IGNORECASE,
            )
            for sub_id in sub_refs:
                if sub_id not in settings.allowed_subscriptions:
                    violations.append(
                        f"Subscription '{sub_id}' is not in the allowed list"
                    )

        # Check 3: No AAD / tenant-level operations
        dangerous_resources = [
            "azuread_", "azurerm_management_group",
            "azurerm_tenant", "azurerm_policy_definition",
        ]
        for dangerous in dangerous_resources:
            if dangerous in terraform_code.lower():
                violations.append(
                    f"Potentially dangerous resource type detected: '{dangerous}'"
                )

        # Check 4: Resource count
        resource_count = len(re.findall(
            r'^resource\s+"',
            terraform_code,
            re.MULTILINE,
        ))
        if resource_count > settings.max_terraform_resources:
            violations.append(
                f"Resource count ({resource_count}) exceeds maximum "
                f"({settings.max_terraform_resources})"
            )

        # ── Layer 2: Plan-JSON analysis (resolved values) ─────────
        # Only run if Layer 1 passed and we're not in dry-run mode
        if not violations and not state.get("dry_run", False):
            plan_violations = _safety_check_plan_json(state, settings, log)
            violations.extend(plan_violations)

        if violations:
            log.warning("Safety violations found: %s", violations)
            return {
                "safety_violations": violations,
                "deploy_status": "unsafe",
            }

        log.info("Safety check passed (no violations)")
        return {
            "safety_violations": [],
            "deploy_status": "pending",
        }


def _safety_check_plan_json(
    state: OrchestratorState,
    settings: Settings,
    log: Any,
) -> list[str]:
    """
    Run ``terraform plan -json`` and validate the resolved plan.

    Returns a list of safety violations found in the plan output.
    """
    violations: list[str] = []
    run_id = state.get("run_id", "unknown")
    terraform_code = state.get("terraform_code", "")

    try:
        tf_runner = TerraformRunner(
            run_id=run_id,
            base_tmp_dir=settings.terraform_tmp_dir,
            azure_env={
                "ARM_CLIENT_ID": settings.azure_client_id,
                "ARM_CLIENT_SECRET": settings.azure_client_secret,
                "ARM_TENANT_ID": settings.azure_tenant_id,
                "ARM_SUBSCRIPTION_ID": settings.azure_subscription_id,
            },
        )
        tf_runner.write_tf_files(terraform_code)
        plan_data = tf_runner.plan_json()

        if not plan_data:
            log.warning("Plan JSON was empty — skipping Layer 2 checks")
            return violations

        # Analyze planned resource changes
        resource_changes = plan_data.get("resource_changes", [])
        log.info("Plan JSON: %d resource changes to analyze", len(resource_changes))

        for rc in resource_changes:
            resource_type = rc.get("type", "")
            change = rc.get("change", {})
            after = change.get("after", {}) or {}

            # Check: resolved resource group names
            if resource_type == "azurerm_resource_group":
                name = after.get("name", "")
                if name and not name.startswith(settings.resource_group_prefix):
                    violations.append(
                        f"[plan-json] Resource group '{name}' does not "
                        f"start with prefix '{settings.resource_group_prefix}'"
                    )

            # Check: resolved subscription references in scope fields
            scope = after.get("scope", "")
            if scope and "/subscriptions/" in scope:
                import re as _re
                sub_match = _re.search(r'/subscriptions/([a-f0-9-]+)', scope, _re.IGNORECASE)
                if sub_match and settings.allowed_subscriptions:
                    sub_id = sub_match.group(1)
                    if sub_id not in settings.allowed_subscriptions:
                        violations.append(
                            f"[plan-json] Resource targets subscription "
                            f"'{sub_id}' which is not in the allowed list"
                        )

            # Check: dangerous resource types in resolved plan
            dangerous_types = [
                "azuread_", "azurerm_management_group",
                "azurerm_tenant_", "azurerm_policy_definition",
            ]
            for dangerous in dangerous_types:
                if resource_type.startswith(dangerous):
                    violations.append(
                        f"[plan-json] Dangerous resource type in plan: "
                        f"'{resource_type}'"
                    )

            # Check: role assignments at management-group or tenant scope
            if resource_type in ("azurerm_role_assignment", "aws_iam_policy_attachment"):
                scope_val = after.get("scope", "")
                if "managementGroups" in scope_val or "tenant" in scope_val.lower():
                    violations.append(
                        f"[plan-json] Role assignment at dangerous scope: "
                        f"'{scope_val}'"
                    )

        # Check: total resource count from plan
        create_count = sum(
            1 for rc in resource_changes
            if "create" in rc.get("change", {}).get("actions", [])
        )
        if create_count > settings.max_terraform_resources:
            violations.append(
                f"[plan-json] Plan creates {create_count} resources, "
                f"exceeding maximum ({settings.max_terraform_resources})"
            )

    except TerraformError as exc:
        log.warning(
            "Terraform plan failed during safety check (non-blocking): %s",
            str(exc)[:300],
        )
        # Plan failure here is not a safety violation — deploy will catch it
    except Exception as exc:
        log.warning("Plan-JSON safety check encountered an error: %s", exc)

    return violations


# ══════════════════════════════════════════════════════════════════
#  NODE: deploy_infrastructure
# ══════════════════════════════════════════════════════════════════

def deploy_infrastructure(state: OrchestratorState) -> dict[str, Any]:
    """
    Node: Deploy the Terraform infrastructure to Azure.
    Uses terraform init → plan → apply with user confirmation.
    """
    with node_logger("deploy_infrastructure", state.get("run_id", "")) as log:
        settings = _get_settings()
        run_id = state.get("run_id", "unknown")
        deploy_retries = state.get("deploy_retries", 0)

        tf_runner = TerraformRunner(
            run_id=run_id,
            base_tmp_dir=settings.terraform_tmp_dir,
            azure_env={
                "ARM_CLIENT_ID": settings.azure_client_id,
                "ARM_CLIENT_SECRET": settings.azure_client_secret,
                "ARM_TENANT_ID": settings.azure_tenant_id,
                "ARM_SUBSCRIPTION_ID": settings.azure_subscription_id,
            },
        )

        # Write the current Terraform code (may be updated from retry)
        tf_code = state.get("terraform_code", "")
        if tf_code:
            tf_runner.write_tf_files(tf_code)

        try:
            # Init
            tf_runner.init()

            # Plan (for output capture)
            plan_output = tf_runner.plan()
            log.info("Terraform plan output:\n%s", plan_output[:1000])

            # Apply with confirmation
            tf_runner.apply(auto_approve=False)

            log.info("Infrastructure deployed successfully")

            # Persist run manifest so orphaned infra can be recovered
            manifest = RunManifest(
                manifest_dir=settings.reports_dir,
                run_id=run_id,
            )
            scenario_id = state.get("scenario_id", "")
            try:
                registry = ScenarioRegistry.get_instance()
                cloud = registry.get(scenario_id).cloud_provider
            except KeyError:
                cloud = "azure"
            manifest.update(scenario_id=scenario_id)
            manifest.mark_deployed(
                terraform_working_dir=str(tf_runner.working_dir),
                terraform_code=tf_code,
                cloud_provider=cloud,
            )

            return {
                "deploy_status": "success",
                "deploy_error": "",
                "terraform_plan_output": plan_output,
            }

        except TerraformError as exc:
            new_retries = deploy_retries + 1
            error_msg = exc.stderr if hasattr(exc, 'stderr') else str(exc)
            error_history = list(state.get("deploy_error_history", []))
            error_history.append(error_msg)
            log.error(
                "Deployment failed (attempt %d/3): %s",
                new_retries,
                error_msg[:300],
            )
            return {
                "deploy_status": "failed",
                "deploy_retries": new_retries,
                "deploy_error": error_msg,
                "deploy_error_history": error_history,
            }
        except Exception as exc:
            new_retries = deploy_retries + 1
            error_msg = str(exc)
            error_history = list(state.get("deploy_error_history", []))
            error_history.append(error_msg)
            log.error("Unexpected deployment error: %s", exc)
            return {
                "deploy_status": "failed",
                "deploy_retries": new_retries,
                "deploy_error": error_msg,
                "deploy_error_history": error_history,
            }


# ══════════════════════════════════════════════════════════════════
#  NODE: execute_simulator
# ══════════════════════════════════════════════════════════════════

def execute_simulator(state: OrchestratorState) -> dict[str, Any]:
    """
    Node: Execute the attack simulation dynamically using the scenario's
    declared simulation_steps and the appropriate cloud provider.

    Steps are dispatched via CloudProvider.execute_action(), making this
    node scenario-agnostic. Each step from the scenario definition is
    executed in order, results are recorded with timestamps.
    """
    with node_logger("execute_simulator", state.get("run_id", "")) as log:
        settings = _get_settings()
        scenario_id = state.get("scenario_id", "")
        results: list[dict[str, Any]] = []

        # ── Load scenario and resolve cloud provider ──────────────
        try:
            registry = ScenarioRegistry.get_instance()
            scenario = registry.get(scenario_id)
        except KeyError:
            log.error("Scenario '%s' not found — cannot execute simulation", scenario_id)
            results.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": "load_scenario",
                "target_resource": scenario_id,
                "result": "failed",
                "details": "",
                "error": f"Scenario '{scenario_id}' not found in registry",
            })
            return {"simulation_results": results}

        cloud = scenario.cloud_provider or "azure"
        log.info(
            "Executing simulation for scenario '%s' (cloud=%s, %d steps)",
            scenario_id, cloud, len(scenario.simulation_steps),
        )

        # ── Resolve cloud provider implementation ─────────────────
        from azure_cortex_orchestrator.cloud_providers.azure_provider import AzureCloudProvider
        from azure_cortex_orchestrator.cloud_providers.aws_provider import AWSCloudProvider

        providers = {
            "azure": AzureCloudProvider,
            "aws": AWSCloudProvider,
        }
        provider_cls = providers.get(cloud)
        if provider_cls is None:
            log.error("Unsupported cloud provider: %s", cloud)
            results.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": "resolve_provider",
                "target_resource": cloud,
                "result": "failed",
                "details": "",
                "error": f"Unsupported cloud provider: '{cloud}'. Supported: {list(providers)}",
            })
            return {"simulation_results": results}

        provider = provider_cls()

        # ── Authenticate ──────────────────────────────────────────
        try:
            provider.authenticate(settings)
            results.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": "authenticate",
                "target_resource": cloud,
                "result": "success",
                "details": f"Authenticated to {cloud}",
                "error": None,
            })
        except NotImplementedError:
            log.error(
                "Cloud provider '%s' authentication is not yet implemented", cloud
            )
            results.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": "authenticate",
                "target_resource": cloud,
                "result": "failed",
                "details": "",
                "error": f"Cloud provider '{cloud}' authentication not implemented",
            })
            return {"simulation_results": results}
        except Exception as exc:
            log.error("Authentication failed for '%s': %s", cloud, exc)
            results.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": "authenticate",
                "target_resource": cloud,
                "result": "failed",
                "details": "",
                "error": str(exc),
            })
            return {"simulation_results": results}

        # ── Execute each simulation step ──────────────────────────
        for step in sorted(scenario.simulation_steps, key=lambda s: s.order):
            log.info(
                "Step %d/%d: %s — %s",
                step.order,
                len(scenario.simulation_steps),
                step.name,
                step.sdk_action,
            )

            try:
                result = provider.execute_action(
                    action=step.sdk_action,
                    target_resource_type=step.target_resource_type,
                    parameters=step.parameters,
                )
                # Enrich the result with step metadata
                result["step_name"] = step.name
                result["step_order"] = step.order
                result["step_description"] = step.description
                results.append(result)

                log.info(
                    "  → %s: %s",
                    result.get("result", "unknown"),
                    result.get("details", "")[:200],
                )

                if result.get("result") == "failed":
                    log.warning(
                        "Step %d (%s) failed: %s",
                        step.order, step.name, result.get("error", ""),
                    )

            except NotImplementedError:
                log.error(
                    "Action '%s' not implemented for provider '%s'",
                    step.sdk_action, cloud,
                )
                results.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "action": step.sdk_action,
                    "target_resource": step.target_resource_type,
                    "result": "failed",
                    "details": step.description,
                    "error": f"Action not implemented for provider '{cloud}'",
                    "step_name": step.name,
                    "step_order": step.order,
                    "step_description": step.description,
                })
            except Exception as exc:
                log.error("Step %d (%s) raised exception: %s", step.order, step.name, exc)
                results.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "action": step.sdk_action,
                    "target_resource": step.target_resource_type,
                    "result": "failed",
                    "details": step.description,
                    "error": str(exc),
                    "step_name": step.name,
                    "step_order": step.order,
                    "step_description": step.description,
                })

        log.info("Simulation completed with %d actions", len(results))
        return {"simulation_results": results}


# ══════════════════════════════════════════════════════════════════
#  NODE: validator
# ══════════════════════════════════════════════════════════════════

def validator(state: OrchestratorState) -> dict[str, Any]:
    """
    Node: Validate whether the simulation was detected.

    Uses Cortex XDR if API key is configured, otherwise falls back
    to simulated (rule-based) detection.
    """
    with node_logger("validator", state.get("run_id", "")) as log:
        settings = _get_settings()

        if settings.has_cortex_xdr:
            log.info("Using Cortex XDR validator")
            from azure_cortex_orchestrator.validators.cortex_xdr import CortexXDRValidator
            v = CortexXDRValidator(settings)
        else:
            log.info("Using simulated validator (no Cortex XDR API key)")
            from azure_cortex_orchestrator.validators.simulated import SimulatedValidator
            v = SimulatedValidator(settings)

        result = v.validate(state)

        log.info(
            "Validation result: detected=%s source=%s confidence=%.2f",
            result.detected,
            result.source,
            result.confidence,
        )

        return {"validation_result": result.to_dict()}


# ══════════════════════════════════════════════════════════════════
#  NODE: teardown
# ══════════════════════════════════════════════════════════════════

def teardown(state: OrchestratorState) -> dict[str, Any]:
    """
    Node: Destroy all deployed Azure infrastructure and clean up.
    """
    with node_logger("teardown", state.get("run_id", "")) as log:
        settings = _get_settings()
        run_id = state.get("run_id", "unknown")

        tf_runner = TerraformRunner(
            run_id=run_id,
            base_tmp_dir=settings.terraform_tmp_dir,
            azure_env={
                "ARM_CLIENT_ID": settings.azure_client_id,
                "ARM_CLIENT_SECRET": settings.azure_client_secret,
                "ARM_TENANT_ID": settings.azure_tenant_id,
                "ARM_SUBSCRIPTION_ID": settings.azure_subscription_id,
            },
        )

        # Write the terraform code so destroy knows what to destroy
        tf_code = state.get("terraform_code", "")
        if tf_code:
            tf_runner.write_tf_files(tf_code)

        try:
            output = tf_runner.destroy(auto_approve=True)
            log.info("Infrastructure destroyed successfully")

            # Update run manifest to reflect successful teardown
            manifest = RunManifest(
                manifest_dir=settings.reports_dir,
                run_id=run_id,
            )
            manifest.mark_teardown_complete()

        except TerraformError as exc:
            log.error("Teardown failed: %s", exc)
        except Exception as exc:
            log.error("Unexpected teardown error: %s", exc)
        finally:
            tf_runner.cleanup()

        return {}


# ══════════════════════════════════════════════════════════════════
#  NODE: erasure_validator
# ══════════════════════════════════════════════════════════════════

def erasure_validator(state: OrchestratorState) -> dict[str, Any]:
    """
    Node: Verify that all cloud resources deployed during the simulation
    have been fully destroyed after teardown.

    Checks:
    1. Terraform state file for residual resources.
    2. Azure API for lingering resource groups (Azure scenarios).
    3. Logs any orphaned resources for the report.
    """
    with node_logger("erasure_validator", state.get("run_id", "")) as log:
        settings = _get_settings()

        if state.get("dry_run", False):
            log.info("Dry run — skipping erasure validation.")
            return {
                "erasure_result": {
                    "fully_erased": True,
                    "orphaned_resources": [],
                    "details": "Dry run — no resources were deployed.",
                },
            }

        from azure_cortex_orchestrator.validators.erasure import validate_erasure

        result = validate_erasure(state, settings)

        log.info(
            "Erasure validation: fully_erased=%s, orphaned=%d",
            result.fully_erased,
            len(result.orphaned_resources),
        )

        if not result.fully_erased:
            log.warning(
                "TEARDOWN INCOMPLETE — %d orphaned resource(s) detected: %s",
                len(result.orphaned_resources),
                result.details,
            )

        # Update run manifest with erasure result
        try:
            manifest = RunManifest(
                manifest_dir=settings.reports_dir,
                run_id=state.get("run_id", "unknown"),
            )
            manifest.mark_erasure_validated(result.fully_erased)
        except Exception as exc:
            log.warning("Failed to update run manifest: %s", exc)

        return {"erasure_result": result.to_dict()}


# ══════════════════════════════════════════════════════════════════
#  NODE: generate_report
# ══════════════════════════════════════════════════════════════════

def generate_report(state: OrchestratorState) -> dict[str, Any]:
    """
    Node: Generate Markdown and JSON reports from the final state.
    """
    with node_logger("generate_report", state.get("run_id", "")) as log:
        settings = _get_settings()
        generator = ReportGenerator(settings.reports_dir)

        md_content, report_dir = generator.generate(state)

        log.info("Report generated at: %s", report_dir)

        return {
            "report": md_content,
            "report_path": report_dir,
        }
