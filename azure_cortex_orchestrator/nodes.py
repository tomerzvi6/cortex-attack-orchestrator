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
from pydantic import ValidationError

from azure_cortex_orchestrator.config import Settings, load_settings
from azure_cortex_orchestrator.models import AttackPlanResponse, ScenarioResponse
from azure_cortex_orchestrator.prompts import (
    FIX_TERRAFORM_SYSTEM_PROMPT,
    GENERATE_INFRA_SYSTEM_PROMPT,
    GENERATE_SCENARIO_SYSTEM_PROMPT,
    PLAN_ATTACK_SYSTEM_PROMPT,
    build_generate_infrastructure_prompt,
    build_generate_scenario_prompt,
    build_plan_attack_prompt,
)
from azure_cortex_orchestrator.prompts.generate_scenario import SUPPORTED_SDK_ACTIONS
from azure_cortex_orchestrator.scenarios.registry import ScenarioRegistry
from azure_cortex_orchestrator.state import LLMUsageRecord, OrchestratorState
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
    # Always reload so .env changes are picked up without process restart
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
    node_name: str = "",
    json_mode: bool = False,
    max_retries: int = 3,
    timeout_seconds: int = 120,
) -> tuple[str, LLMUsageRecord]:
    """
    Call OpenAI chat completions with exponential backoff and timeout.

    Args:
        json_mode: When True, sets ``response_format={"type": "json_object"}``
            so the model is guaranteed to return valid JSON (no markdown
            fences needed).

    Returns:
        Tuple of (response_text, usage_record) where usage_record
        contains token counts, cost estimate, and timing.

    Retries on transient errors (rate limits, server errors, timeouts).
    Raises after ``max_retries`` failures.
    """
    client = _get_openai_client()
    settings = _get_settings()
    resolved_model = model or settings.openai_model

    # Build optional kwargs
    extra_kwargs: dict[str, Any] = {}
    if json_mode:
        extra_kwargs["response_format"] = {"type": "json_object"}

    last_exc: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            call_start = time.perf_counter()
            response = client.chat.completions.create(
                model=resolved_model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=temperature,
                max_tokens=max_tokens,
                timeout=timeout_seconds,
                **extra_kwargs,
            )
            call_duration_ms = round((time.perf_counter() - call_start) * 1000, 2)

            text = response.choices[0].message.content or ""

            # ── Extract token usage ───────────────────────────────
            usage = response.usage
            prompt_tokens = usage.prompt_tokens if usage else 0
            completion_tokens = usage.completion_tokens if usage else 0
            total_tokens = usage.total_tokens if usage else 0

            usage_record: LLMUsageRecord = {
                "node": node_name,
                "model": resolved_model,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens,
                "estimated_cost_usd": _estimate_cost(
                    resolved_model, prompt_tokens, completion_tokens,
                ),
                "duration_ms": call_duration_ms,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            logger.info(
                "OpenAI call completed: model=%s tokens=%d "
                "(prompt=%d, completion=%d) cost=$%.4f duration=%.0fms",
                resolved_model,
                total_tokens,
                prompt_tokens,
                completion_tokens,
                usage_record["estimated_cost_usd"],
                call_duration_ms,
            )

            return text, usage_record

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


# ── Cost estimation lookup ────────────────────────────────────────
# Prices per 1K tokens (USD). Update as OpenAI publishes new prices.
_MODEL_PRICING: dict[str, tuple[float, float]] = {
    # (prompt_per_1k, completion_per_1k)
    "gpt-5-mini": (0.00015, 0.0006),
    "gpt-4o": (0.005, 0.015),
}


def _estimate_cost(
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
) -> float:
    """
    Estimate the cost of an OpenAI API call in USD.

    Falls back to gpt-5-mini pricing for unknown models.
    """
    # Normalise model name for lookup (strip date suffixes like -0613)
    model_key = model.lower()
    for known_model in _MODEL_PRICING:
        if model_key.startswith(known_model):
            prompt_rate, completion_rate = _MODEL_PRICING[known_model]
            return (
                (prompt_tokens / 1000) * prompt_rate
                + (completion_tokens / 1000) * completion_rate
            )

    # Default to gpt-5-mini pricing if model is unrecognised
    prompt_rate, completion_rate = _MODEL_PRICING["gpt-5-mini"]
    return (
        (prompt_tokens / 1000) * prompt_rate
        + (completion_tokens / 1000) * completion_rate
    )


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
#  NODE: fetch_cobra_intel
# ══════════════════════════════════════════════════════════════════


def fetch_cobra_intel(state: OrchestratorState) -> dict[str, Any]:
    """
    Node: Fetch live attack intelligence from PaloAltoNetworks/cobra-tool.

    Runs at the very start of every graph execution before planning or
    scenario generation.  Checks GitHub for the latest commit SHA; if the
    repo has changed since the last run, downloads updated attack definition
    files and stores them in state['cobra_intel'].

    Downstream nodes (plan_attack, generate_scenario) automatically include
    the cobra-tool content as supplementary reference in their LLM prompts.

    Graceful degradation: any error (network, rate-limit, auth) is caught
    and logged.  The run continues normally with no cobra intel rather than
    failing.  The integration can also be turned off entirely via
    COBRA_TOOL_ENABLED=false.
    """
    with node_logger("fetch_cobra_intel", state.get("run_id", "")) as log:
        settings = _get_settings()

        if not settings.cobra_tool_enabled:
            log.info(
                "cobra-tool integration disabled (COBRA_TOOL_ENABLED=false)"
            )
            return {}

        try:
            from azure_cortex_orchestrator.utils.cobra_tool import (
                fetch as cobra_fetch,
            )

            intel = cobra_fetch(
                github_token=settings.cobra_tool_github_token or None,
                cache_ttl=settings.cobra_tool_cache_ttl,
            )
            if intel:
                log.info("cobra-tool intel ready: %s", intel["summary"])
                return {"cobra_intel": intel}
            else:
                log.warning(
                    "cobra-tool: no intel available (fetch returned None)"
                )
                return {}

        except Exception as exc:
            log.warning(
                "cobra-tool: failed to fetch intel (%s) — continuing without it",
                exc,
            )
            return {}


# ══════════════════════════════════════════════════════════════════
#  NODE: fetch_mitre_intel
# ══════════════════════════════════════════════════════════════════


def fetch_mitre_intel(state: OrchestratorState) -> dict[str, Any]:
    """
    Node: Fetch live MITRE ATT&CK cloud technique data from mitre/cti.

    Runs immediately after fetch_cobra_intel, before scenario generation or
    attack planning.  Downloads the enterprise-attack STIX bundle (cached
    after the first run), filters for cloud/IaaS techniques, and stores the
    result in state['mitre_intel'].

    Downstream node plan_attack injects these authoritative technique IDs
    into the LLM prompt so the model never invents non-existent IDs.

    Graceful degradation: any error is caught and logged.  The run continues
    normally with LLM training-data fallback.  Disable via MITRE_TOOL_ENABLED=false.
    """
    with node_logger("fetch_mitre_intel", state.get("run_id", "")) as log:
        settings = _get_settings()

        if not settings.mitre_tool_enabled:
            log.info("mitre-tool integration disabled (MITRE_TOOL_ENABLED=false)")
            return {}

        try:
            from azure_cortex_orchestrator.utils.mitre_tool import (
                fetch as mitre_fetch,
            )

            token = settings.mitre_tool_github_token or settings.cobra_tool_github_token or None
            intel = mitre_fetch(
                github_token=token,
                cache_ttl=settings.mitre_tool_cache_ttl,
            )
            if intel:
                log.info("mitre-tool intel ready: %s", intel["summary"])
                return {"mitre_intel": intel}
            else:
                log.warning("mitre-tool: no intel available (fetch returned None)")
                return {}

        except Exception as exc:
            log.warning(
                "mitre-tool: failed to fetch intel (%s) — continuing without it",
                exc,
            )
            return {}


# ══════════════════════════════════════════════════════════════════
#  NODE: fetch_terraform_schema
# ══════════════════════════════════════════════════════════════════


def fetch_terraform_schema(state: OrchestratorState) -> dict[str, Any]:
    """
    Node: Fetch live azurerm provider schema reference from the official repo.

    Runs between review_plan and generate_infrastructure.  Downloads
    documentation pages for commonly-used azurerm resources (cached after
    the first run), parses deprecated/removed argument names, and stores
    the result in state['terraform_schema_intel'].

    Downstream node generate_infrastructure injects this schema reference
    into the LLM prompt so the model uses only valid argument names for the
    current provider version — eliminating the class of errors that require
    hardcoded workarounds in the prompt and post-processing sanitizer.

    Graceful degradation: any error is caught and logged.  The run continues
    normally with the existing hardcoded constraints.  Disable via
    TF_SCHEMA_TOOL_ENABLED=false.
    """
    with node_logger("fetch_terraform_schema", state.get("run_id", "")) as log:
        settings = _get_settings()

        if not settings.tf_schema_tool_enabled:
            log.info(
                "terraform-schema integration disabled (TF_SCHEMA_TOOL_ENABLED=false)"
            )
            return {}

        try:
            from azure_cortex_orchestrator.utils.terraform_schema_tool import (
                fetch as schema_fetch,
            )

            token = settings.tf_schema_github_token or settings.cobra_tool_github_token or None
            intel = schema_fetch(
                github_token=token,
                cache_ttl=settings.tf_schema_cache_ttl,
            )
            if intel:
                log.info("terraform-schema intel ready: %s", intel["summary"])
                return {"terraform_schema_intel": intel}
            else:
                log.warning(
                    "terraform-schema: no intel available (fetch returned None)"
                )
                return {}

        except Exception as exc:
            log.warning(
                "terraform-schema: failed to fetch intel (%s) — continuing without it",
                exc,
            )
            return {}


# ══════════════════════════════════════════════════════════════════
#  NODE: generate_scenario
# ══════════════════════════════════════════════════════════════════


def generate_scenario(state: OrchestratorState) -> dict[str, Any]:
    """
    Node: Convert a free-text user prompt into a structured Scenario
    and register it dynamically. Only runs when state['prompt'] is set.

    This node:
    1. Sends the prompt to the LLM with GENERATE_SCENARIO_SYSTEM_PROMPT
    2. Validates the response with ScenarioResponse (Pydantic)
    3. Validates sdk_actions against the supported allowlist
    4. Creates a Scenario dataclass and registers it in ScenarioRegistry
    5. Sets state['goal'] and state['scenario_id'] for downstream nodes
    """
    with node_logger("generate_scenario", state.get("run_id", "")) as log:
        prompt = state.get("prompt", "")
        if not prompt:
            log.debug("No prompt provided — skipping scenario generation")
            return {}

        log.info("Generating scenario from user prompt: %s", prompt[:200])

        response, usage_record = _call_openai(
            build_generate_scenario_prompt(state.get("cobra_intel")),
            f"User request: {prompt}",
            node_name="generate_scenario",
            json_mode=True,
            max_tokens=4096,
        )
        llm_usage = list(state.get("llm_usage", []))
        llm_usage.append(usage_record)

        # ── Parse and validate with Pydantic ──────────────────────
        try:
            parsed = ScenarioResponse.model_validate_json(response)
        except Exception as exc:
            log.warning("Pydantic validation failed, trying raw JSON: %s", exc)
            try:
                raw = _extract_json(response)
                parsed = ScenarioResponse.model_validate(raw)
            except Exception as parse_exc:
                log.error("Failed to parse scenario response: %s", parse_exc)
                # Return with original state — will fall through to
                # plan_attack with whatever goal/scenario_id was set
                return {"llm_usage": llm_usage}

        # ── Validate sdk_actions against allowlist ────────────────
        cloud = parsed.cloud_provider
        supported = set(SUPPORTED_SDK_ACTIONS.get(cloud, []))
        for step in parsed.simulation_steps:
            if step.sdk_action not in supported:
                log.warning(
                    "LLM generated unsupported sdk_action '%s' for %s — "
                    "replacing with closest match or removing",
                    step.sdk_action, cloud,
                )
                # Try fuzzy match: same service prefix
                service_prefix = step.sdk_action.split(".")[0]
                candidates = [a for a in supported if a.startswith(service_prefix)]
                if candidates:
                    step.sdk_action = candidates[0]
                    log.info("  → Replaced with: %s", step.sdk_action)
                else:
                    step.sdk_action = f"UNSUPPORTED:{step.sdk_action}"

        # ── Build Scenario dataclass and register ─────────────────
        from azure_cortex_orchestrator.scenarios.registry import (
            Scenario,
            SimulationStep,
        )

        scenario = Scenario(
            id=parsed.id,
            name=parsed.name,
            description=parsed.description,
            goal_template=parsed.goal_template,
            cloud_provider=parsed.cloud_provider,
            expected_mitre_techniques=[
                t.model_dump() for t in parsed.expected_mitre_techniques
            ],
            terraform_hints=parsed.terraform_hints.model_dump(),
            simulation_steps=[
                SimulationStep(
                    order=s.order,
                    name=s.name,
                    description=s.description,
                    sdk_action=s.sdk_action,
                    target_resource_type=s.target_resource_type,
                )
                for s in parsed.simulation_steps
            ],
            detection_expectations=parsed.detection_expectations.model_dump(),
        )

        registry = ScenarioRegistry.get_instance()
        registry.register(scenario)

        log.info(
            "Scenario generated and registered: id=%s, cloud=%s, "
            "%d techniques, %d steps",
            scenario.id,
            scenario.cloud_provider,
            len(scenario.expected_mitre_techniques),
            len(scenario.simulation_steps),
        )

        return {
            "goal": parsed.goal_template,
            "scenario_id": parsed.id,
            "llm_usage": llm_usage,
        }


# ══════════════════════════════════════════════════════════════════
#  NODE: plan_attack
# ══════════════════════════════════════════════════════════════════


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
        response, usage_record = _call_openai(
            build_plan_attack_prompt(
                cobra_intel=state.get("cobra_intel"),
                mitre_intel=state.get("mitre_intel"),
            ),
            user_prompt,
            node_name="plan_attack",
            json_mode=True,
        )
        llm_usage = list(state.get("llm_usage", []))
        llm_usage.append(usage_record)

        # Validate response against Pydantic schema
        try:
            parsed = AttackPlanResponse.model_validate_json(response)
            attack_plan = parsed.model_dump()
        except (ValidationError, ValueError) as exc:
            log.warning(
                "Pydantic validation failed, falling back to raw JSON: %s", exc,
            )
            # Fallback: try plain JSON parse (tolerates extra/missing fields)
            try:
                attack_plan = _extract_json(response)
            except (json.JSONDecodeError, ValueError) as parse_exc:
                log.error("Failed to parse attack plan JSON: %s", parse_exc)
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

        return {"attack_plan": attack_plan, "llm_usage": llm_usage}


# ══════════════════════════════════════════════════════════════════
#  NODE: generate_infrastructure
# ══════════════════════════════════════════════════════════════════


def _sanitize_terraform_code(code: str) -> str:
    """Post-process LLM-generated Terraform to fix known bad patterns.

    The LLM frequently generates deprecated or invalid arguments that cause
    ``terraform plan``/``apply`` to fail.  We fix them deterministically here
    so the self-healing retry loop doesn't waste attempts on preventable errors.
    """

    # 1. Remove deprecated `allow_blob_public_access` (azurerm >= 3.0)
    code = re.sub(
        r'^\s*allow_blob_public_access\s*=\s*\S+\s*\n',
        '',
        code,
        flags=re.MULTILINE,
    )

    # 2. Remove `tags` blocks from azurerm_subnet (does not support tags)
    code = re.sub(
        r'(resource\s+"azurerm_subnet"\s+"[^"]*"\s*\{[^}]*?)\s*tags\s*=\s*\{[^}]*\}\s*\n',
        r'\1',
        code,
        flags=re.DOTALL,
    )

    # 3. Replace `source = "..."` with `source_content` in azurerm_storage_blob
    #    to avoid referencing local files that don't exist.
    code = re.sub(
        r'(resource\s+"azurerm_storage_blob"[^}]*?)'
        r'source\s*=\s*"[^"]*"',
        r'\1source_content = "simulated-sensitive-data"',
        code,
        flags=re.DOTALL,
    )

    # 4. Fix diagnostic setting log categories for storage accounts.
    #    Azure storage requires StorageRead/StorageWrite/StorageDelete,
    #    not Read/Write/Delete.
    _STORAGE_DIAG_CAT_MAP = {
        '"Read"': '"StorageRead"',
        '"Write"': '"StorageWrite"',
        '"Delete"': '"StorageDelete"',
    }
    # Only replace inside azurerm_monitor_diagnostic_setting blocks
    def _fix_diag_block(m: re.Match) -> str:
        block = m.group(0)
        for old, new in _STORAGE_DIAG_CAT_MAP.items():
            block = block.replace(f'category       = {old}', f'category       = {new}')
            block = block.replace(f'category = {old}', f'category = {new}')
        return block

    code = re.sub(
        r'resource\s+"azurerm_monitor_diagnostic_setting"[^}]*(?:\{[^}]*\}[^}]*)*\}',
        _fix_diag_block,
        code,
        flags=re.DOTALL,
    )

    # 5. Replace Standard_DS1_v2 with Standard_B2s (DS1_v2 is frequently
    #    capacity-constrained in eastus2 and other popular regions).
    code = re.sub(
        r'Standard_DS1_v2',
        'Standard_B2s',
        code,
    )

    # 6. Replace eastus2 with eastus for better VM SKU availability.
    #    Only replace in location fields and provider blocks, not in comments.
    code = re.sub(
        r'(location\s*=\s*"?)eastus2("?)',
        r'\1eastus\2',
        code,
    )

    # 7. Fix missing newlines before closing braces.
    #    LLM sometimes puts `]}\n` or `"}\n` on one line.
    code = re.sub(
        r'(\])\}',
        r'\1\n}',
        code,
    )

    # 8. Remove LLM placeholder values like "<your_...>" or "<YOUR_...>".
    #    These cause Terraform parse errors at apply time.
    code = re.sub(
        r'"<[Yy]our_[^"]*>"',
        '""',
        code,
    )

    return code


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
            response, usage_record = _call_openai(
                FIX_TERRAFORM_SYSTEM_PROMPT,
                fix_user_prompt,
                max_tokens=8192,
                node_name="generate_infrastructure",
            )
            terraform_code = _extract_hcl(response)
            llm_usage = list(state.get("llm_usage", []))
            llm_usage.append(usage_record)
        else:
            # ── First run ───────────────────────────────────────────
            templates_dir = Path(__file__).resolve().parent / "templates"
            jinja_env = Environment(loader=FileSystemLoader(str(templates_dir)))

            # Determine cloud provider
            cloud_provider = "azure"
            scenario = None
            try:
                registry = ScenarioRegistry.get_instance()
                scenario = registry.get(scenario_id)
                cloud_provider = scenario.cloud_provider or "azure"
            except KeyError:
                pass

            # ── Template-direct path: use pre-validated scenario template
            # Map common LLM-generated scenario IDs to known templates
            _SCENARIO_TEMPLATE_ALIASES: dict[str, str] = {
                # Azure IAM / privilege escalation variants
                "azure_low_privilege_role_assignment": "iam_privilege_escalation",
                "low_privilege_role_assignment": "iam_privilege_escalation",
                "azure_iam_privilege_escalation": "iam_privilege_escalation",
                "azure_role_escalation": "iam_privilege_escalation",
                "privilege_escalation": "iam_privilege_escalation",
                "role_assignment_escalation": "iam_privilege_escalation",
                # Azure storage variants
                "azure_storage_data_exfil": "storage_data_exfil",
                "azure_storage_exfiltration": "storage_data_exfil",
                "blob_data_exfiltration": "storage_data_exfil",
                # Azure VM variants
                "azure_vm_identity_log_deletion": "vm_identity_log_deletion",
                "vm_log_deletion": "vm_identity_log_deletion",
                "azure_vm_log_tampering": "vm_identity_log_deletion",
            }
            resolved_template_id = _SCENARIO_TEMPLATE_ALIASES.get(
                scenario_id, scenario_id
            )
            scenario_template_name = f"{resolved_template_id}.tf.j2"
            scenario_template_exists = (
                scenario_id != "custom"
                and (templates_dir / scenario_template_name).is_file()
            )

            if scenario_template_exists:
                log.info(
                    "Using pre-validated template: %s",
                    scenario_template_name,
                )
                template = jinja_env.get_template(scenario_template_name)

                region = (
                    scenario.terraform_hints.get("region", "eastus")
                    if scenario
                    else "eastus"
                )

                if cloud_provider == "aws":
                    terraform_code = template.render(
                        resource_name_prefix="cortex-sim-",
                        run_id=run_id,
                        region=region,
                    )
                else:
                    terraform_code = template.render(
                        resource_group_name=f"{settings.resource_group_prefix}{run_id[:8]}",
                        subscription_id=settings.azure_subscription_id or "SUBSCRIPTION_ID",
                        run_id=run_id,
                        location=region,
                        vm_name=f"sim-vm-{run_id[:8]}",
                        admin_username="simadmin",
                    )

                llm_usage = list(state.get("llm_usage", []))
                # No LLM call — no usage record

            else:
                # ── LLM fallback: custom/freeform prompts ───────────
                log.info(
                    "No scenario template for '%s' — using LLM generation",
                    scenario_id,
                )

                template_context = ""
                try:
                    base_template_name = (
                        "base_infra_aws.tf.j2"
                        if cloud_provider == "aws"
                        else "base_infra.tf.j2"
                    )
                    template = jinja_env.get_template(base_template_name)

                    if cloud_provider == "aws":
                        rendered = template.render(
                            resource_name_prefix="cortex-sim-",
                            run_id=run_id,
                            region="us-east-1",
                        )
                    else:
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
                response, usage_record = _call_openai(
                    build_generate_infrastructure_prompt(
                        terraform_schema_intel=state.get("terraform_schema_intel"),
                    ),
                    user_prompt,
                    max_tokens=8192,
                    node_name="generate_infrastructure",
                )

                terraform_code = _extract_hcl(response)
                llm_usage = list(state.get("llm_usage", []))
                llm_usage.append(usage_record)

        # ── Sanitize known bad patterns before writing ────────────
        terraform_code = _sanitize_terraform_code(terraform_code)

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
            "llm_usage": llm_usage,
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

        # Determine cloud provider for this run
        cloud_provider = "azure"
        try:
            registry = ScenarioRegistry.get_instance()
            scenario = registry.get(state.get("scenario_id", ""))
            cloud_provider = scenario.cloud_provider or "azure"
        except KeyError:
            pass

        if cloud_provider == "azure":
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

        elif cloud_provider == "aws":
            # AWS-specific safety checks

            # Check 1: No IAM admin / organization-level resources
            dangerous_aws_resources = [
                "aws_organizations_",
                "aws_iam_account_alias",
                "aws_iam_account_password_policy",
            ]
            for dangerous in dangerous_aws_resources:
                if dangerous in terraform_code.lower():
                    violations.append(
                        f"Potentially dangerous AWS resource type: '{dangerous}'"
                    )

            # Check 2: Block wildcard IAM policies (Action: "*")
            if re.search(
                r'"Action"\s*:\s*"\*"',
                terraform_code,
            ):
                violations.append(
                    'IAM policy with Action: "*" (admin access) detected'
                )

            # Check 3: Block excessive public S3 ACLs
            public_acl_count = len(re.findall(
                r'acl\s*=\s*"public-read',
                terraform_code,
            ))
            if public_acl_count > 1:
                violations.append(
                    f"Multiple public S3 ACLs detected ({public_acl_count}) — "
                    f"only 1 expected for simulation"
                )

            # Check 4: Resource naming prefix
            bucket_names = re.findall(
                r'resource\s+"aws_s3_bucket".*?bucket\s*=\s*"([^"]+)"',
                terraform_code,
                re.DOTALL,
            )
            for name in bucket_names:
                if not name.startswith("cortex-sim"):
                    violations.append(
                        f"S3 bucket '{name}' does not start with 'cortex-sim' prefix"
                    )

        # Check (universal): Resource count
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
            log.info("[1/3] Running terraform init...")
            tf_runner.init()
            log.info("[1/3] terraform init complete")

            # Plan (for output capture)
            log.info("[2/3] Running terraform plan...")
            plan_output = tf_runner.plan()
            log.info("[2/3] terraform plan complete")
            log.info("Terraform plan output:\n%s", plan_output[:1000])

            # Apply — only prompt for confirmation in CLI interactive mode
            interactive = state.get("interactive", False)
            log.info(
                "[3/3] Running terraform apply (auto_approve=%s) "
                "— this may take several minutes...",
                not interactive,
            )
            tf_runner.apply(auto_approve=not interactive)
            log.info("[3/3] terraform apply complete — infrastructure deployed successfully")

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
            log.info("Running terraform destroy — this may take several minutes...")
            output = tf_runner.destroy(auto_approve=True)
            log.info("terraform destroy complete — infrastructure destroyed successfully")

            # Update run manifest to reflect successful teardown
            manifest = RunManifest.load(
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
            manifest = RunManifest.load(
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
