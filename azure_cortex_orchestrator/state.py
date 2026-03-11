"""
LangGraph state definition for the Azure-Cortex Orchestrator.

Defines OrchestratorState as a TypedDict used across all graph nodes.
Each node receives the full state and returns a partial dict update.
"""

from __future__ import annotations

import uuid
from typing import Any, TypedDict


class CobraFile(TypedDict, total=False):
    """A single file fetched from the cobra-tool repo."""

    path: str    # repo-relative path, e.g. "attacks/lateral_movement.yaml"
    name: str    # filename only
    content: str # raw text content


class CobraIntel(TypedDict, total=False):
    """Live attack intelligence fetched from PaloAltoNetworks/cobra-tool."""

    fetched_at: str           # ISO-8601 timestamp of last successful fetch
    commit_sha: str           # Latest commit SHA (used for change detection)
    repo_url: str             # Source repo URL
    files: list[CobraFile]    # Fetched attack definition files
    summary: str              # Human-readable fetch summary (for logs)


class AttackStep(TypedDict, total=False):
    """A single step in the attack plan."""

    step_number: int
    description: str
    mitre_technique_id: str
    mitre_technique_name: str
    kill_chain_phase: str
    details: str


class AttackPlan(TypedDict, total=False):
    """Structured attack plan produced by the plan_attack node."""

    goal: str
    scenario_id: str
    mitre_techniques: list[dict[str, str]]  # [{id, name, description, url}]
    steps: list[AttackStep]
    summary: str


class LLMUsageRecord(TypedDict, total=False):
    """Token and cost metrics for a single LLM call."""

    node: str                # Which graph node made the call
    model: str               # Model used (e.g. "gpt-4o-mini")
    prompt_tokens: int       # Tokens in the prompt
    completion_tokens: int   # Tokens in the completion
    total_tokens: int        # prompt_tokens + completion_tokens
    estimated_cost_usd: float  # Estimated cost based on model pricing
    duration_ms: float       # Wall-clock time for the API call
    timestamp: str           # ISO-8601 timestamp of the call


class SimulationAction(TypedDict, total=False):
    """A single action executed during the simulation."""

    timestamp: str
    action: str
    target_resource: str
    result: str  # "success" | "failed" | "skipped"
    details: str
    error: str | None


class ValidationResult(TypedDict, total=False):
    """Result from the validator node."""

    detected: bool
    source: str  # "cortex_xdr" | "simulated"
    details: str
    confidence: float  # 0.0 - 1.0
    raw_data: Any


class OrchestratorState(TypedDict, total=False):
    """
    Central state for the LangGraph orchestration graph.

    All nodes read from and write partial updates back to this state.
    """

    # ── Run metadata ──────────────────────────────────────────────
    run_id: str                     # UUID for this execution run
    dry_run: bool                   # If True, skip cloud operations
    interactive: bool               # If True, prompt user at checkpoints

    # ── Human intervention ────────────────────────────────────────
    user_aborted: bool              # Set by checkpoint if user aborts
    replan_requested: bool          # Set if user wants to modify the goal
    skip_teardown: bool             # Set if user wants to keep infra alive

    # ── Input ─────────────────────────────────────────────────────
    prompt: str                     # Free-text user prompt (optional, triggers generate_scenario)
    goal: str                       # Natural language attack goal
    scenario_id: str                # Scenario registry key

    # ── Plan ──────────────────────────────────────────────────────
    attack_plan: AttackPlan         # ATT&CK-mapped attack plan

    # ── Infrastructure ────────────────────────────────────────────
    terraform_code: str             # Generated HCL code
    terraform_plan_output: str      # Output of `terraform plan`
    terraform_workspace: str        # Terraform workspace name (per-run)
    terraform_working_dir: str      # Temp directory for .tf files

    # ── Deployment ────────────────────────────────────────────────
    deploy_status: str              # "pending" | "success" | "failed" | "unsafe"
    deploy_retries: int             # Current retry count (max 3)
    deploy_error: str               # Last deployment error message
    deploy_error_history: list[str] # All deployment errors across retries

    # ── Safety ────────────────────────────────────────────────────
    safety_violations: list[str]    # List of safety guardrail violations

    # ── Simulation ────────────────────────────────────────────────
    simulation_results: list[SimulationAction]  # Timestamped action log

    # ── Validation ────────────────────────────────────────────────
    validation_result: ValidationResult  # Detection verdict

    # ── Erasure ───────────────────────────────────────────────────
    erasure_result: dict[str, Any]       # Teardown completeness check

    # ── LLM Observability ──────────────────────────────────────────
    llm_usage: list[LLMUsageRecord]  # Token/cost metrics per LLM call
    # ── External Intel ─────────────────────────────────────────
    cobra_intel: CobraIntel         # Live intel from the cobra-tool repo (optional)
    # ── Reporting ─────────────────────────────────────────────────
    report_path: str                # Path to the generated report directory
    report: str                     # Full Markdown report content


def create_initial_state(
    goal: str,
    scenario_id: str,
    dry_run: bool = False,
    interactive: bool = False,
    run_id: str | None = None,
    prompt: str = "",
) -> OrchestratorState:
    """Create a fresh initial state for a new orchestration run."""
    return OrchestratorState(
        run_id=run_id or str(uuid.uuid4()),
        dry_run=dry_run,
        interactive=interactive,
        prompt=prompt,
        goal=goal,
        scenario_id=scenario_id,
        user_aborted=False,
        replan_requested=False,
        skip_teardown=False,
        attack_plan={},
        terraform_code="",
        terraform_plan_output="",
        terraform_workspace="",
        terraform_working_dir="",
        deploy_status="pending",
        deploy_retries=0,
        deploy_error="",
        deploy_error_history=[],
        safety_violations=[],
        simulation_results=[],
        validation_result={},
        erasure_result={},
        llm_usage=[],
        report_path="",
        report="",
    )
