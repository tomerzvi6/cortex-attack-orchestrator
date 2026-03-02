"""
LangGraph state definition for the Azure-Cortex Orchestrator.

Defines OrchestratorState as a TypedDict used across all graph nodes.
Each node receives the full state and returns a partial dict update.
"""

from __future__ import annotations

import uuid
from typing import Any, TypedDict


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

    # ── Input ─────────────────────────────────────────────────────
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

    # ── Safety ────────────────────────────────────────────────────
    safety_violations: list[str]    # List of safety guardrail violations

    # ── Simulation ────────────────────────────────────────────────
    simulation_results: list[SimulationAction]  # Timestamped action log

    # ── Validation ────────────────────────────────────────────────
    validation_result: ValidationResult  # Detection verdict

    # ── Reporting ─────────────────────────────────────────────────
    report_path: str                # Path to the generated report directory
    report: str                     # Full Markdown report content


def create_initial_state(
    goal: str,
    scenario_id: str,
    dry_run: bool = False,
    run_id: str | None = None,
) -> OrchestratorState:
    """Create a fresh initial state for a new orchestration run."""
    return OrchestratorState(
        run_id=run_id or str(uuid.uuid4()),
        dry_run=dry_run,
        goal=goal,
        scenario_id=scenario_id,
        attack_plan={},
        terraform_code="",
        terraform_plan_output="",
        terraform_workspace="",
        terraform_working_dir="",
        deploy_status="pending",
        deploy_retries=0,
        deploy_error="",
        safety_violations=[],
        simulation_results=[],
        validation_result={},
        report_path="",
        report="",
    )
