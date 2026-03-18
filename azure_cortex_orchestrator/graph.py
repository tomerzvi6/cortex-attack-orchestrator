"""
LangGraph graph construction for the Azure-Cortex Orchestrator.

Defines the StateGraph with all nodes and conditional edges:

    START
      → fetch_cobra_intel  ← live cobra-tool repo intel (graceful no-op if offline)
      → [conditional: prompt mode or scenario mode]
         ├─ prompt provided   → generate_scenario
         └─ scenario mode     → plan_attack
      → review_plan (interactive checkpoint #1)
      → [conditional: aborted / replan / continue]
         ├─ aborted              → generate_report → END
         ├─ replan_requested     → plan_attack (loop)
         └─ continue             → generate_infrastructure
      → generate_infrastructure
      → safety_check
      → approve_deploy (interactive checkpoint #2)
      → [conditional: dry_run / unsafe / user_rejected / proceed]
         ├─ dry_run=True          → generate_report → END
         ├─ deploy_status=unsafe  → generate_report → END
         ├─ user_rejected         → generate_report → END
         └─ else                  → deploy_infrastructure
      → [conditional: deploy result]
         ├─ success               → execute_simulator
         ├─ failed & retries < 3  → generate_infrastructure → safety_check (re-validated) → deploy
         └─ retries >= 3          → teardown_on_failure → generate_report → END
      → execute_simulator
      → validator
      → confirm_teardown (interactive checkpoint #3)
      → [conditional: skip_teardown / proceed]
         ├─ skip_teardown         → generate_report → END
         └─ else                  → teardown
      → teardown
      → erasure_validator   ← verifies all cloud resources were fully destroyed
      → generate_report
      → END

NOTE: On every deploy retry, the AI-regenerated Terraform code is
re-checked by safety_check before it reaches deploy_infrastructure
again. This ensures that AI self-corrections don't introduce
safety violations.

NOTE: When --interactive is enabled, three human checkpoints are
inserted into the flow. In non-interactive mode they pass through
without blocking.
"""

from __future__ import annotations

from typing import Any, Literal

from langgraph.graph import END, START, StateGraph

from azure_cortex_orchestrator.human_intervention import (
    approve_deploy,
    confirm_teardown,
    review_plan,
)
from azure_cortex_orchestrator.nodes import (
    deploy_infrastructure,
    erasure_validator,
    execute_simulator,
    fetch_cobra_intel,
    fetch_mitre_intel,
    fetch_terraform_schema,
    generate_infrastructure,
    generate_report,
    generate_scenario,
    plan_attack,
    safety_check,
    teardown,
    validator,
)
from azure_cortex_orchestrator.state import OrchestratorState

MAX_DEPLOY_RETRIES = 3


# ── Conditional Edge Functions ────────────────────────────────────
def route_after_start(
    state: OrchestratorState,
) -> Literal["generate_scenario", "plan_attack"]:
    """
    Route at start:
    - If a free-text prompt is provided → generate_scenario first
    - Otherwise → go directly to plan_attack (existing behavior)
    """
    if state.get("prompt", "").strip():
        return "generate_scenario"
    return "plan_attack"

def route_after_review_plan(
    state: OrchestratorState,
) -> Literal["fetch_terraform_schema", "plan_attack", "generate_report"]:
    """
    Route after review_plan checkpoint:
    - If user aborted → skip to report
    - If user requested replan → loop back to plan_attack
    - Otherwise → fetch live terraform schema then generate_infrastructure
    """
    if state.get("user_aborted", False):
        return "generate_report"

    if state.get("replan_requested", False):
        return "plan_attack"

    return "fetch_terraform_schema"


def route_after_approve_deploy(
    state: OrchestratorState,
) -> Literal["deploy_infrastructure", "generate_report"]:
    """
    Route after approve_deploy checkpoint:
    - If dry_run → skip to report
    - If unsafe → skip to report (with violations in state)
    - If user rejected → skip to report
    - Otherwise → proceed to deploy
    """
    if state.get("dry_run", False):
        return "generate_report"

    if state.get("deploy_status") in ("unsafe", "user_rejected"):
        return "generate_report"

    if state.get("user_aborted", False):
        return "generate_report"

    return "deploy_infrastructure"


def route_after_deploy(
    state: OrchestratorState,
) -> Literal["execute_simulator", "generate_infrastructure", "teardown"]:
    """
    Route after deploy_infrastructure:
    - If success → proceed to simulator
    - If failed and retries < max → retry by looping back to generate_infrastructure
    - If retries exhausted → teardown (abort)
    """
    deploy_status = state.get("deploy_status", "pending")
    deploy_retries = state.get("deploy_retries", 0)

    if deploy_status == "success":
        return "execute_simulator"

    if deploy_status == "failed" and deploy_retries < MAX_DEPLOY_RETRIES:
        return "generate_infrastructure"

    # Retries exhausted or other failure — abort via teardown
    return "teardown"


def route_after_confirm_teardown(
    state: OrchestratorState,
) -> Literal["teardown", "generate_report"]:
    """
    Route after confirm_teardown checkpoint:
    - If user chose to keep infra → skip to report (no teardown)
    - Otherwise → proceed with teardown
    """
    if state.get("skip_teardown", False):
        return "generate_report"

    return "teardown"


# ── Graph Builder ─────────────────────────────────────────────────

def build_graph() -> StateGraph:
    """
    Construct and compile the LangGraph StateGraph.

    Returns:
        A compiled graph ready to be invoked with an initial state.
    """
    graph = StateGraph(OrchestratorState)

    # ── Add nodes ─────────────────────────────────────────────────
    graph.add_node("fetch_cobra_intel", fetch_cobra_intel)
    graph.add_node("fetch_mitre_intel", fetch_mitre_intel)
    graph.add_node("fetch_terraform_schema", fetch_terraform_schema)
    graph.add_node("generate_scenario", generate_scenario)
    graph.add_node("plan_attack", plan_attack)
    graph.add_node("review_plan", review_plan)
    graph.add_node("generate_infrastructure", generate_infrastructure)
    graph.add_node("safety_check", safety_check)
    graph.add_node("approve_deploy", approve_deploy)
    graph.add_node("deploy_infrastructure", deploy_infrastructure)
    graph.add_node("execute_simulator", execute_simulator)
    graph.add_node("validator", validator)
    graph.add_node("confirm_teardown", confirm_teardown)
    graph.add_node("teardown", teardown)
    graph.add_node("erasure_validator", erasure_validator)
    graph.add_node("generate_report", generate_report)

    # ── Add edges ─────────────────────────────────────────────────

    # START → fetch_cobra_intel → fetch_mitre_intel (both run before planning)
    graph.add_edge(START, "fetch_cobra_intel")
    graph.add_edge("fetch_cobra_intel", "fetch_mitre_intel")

    # fetch_mitre_intel → conditional: prompt mode or scenario mode
    graph.add_conditional_edges(
        "fetch_mitre_intel",
        route_after_start,
        {
            "generate_scenario": "generate_scenario",
            "plan_attack": "plan_attack",
        },
    )

    # generate_scenario → plan_attack
    graph.add_edge("generate_scenario", "plan_attack")

    # plan_attack → review_plan checkpoint
    graph.add_edge("plan_attack", "review_plan")

    # Conditional: after review_plan → fetch schema then infra, replan, or abort
    graph.add_conditional_edges(
        "review_plan",
        route_after_review_plan,
        {
            "fetch_terraform_schema": "fetch_terraform_schema",
            "plan_attack": "plan_attack",
            "generate_report": "generate_report",
        },
    )

    # fetch_terraform_schema → generate_infrastructure (always)
    graph.add_edge("fetch_terraform_schema", "generate_infrastructure")

    # generate_infrastructure → safety_check → approve_deploy checkpoint
    graph.add_edge("generate_infrastructure", "safety_check")
    graph.add_edge("safety_check", "approve_deploy")

    # Conditional: after approve_deploy → deploy or report
    graph.add_conditional_edges(
        "approve_deploy",
        route_after_approve_deploy,
        {
            "deploy_infrastructure": "deploy_infrastructure",
            "generate_report": "generate_report",
        },
    )

    # Conditional: after deploy → simulator, retry, or abort
    graph.add_conditional_edges(
        "deploy_infrastructure",
        route_after_deploy,
        {
            "execute_simulator": "execute_simulator",
            "generate_infrastructure": "generate_infrastructure",
            "teardown": "teardown",
        },
    )

    # simulator → validator → confirm_teardown checkpoint
    graph.add_edge("execute_simulator", "validator")
    graph.add_edge("validator", "confirm_teardown")

    # Conditional: after confirm_teardown → teardown or skip to report
    graph.add_conditional_edges(
        "confirm_teardown",
        route_after_confirm_teardown,
        {
            "teardown": "teardown",
            "generate_report": "generate_report",
        },
    )

    # teardown → erasure_validator → report → END
    graph.add_edge("teardown", "erasure_validator")
    graph.add_edge("erasure_validator", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def compile_graph():
    """Build and compile the graph, returning a runnable."""
    graph = build_graph()
    return graph.compile()
