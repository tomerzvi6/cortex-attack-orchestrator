"""
LangGraph graph construction for the Azure-Cortex Orchestrator.

Defines the StateGraph with all nodes and conditional edges:

    START
      → plan_attack
      → generate_infrastructure
      → safety_check
      → [conditional: dry_run / unsafe / proceed]
         ├─ dry_run=True          → generate_report → END
         ├─ deploy_status=unsafe  → generate_report → END
         └─ else                  → deploy_infrastructure
      → [conditional: deploy result]
         ├─ success               → execute_simulator
         ├─ failed & retries < 3  → generate_infrastructure → safety_check (re-validated) → deploy
         └─ retries >= 3          → teardown_on_failure → generate_report → END
      → execute_simulator
      → validator
      → teardown
      → erasure_validator   ← verifies all cloud resources were fully destroyed
      → generate_report
      → END

NOTE: On every deploy retry, the AI-regenerated Terraform code is
re-checked by safety_check before it reaches deploy_infrastructure
again. This ensures that AI self-corrections don't introduce
safety violations.
"""

from __future__ import annotations

from typing import Any, Literal

from langgraph.graph import END, START, StateGraph

from azure_cortex_orchestrator.nodes import (
    deploy_infrastructure,
    erasure_validator,
    execute_simulator,
    generate_infrastructure,
    generate_report,
    plan_attack,
    safety_check,
    teardown,
    validator,
)
from azure_cortex_orchestrator.state import OrchestratorState

MAX_DEPLOY_RETRIES = 3


# ── Conditional Edge Functions ────────────────────────────────────

def route_after_safety(
    state: OrchestratorState,
) -> Literal["deploy_infrastructure", "generate_report"]:
    """
    Route after safety_check:
    - If dry_run → skip to report
    - If unsafe → skip to report (with violations in state)
    - Otherwise → proceed to deploy
    """
    if state.get("dry_run", False):
        return "generate_report"

    if state.get("deploy_status") == "unsafe":
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


# ── Graph Builder ─────────────────────────────────────────────────

def build_graph() -> StateGraph:
    """
    Construct and compile the LangGraph StateGraph.

    Returns:
        A compiled graph ready to be invoked with an initial state.
    """
    graph = StateGraph(OrchestratorState)

    # ── Add nodes ─────────────────────────────────────────────────
    graph.add_node("plan_attack", plan_attack)
    graph.add_node("generate_infrastructure", generate_infrastructure)
    graph.add_node("safety_check", safety_check)
    graph.add_node("deploy_infrastructure", deploy_infrastructure)
    graph.add_node("execute_simulator", execute_simulator)
    graph.add_node("validator", validator)
    graph.add_node("teardown", teardown)
    graph.add_node("erasure_validator", erasure_validator)
    graph.add_node("generate_report", generate_report)

    # ── Add edges ─────────────────────────────────────────────────

    # Linear flow: START → plan → generate → safety
    graph.add_edge(START, "plan_attack")
    graph.add_edge("plan_attack", "generate_infrastructure")
    graph.add_edge("generate_infrastructure", "safety_check")

    # Conditional: after safety → deploy or report (dry-run / unsafe)
    graph.add_conditional_edges(
        "safety_check",
        route_after_safety,
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

    # Linear flow: simulator → validator → teardown → erasure_validator → report → END
    graph.add_edge("execute_simulator", "validator")
    graph.add_edge("validator", "teardown")
    graph.add_edge("teardown", "erasure_validator")
    graph.add_edge("erasure_validator", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def compile_graph():
    """Build and compile the graph, returning a runnable."""
    graph = build_graph()
    return graph.compile()
