"""
Orchestrator service — wraps the LangGraph execution for UI streaming.

Provides:
- run_simulation(): Full graph-based streaming (non-interactive).
- run_phase(): Execute a list of node functions directly, yielding
  NodeEvent objects. Used by the dashboard for phased interactive mode
  where the UI pauses at checkpoints for user input.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Generator

# Ensure the project root is importable
_project_root = Path(__file__).resolve().parent.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from azure_cortex_orchestrator.state import OrchestratorState, create_initial_state
from azure_cortex_orchestrator.graph import MAX_DEPLOY_RETRIES
from azure_cortex_orchestrator.nodes import (
    fetch_cobra_intel,
    generate_scenario,
    plan_attack,
    generate_infrastructure,
    safety_check,
    deploy_infrastructure,
    execute_simulator,
    validator,
    teardown,
    erasure_validator,
    generate_report,
)


# ── Pipeline node ordering (for UI rendering) ────────────────────

PIPELINE_NODES = [
    {"id": "fetch_cobra_intel",       "label": "Cobra Intel",         "icon": "🔍", "description": "Fetch live attack intel from cobra-tool repo"},
    {"id": "generate_scenario",       "label": "Generate Scenario",   "icon": "🤖", "description": "AI generates scenario from free-text prompt"},
    {"id": "plan_attack",             "label": "Plan Attack",         "icon": "📋", "description": "Map attack to MITRE ATT&CK techniques"},
    {"id": "review_plan",             "label": "Review Plan",         "icon": "👁️",  "description": "Human checkpoint — review attack plan"},
    {"id": "generate_infrastructure", "label": "Generate Infra",      "icon": "🏗️",  "description": "AI generates Terraform infrastructure code"},
    {"id": "safety_check",            "label": "Safety Check",        "icon": "🛡️",  "description": "Validate Terraform against safety guardrails"},
    {"id": "approve_deploy",          "label": "Approve Deploy",      "icon": "✅", "description": "Human checkpoint — approve deployment"},
    {"id": "deploy_infrastructure",   "label": "Deploy",              "icon": "🚀", "description": "Terraform apply — create cloud resources"},
    {"id": "execute_simulator",       "label": "Execute Attack",      "icon": "⚔️",  "description": "Run attack simulation via cloud SDK"},
    {"id": "validator",               "label": "Validate Detection",  "icon": "🔎", "description": "Check if Cortex XDR detected the attack"},
    {"id": "confirm_teardown",        "label": "Confirm Teardown",    "icon": "🗑️",  "description": "Human checkpoint — confirm resource cleanup"},
    {"id": "teardown",                "label": "Teardown",            "icon": "💥", "description": "Terraform destroy — remove all resources"},
    {"id": "erasure_validator",       "label": "Verify Erasure",      "icon": "🧹", "description": "Verify all cloud resources were destroyed"},
    {"id": "generate_report",         "label": "Generate Report",     "icon": "📊", "description": "Create Markdown + JSON + ATT&CK Navigator report"},
]

NODE_LABELS = {n["id"]: n for n in PIPELINE_NODES}


# ── Node function registry (for direct invocation) ───────────────

NODE_FUNCTIONS: dict[str, Any] = {
    "fetch_cobra_intel": fetch_cobra_intel,
    "generate_scenario": generate_scenario,
    "plan_attack": plan_attack,
    "generate_infrastructure": generate_infrastructure,
    "safety_check": safety_check,
    "deploy_infrastructure": deploy_infrastructure,
    "execute_simulator": execute_simulator,
    "validator": validator,
    "teardown": teardown,
    "erasure_validator": erasure_validator,
    "generate_report": generate_report,
}


@dataclass
class NodeEvent:
    """Event emitted for each graph node during streaming."""

    node_name: str
    status: str          # "started" | "completed" | "failed" | "skipped"
    output: dict = field(default_factory=dict)
    duration_ms: float = 0.0
    error: str = ""


# ── Phased execution (for interactive dashboard) ─────────────────

def run_phase(
    node_names: list[str],
    state: dict[str, Any],
) -> Generator[NodeEvent, None, None]:
    """
    Execute a list of node functions directly (bypassing the LangGraph
    graph), yielding a NodeEvent for each.

    The ``state`` dict is mutated in-place with each node's output so
    that subsequent nodes see prior results.

    Args:
        node_names: Ordered list of node IDs to execute.
        state: Mutable accumulated state dict.

    Yields:
        NodeEvent for each node.
    """
    for node_name in node_names:
        fn = NODE_FUNCTIONS.get(node_name)
        if fn is None:
            continue
        t0 = time.perf_counter()
        try:
            output = fn(state) or {}
            if isinstance(output, dict):
                state.update(output)
            duration = (time.perf_counter() - t0) * 1000.0
            yield NodeEvent(
                node_name=node_name,
                status="completed",
                output=output if isinstance(output, dict) else {},
                duration_ms=duration,
            )
        except Exception as exc:
            duration = (time.perf_counter() - t0) * 1000.0
            yield NodeEvent(
                node_name=node_name,
                status="failed",
                output={},
                duration_ms=duration,
                error=str(exc),
            )
            break


# ── Full graph execution (non-interactive) ───────────────────────

def run_simulation(
    *,
    scenario_id: str = "",
    goal: str = "",
    prompt: str = "",
    dry_run: bool = True,
    interactive: bool = False,
) -> Generator[NodeEvent | dict, None, None]:
    """
    Execute the orchestration graph and yield NodeEvent objects.

    The final yield is the accumulated state dict (the full result).
    """
    from azure_cortex_orchestrator.graph import compile_graph

    compiled = compile_graph()

    if prompt:
        initial_state = create_initial_state(
            goal=prompt,
            scenario_id=scenario_id or "custom",
            dry_run=dry_run,
            interactive=interactive,
            prompt=prompt,
        )
    else:
        initial_state = create_initial_state(
            goal=goal,
            scenario_id=scenario_id,
            dry_run=dry_run,
            interactive=interactive,
        )

    final_state: dict[str, Any] = dict(initial_state)

    try:
        t0 = time.perf_counter()
        for event in compiled.stream(initial_state, stream_mode="updates"):
            for node_name, node_output in event.items():
                duration = (time.perf_counter() - t0) * 1000.0
                # Merge output into accumulated state
                if isinstance(node_output, dict):
                    final_state.update(node_output)

                yield NodeEvent(
                    node_name=node_name,
                    status="completed",
                    output=node_output if isinstance(node_output, dict) else {},
                    duration_ms=duration,
                )
            t0 = time.perf_counter()
    except Exception as exc:
        yield NodeEvent(
            node_name="__error__",
            status="failed",
            error=str(exc),
        )

    # Final yield: the accumulated state
    yield final_state
