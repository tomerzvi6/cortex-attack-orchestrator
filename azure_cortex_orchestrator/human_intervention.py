"""
Human intervention checkpoints for the Azure-Cortex Orchestrator.

Provides interactive prompts at key decision points in the graph,
allowing the user to review, approve, modify, or abort the run.

Three checkpoints:
  1. review_plan      — After plan_attack, before generate_infrastructure
  2. approve_deploy   — After safety_check, before deploy_infrastructure
  3. confirm_teardown — After execute_simulator, before teardown
"""

from __future__ import annotations

import json
import textwrap
from typing import Any

from azure_cortex_orchestrator.state import OrchestratorState
from azure_cortex_orchestrator.utils.observability import get_logger, node_logger

logger = get_logger("human_intervention")

# ── Formatting helpers ────────────────────────────────────────────

_SEPARATOR = "=" * 60
_THIN_SEP = "-" * 60


def _prompt_user(prompt: str, valid_choices: list[str]) -> str:
    """
    Prompt the user for input, repeating until a valid choice is given.

    Args:
        prompt: Text to display.
        valid_choices: Accepted lowercase inputs (e.g. ["y", "n", "m"]).

    Returns:
        The user's choice (lowercase, stripped).
    """
    while True:
        try:
            answer = input(prompt).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted by user.")
            return "a"  # treat as abort
        if answer in valid_choices:
            return answer
        print(f"  Invalid choice '{answer}'. Please enter one of: {', '.join(valid_choices)}")


def _print_attack_plan(plan: dict[str, Any]) -> None:
    """Pretty-print the attack plan for human review."""
    print(f"\n{_SEPARATOR}")
    print("  ATTACK PLAN REVIEW")
    print(_SEPARATOR)

    print(f"\n  Goal:     {plan.get('goal', 'N/A')}")
    print(f"  Scenario: {plan.get('scenario_id', 'N/A')}")
    print(f"  Summary:  {plan.get('summary', 'N/A')}")

    techniques = plan.get("mitre_techniques", [])
    if techniques:
        print(f"\n  MITRE ATT&CK Techniques ({len(techniques)}):")
        for t in techniques:
            tid = t.get("id", "?")
            tname = t.get("name", t.get("technique_name", "?"))
            print(f"    - {tid}: {tname}")

    steps = plan.get("steps", [])
    if steps:
        print(f"\n  Attack Steps ({len(steps)}):")
        for s in steps:
            num = s.get("step_number", "?")
            desc = s.get("description", "N/A")
            technique = s.get("mitre_technique_id", "")
            phase = s.get("kill_chain_phase", "")
            extra = f" [{technique}]" if technique else ""
            extra += f" ({phase})" if phase else ""
            print(f"    {num}. {desc}{extra}")

    print(f"\n{_THIN_SEP}")


def _print_terraform_summary(state: OrchestratorState) -> None:
    """Print a summary of the Terraform code and safety results."""
    print(f"\n{_SEPARATOR}")
    print("  DEPLOYMENT APPROVAL")
    print(_SEPARATOR)

    terraform_code = state.get("terraform_code", "")
    safety_violations = state.get("safety_violations", [])

    # Count resources
    import re
    resource_count = len(re.findall(r'^resource\s+"', terraform_code, re.MULTILINE))
    data_count = len(re.findall(r'^data\s+"', terraform_code, re.MULTILINE))

    print(f"\n  Resources to create:  {resource_count}")
    print(f"  Data sources:         {data_count}")
    print(f"  Terraform code size:  {len(terraform_code)} chars")

    # Show resource types
    resource_types = re.findall(r'resource\s+"([^"]+)"', terraform_code)
    if resource_types:
        print(f"\n  Resource types:")
        for rt in sorted(set(resource_types)):
            count = resource_types.count(rt)
            print(f"    - {rt}" + (f" (x{count})" if count > 1 else ""))

    # Safety status
    if safety_violations:
        print(f"\n  ⚠ Safety violations ({len(safety_violations)}):")
        for v in safety_violations:
            print(f"    - {v}")
    else:
        print(f"\n  Safety check: PASSED (no violations)")

    # Show Terraform code preview (first 40 lines)
    if terraform_code:
        lines = terraform_code.splitlines()
        preview_lines = min(40, len(lines))
        print(f"\n  Terraform code preview (first {preview_lines} of {len(lines)} lines):")
        print(_THIN_SEP)
        for line in lines[:preview_lines]:
            print(f"  {line}")
        if len(lines) > preview_lines:
            print(f"  ... ({len(lines) - preview_lines} more lines)")
        print(_THIN_SEP)

    print()


def _print_simulation_summary(state: OrchestratorState) -> None:
    """Print simulation results before teardown decision."""
    print(f"\n{_SEPARATOR}")
    print("  TEARDOWN DECISION")
    print(_SEPARATOR)

    sim_results = state.get("simulation_results", [])
    validation = state.get("validation_result", {})

    print(f"\n  Simulation actions executed: {len(sim_results)}")
    for action in sim_results:
        status = action.get("result", "?")
        desc = action.get("action", "N/A")
        target = action.get("target_resource", "")
        marker = "+" if status == "success" else "x" if status == "failed" else "~"
        print(f"    [{marker}] {desc}" + (f" -> {target}" if target else ""))

    if validation:
        print(f"\n  Detection result:")
        print(f"    Detected:   {validation.get('detected', 'N/A')}")
        print(f"    Source:     {validation.get('source', 'N/A')}")
        print(f"    Confidence: {validation.get('confidence', 'N/A')}")

    tf_dir = state.get("terraform_working_dir", "")
    if tf_dir:
        print(f"\n  Terraform working dir: {tf_dir}")

    print(f"\n{_THIN_SEP}")


# ══════════════════════════════════════════════════════════════════
#  CHECKPOINT 1: Review Attack Plan
# ══════════════════════════════════════════════════════════════════

def review_plan(state: OrchestratorState) -> dict[str, Any]:
    """
    Checkpoint node: Let the user review the attack plan before
    proceeding to Terraform generation.

    Returns:
        State update. Sets ``user_aborted=True`` if the user chooses
        to abort, or ``goal`` if the user modifies it.
    """
    with node_logger("review_plan", state.get("run_id", "")) as log:
        # Skip if not interactive
        if not state.get("interactive", False):
            log.debug("Non-interactive mode — skipping plan review")
            return {}

        attack_plan = state.get("attack_plan", {})
        _print_attack_plan(attack_plan)

        print("  Options:")
        print("    [c] Continue — proceed to Terraform generation")
        print("    [m] Modify  — enter a new/refined attack goal")
        print("    [a] Abort   — stop the run")

        choice = _prompt_user("\n  Your choice (c/m/a): ", ["c", "m", "a"])

        if choice == "a":
            log.info("User aborted at plan review")
            print("\n  Run aborted by user.")
            return {"user_aborted": True}

        if choice == "m":
            print()
            try:
                new_goal = input("  Enter new/refined attack goal: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n  Aborted by user.")
                return {"user_aborted": True}

            if not new_goal:
                print("  Empty goal — keeping original.")
                log.info("User chose to modify but provided empty goal, continuing")
                return {}

            log.info("User modified goal to: %s", new_goal)
            print(f"  Goal updated. Will re-plan with: {new_goal}")
            return {"goal": new_goal, "replan_requested": True}

        log.info("User approved attack plan")
        print("  Continuing...")
        return {"replan_requested": False}


# ══════════════════════════════════════════════════════════════════
#  CHECKPOINT 2: Approve Deployment
# ══════════════════════════════════════════════════════════════════

def approve_deploy(state: OrchestratorState) -> dict[str, Any]:
    """
    Checkpoint node: Let the user review Terraform code and safety
    results before deploying real cloud resources.

    Returns:
        State update. Sets ``user_aborted=True`` to skip deployment.
    """
    with node_logger("approve_deploy", state.get("run_id", "")) as log:
        # Skip if not interactive
        if not state.get("interactive", False):
            log.debug("Non-interactive mode — skipping deploy approval")
            return {}

        # Skip if dry-run or already unsafe (will be routed to report anyway)
        if state.get("dry_run", False):
            log.debug("Dry-run mode — skipping deploy approval")
            return {}
        if state.get("deploy_status") == "unsafe":
            log.debug("Unsafe deploy — skipping approval (already blocked)")
            return {}

        _print_terraform_summary(state)

        print("  Options:")
        print("    [y] Yes   — deploy the infrastructure")
        print("    [n] No    — abort the run (no resources created)")
        print("    [v] View  — print full Terraform code, then decide")

        choice = _prompt_user("\n  Your choice (y/n/v): ", ["y", "n", "v"])

        if choice == "v":
            tf_code = state.get("terraform_code", "")
            print(f"\n{_SEPARATOR}")
            print("  FULL TERRAFORM CODE")
            print(_SEPARATOR)
            print(tf_code)
            print(_SEPARATOR)
            choice = _prompt_user("\n  Deploy? (y/n): ", ["y", "n"])

        if choice == "n":
            log.info("User rejected deployment")
            print("\n  Deployment rejected. Generating report...")
            return {"user_aborted": True, "deploy_status": "user_rejected"}

        log.info("User approved deployment")
        print("  Deploying...")
        return {}


# ══════════════════════════════════════════════════════════════════
#  CHECKPOINT 3: Confirm Teardown
# ══════════════════════════════════════════════════════════════════

def confirm_teardown(state: OrchestratorState) -> dict[str, Any]:
    """
    Checkpoint node: Let the user decide whether to tear down
    infrastructure immediately or keep it alive for inspection.

    Returns:
        State update. Sets ``skip_teardown=True`` to keep infra alive.
    """
    with node_logger("confirm_teardown", state.get("run_id", "")) as log:
        # Skip if not interactive
        if not state.get("interactive", False):
            log.debug("Non-interactive mode — skipping teardown confirmation")
            return {}

        # Skip if dry-run (nothing to tear down)
        if state.get("dry_run", False):
            log.debug("Dry-run mode — skipping teardown confirmation")
            return {}

        _print_simulation_summary(state)

        print("  Options:")
        print("    [t] Tear down  — destroy all cloud resources now")
        print("    [k] Keep alive — skip teardown (you must destroy manually later!)")

        choice = _prompt_user("\n  Your choice (t/k): ", ["t", "k"])

        if choice == "k":
            log.warning("User chose to keep infrastructure alive!")
            tf_dir = state.get("terraform_working_dir", "")
            print(f"\n  Infrastructure kept alive.")
            print(f"  To destroy manually later, run:")
            print(f"    cd {tf_dir}")
            print(f"    terraform destroy -auto-approve")
            print()
            return {"skip_teardown": True}

        log.info("User confirmed teardown")
        print("  Tearing down...")
        return {}
