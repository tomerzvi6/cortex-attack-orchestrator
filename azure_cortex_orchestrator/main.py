"""
Azure-Cortex Orchestrator — Main Entry Point.

CLI interface for running cloud attack simulations using LangGraph.

Usage:
    python -m azure_cortex_orchestrator.main --scenario vm_identity_log_deletion
    python -m azure_cortex_orchestrator.main --dry-run --scenario vm_identity_log_deletion
    python -m azure_cortex_orchestrator.main --list-scenarios
    python -m azure_cortex_orchestrator.main --goal "Custom attack goal..." --scenario vm_identity_log_deletion
"""

from __future__ import annotations

import argparse
import sys
import uuid

from azure_cortex_orchestrator.config import ConfigError, load_settings
from azure_cortex_orchestrator.graph import compile_graph
from azure_cortex_orchestrator.scenarios.registry import ScenarioRegistry
from azure_cortex_orchestrator.state import create_initial_state
from azure_cortex_orchestrator.utils.observability import setup_logging


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="azure-cortex-orchestrator",
        description=(
            "Azure-Cortex Orchestrator — Agentic cloud attack simulation "
            "using LangGraph, Terraform, and Azure SDK."
        ),
    )
    parser.add_argument(
        "--scenario",
        type=str,
        default="vm_identity_log_deletion",
        help="Scenario ID from the registry (default: vm_identity_log_deletion)",
    )
    parser.add_argument(
        "--goal",
        type=str,
        default=None,
        help="Custom attack goal (overrides scenario default)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Skip cloud operations (deploy, simulate, validate, teardown)",
    )
    parser.add_argument(
        "--list-scenarios",
        action="store_true",
        default=False,
        help="List all registered scenarios and exit",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Override log level (default: from env or INFO)",
    )
    parser.add_argument(
        "--run-id",
        type=str,
        default=None,
        help="Custom run ID (default: auto-generated UUID)",
    )
    return parser.parse_args(argv)


def list_scenarios() -> None:
    """Print all registered scenarios and exit."""
    registry = ScenarioRegistry.get_instance()
    scenarios = registry.list_all()

    if not scenarios:
        print("No scenarios registered.")
        return

    print("\n" + "=" * 60)
    print("REGISTERED SCENARIOS")
    print("=" * 60)
    for s in scenarios:
        print(f"\n  ID:   {s.id}")
        print(f"  Name: {s.name}")
        print(f"  Desc: {s.description[:80]}...")
        techniques = ", ".join(t["id"] for t in s.expected_mitre_techniques)
        print(f"  ATT&CK: {techniques}")
    print("\n" + "=" * 60)


def main(argv: list[str] | None = None) -> int:
    """Main entry point."""
    args = parse_args(argv)

    # ── List scenarios mode ───────────────────────────────────────
    if args.list_scenarios:
        list_scenarios()
        return 0

    # ── Load configuration ────────────────────────────────────────
    try:
        settings = load_settings()
    except Exception as exc:
        print(f"ERROR: Failed to load configuration: {exc}", file=sys.stderr)
        return 1

    # Override log level from CLI if provided
    if args.log_level:
        settings.log_level = args.log_level

    # ── Validate configuration ────────────────────────────────────
    try:
        settings.validate(dry_run=args.dry_run)
    except ConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    # ── Generate run ID ───────────────────────────────────────────
    run_id = args.run_id or str(uuid.uuid4())

    # ── Initialize observability ──────────────────────────────────
    log = setup_logging(
        run_id=run_id,
        log_level=settings.log_level,
        reports_dir=settings.reports_dir,
    )

    log.info("=" * 60)
    log.info("Azure-Cortex Orchestrator starting")
    log.info("Run ID: %s", run_id)
    log.info("Scenario: %s", args.scenario)
    log.info("Dry Run: %s", args.dry_run)
    log.info("=" * 60)

    # ── Resolve scenario ──────────────────────────────────────────
    registry = ScenarioRegistry.get_instance()
    try:
        scenario = registry.get(args.scenario)
    except KeyError as exc:
        log.error("Scenario not found: %s", exc)
        print(f"ERROR: {exc}", file=sys.stderr)
        print("Use --list-scenarios to see available scenarios.", file=sys.stderr)
        return 1

    goal = args.goal or scenario.goal_template
    log.info("Attack goal: %s", goal)

    # ── Build initial state ───────────────────────────────────────
    initial_state = create_initial_state(
        goal=goal,
        scenario_id=args.scenario,
        dry_run=args.dry_run,
        run_id=run_id,
    )

    # ── Compile and run graph ─────────────────────────────────────
    log.info("Compiling LangGraph orchestration graph...")
    compiled_graph = compile_graph()

    log.info("Invoking graph...")
    try:
        final_state = compiled_graph.invoke(initial_state)
    except Exception as exc:
        log.error("Graph execution failed: %s", exc, exc_info=True)
        print(f"ERROR: Graph execution failed: {exc}", file=sys.stderr)
        return 1

    # ── Print results ─────────────────────────────────────────────
    report_path = final_state.get("report_path", "")
    deploy_status = final_state.get("deploy_status", "")
    validation_result = final_state.get("validation_result", {})

    print("\n" + "=" * 60)
    print("EXECUTION COMPLETE")
    print("=" * 60)
    print(f"  Run ID:        {run_id}")
    print(f"  Scenario:      {args.scenario}")
    print(f"  Dry Run:       {args.dry_run}")
    print(f"  Deploy Status: {deploy_status}")

    if validation_result:
        print(f"  Detected:      {validation_result.get('detected', 'N/A')}")
        print(f"  Source:        {validation_result.get('source', 'N/A')}")
        print(f"  Confidence:    {validation_result.get('confidence', 'N/A')}")

    safety = final_state.get("safety_violations", [])
    if safety:
        print(f"  Safety Issues: {len(safety)}")
        for v in safety:
            print(f"    - {v}")

    if report_path:
        print(f"\n  Report: {report_path}")

    print("=" * 60)

    log.info("Orchestration complete. Report at: %s", report_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
