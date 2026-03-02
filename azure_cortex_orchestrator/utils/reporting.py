"""
Report generation utilities for Azure-Cortex Orchestrator.

Produces structured Markdown and JSON reports from the final
orchestration state.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from azure_cortex_orchestrator.state import OrchestratorState
from azure_cortex_orchestrator.utils.observability import get_logger

logger = get_logger("reporting")


class ReportGenerator:
    """
    Generates Markdown and JSON reports from the orchestrator state.

    Reports are saved to ``{reports_dir}/{run_id}/``.
    """

    def __init__(self, reports_dir: Path) -> None:
        self.reports_dir = reports_dir

    def generate(self, state: OrchestratorState) -> tuple[str, str]:
        """
        Generate both Markdown and JSON reports.

        Args:
            state: Final orchestrator state after graph execution.

        Returns:
            Tuple of (markdown_content, report_directory_path).
        """
        run_id = state.get("run_id", "unknown")
        report_dir = self.reports_dir / run_id
        report_dir.mkdir(parents=True, exist_ok=True)

        md = self._generate_markdown(state)
        json_data = self._generate_json(state)

        # Write files
        md_path = report_dir / "report.md"
        json_path = report_dir / "report.json"
        md_path.write_text(md, encoding="utf-8")
        json_path.write_text(json.dumps(json_data, indent=2, default=str), encoding="utf-8")

        logger.info("Reports written to %s", report_dir)
        return md, str(report_dir)

    def _generate_markdown(self, state: OrchestratorState) -> str:
        """Build the Markdown report."""
        lines: list[str] = []

        run_id = state.get("run_id", "unknown")
        goal = state.get("goal", "N/A")
        scenario_id = state.get("scenario_id", "N/A")
        dry_run = state.get("dry_run", False)
        attack_plan = state.get("attack_plan", {})
        deploy_status = state.get("deploy_status", "N/A")
        deploy_retries = state.get("deploy_retries", 0)
        safety_violations = state.get("safety_violations", [])
        simulation_results = state.get("simulation_results", [])
        validation_result = state.get("validation_result", {})

        # ── Header ────────────────────────────────────────────────
        lines.append("# Azure-Cortex Orchestrator — Simulation Report")
        lines.append("")
        lines.append(f"**Run ID:** `{run_id}`  ")
        lines.append(f"**Generated:** {datetime.now(timezone.utc).isoformat()}  ")
        lines.append(f"**Scenario:** {scenario_id}  ")
        lines.append(f"**Dry Run:** {dry_run}  ")
        lines.append("")

        # ── Executive Summary ─────────────────────────────────────
        lines.append("## Executive Summary")
        lines.append("")
        detected = validation_result.get("detected")
        if dry_run:
            lines.append("This was a **dry-run** execution. No cloud resources were deployed.")
        elif detected is True:
            lines.append(
                "The simulated attack **was detected** by the defense layer. "
                f"Detection source: **{validation_result.get('source', 'N/A')}**."
            )
        elif detected is False:
            lines.append(
                "The simulated attack **was NOT detected**. "
                "This indicates a gap in the defense coverage."
            )
        else:
            lines.append(f"Deployment status: **{deploy_status}**. Simulation may not have run.")
        lines.append("")

        # ── Attack Goal ───────────────────────────────────────────
        lines.append("## Attack Goal")
        lines.append("")
        lines.append(f"> {goal}")
        lines.append("")

        # ── MITRE ATT&CK Mapping ─────────────────────────────────
        lines.append("## MITRE ATT&CK Mapping")
        lines.append("")
        techniques = attack_plan.get("mitre_techniques", [])
        if techniques:
            lines.append("| Technique ID | Name | Tactic | Description |")
            lines.append("|---|---|---|---|")
            for tech in techniques:
                tid = tech.get("id", "?")
                name = tech.get("name", "?")
                tactic = tech.get("tactic", "?")
                desc = tech.get("description", "")[:100]
                lines.append(f"| {tid} | {name} | {tactic} | {desc} |")
        else:
            lines.append("*No ATT&CK techniques mapped.*")
        lines.append("")

        # ── Attack Steps ──────────────────────────────────────────
        steps = attack_plan.get("steps", [])
        if steps:
            lines.append("## Attack Steps")
            lines.append("")
            for step in steps:
                num = step.get("step_number", "?")
                desc = step.get("description", "")
                technique = step.get("mitre_technique_id", "")
                lines.append(f"{num}. **{desc}**")
                if technique:
                    lines.append(f"   - MITRE: `{technique}`")
            lines.append("")

        # ── Infrastructure ────────────────────────────────────────
        lines.append("## Infrastructure")
        lines.append("")
        lines.append(f"- **Deploy Status:** {deploy_status}")
        lines.append(f"- **Retries:** {deploy_retries}")
        if safety_violations:
            lines.append("- **Safety Violations:**")
            for v in safety_violations:
                lines.append(f"  - ⚠️ {v}")
        lines.append("")
        tf_code = state.get("terraform_code", "")
        if tf_code:
            lines.append("<details><summary>Terraform Code (click to expand)</summary>")
            lines.append("")
            lines.append("```hcl")
            lines.append(tf_code)
            lines.append("```")
            lines.append("</details>")
            lines.append("")

        # ── Simulation Timeline ───────────────────────────────────
        lines.append("## Simulation Timeline")
        lines.append("")
        if simulation_results:
            lines.append("| Timestamp | Action | Target | Result | Details |")
            lines.append("|---|---|---|---|---|")
            for action in simulation_results:
                ts = action.get("timestamp", "")
                act = action.get("action", "")
                target = action.get("target_resource", "")
                result = action.get("result", "")
                details = action.get("details", "")[:80]
                lines.append(f"| {ts} | {act} | {target} | {result} | {details} |")
        else:
            lines.append("*No simulation actions recorded.*")
        lines.append("")

        # ── Detection Results ─────────────────────────────────────
        lines.append("## Detection Results")
        lines.append("")
        if validation_result:
            lines.append(f"- **Detected:** {validation_result.get('detected', 'N/A')}")
            lines.append(f"- **Source:** {validation_result.get('source', 'N/A')}")
            lines.append(f"- **Confidence:** {validation_result.get('confidence', 'N/A')}")
            lines.append(f"- **Details:** {validation_result.get('details', 'N/A')}")
        else:
            lines.append("*No validation performed.*")
        lines.append("")

        # ── Footer ────────────────────────────────────────────────
        lines.append("---")
        lines.append("*Generated by Azure-Cortex Orchestrator*")
        lines.append("")

        return "\n".join(lines)

    def _generate_json(self, state: OrchestratorState) -> dict[str, Any]:
        """Build the JSON report data."""
        return {
            "metadata": {
                "run_id": state.get("run_id", ""),
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "scenario_id": state.get("scenario_id", ""),
                "dry_run": state.get("dry_run", False),
            },
            "goal": state.get("goal", ""),
            "attack_plan": state.get("attack_plan", {}),
            "infrastructure": {
                "deploy_status": state.get("deploy_status", ""),
                "deploy_retries": state.get("deploy_retries", 0),
                "safety_violations": state.get("safety_violations", []),
                "terraform_code": state.get("terraform_code", ""),
            },
            "simulation_results": state.get("simulation_results", []),
            "validation_result": state.get("validation_result", {}),
        }
