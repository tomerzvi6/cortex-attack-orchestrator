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
        navigator_layer = self._generate_attack_navigator_layer(state)

        # Write files
        md_path = report_dir / "report.md"
        json_path = report_dir / "report.json"
        nav_path = report_dir / "attack_navigator_layer.json"
        md_path.write_text(md, encoding="utf-8")
        json_path.write_text(json.dumps(json_data, indent=2, default=str), encoding="utf-8")
        nav_path.write_text(json.dumps(navigator_layer, indent=2, default=str), encoding="utf-8")

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

        # ── Self-Healing Attempts ─────────────────────────────────
        deploy_error_history = state.get("deploy_error_history", [])
        lines.append("## Self-Healing Attempts")
        lines.append("")
        if deploy_error_history:
            if deploy_retries > 0:
                lines.append(
                    f"**{deploy_retries}** AI-assisted fix attempt(s) were made "
                    "to resolve Terraform deployment errors."
                )
                lines.append("")
            for idx, err in enumerate(deploy_error_history, start=1):
                lines.append(f"{idx}. `{err}`")
        else:
            lines.append("*No self-healing attempts were needed.*")
        lines.append("")

        # ── LLM Observability ─────────────────────────────────────
        llm_usage = state.get("llm_usage", [])
        lines.append("## LLM Observability")
        lines.append("")
        if llm_usage:
            total_tokens_all = sum(r.get("total_tokens", 0) for r in llm_usage)
            total_cost_all = sum(r.get("estimated_cost_usd", 0.0) for r in llm_usage)
            total_duration_all = sum(r.get("duration_ms", 0.0) for r in llm_usage)
            lines.append(
                f"**{len(llm_usage)}** LLM call(s) — "
                f"**{total_tokens_all:,}** total tokens — "
                f"**${total_cost_all:.4f}** estimated cost — "
                f"**{total_duration_all:,.0f} ms** total latency"
            )
            lines.append("")
            lines.append("| Node | Model | Prompt Tokens | Completion Tokens | Total | Cost (USD) | Latency |")
            lines.append("|---|---|---:|---:|---:|---:|---|")
            for r in llm_usage:
                lines.append(
                    f"| {r.get('node', '?')} "
                    f"| {r.get('model', '?')} "
                    f"| {r.get('prompt_tokens', 0):,} "
                    f"| {r.get('completion_tokens', 0):,} "
                    f"| {r.get('total_tokens', 0):,} "
                    f"| ${r.get('estimated_cost_usd', 0.0):.4f} "
                    f"| {r.get('duration_ms', 0.0):,.0f} ms |"
                )
        else:
            lines.append("*No LLM calls were recorded.*")
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

        # ── Risk Assessment ───────────────────────────────────────
        lines.append("## Risk Assessment")
        lines.append("")
        if dry_run:
            lines.append(
                "ℹ️ DRY RUN — No risk assessment available. "
                "Run without `--dry-run` to evaluate detection coverage."
            )
        elif detected is True:
            lines.append(
                "✅ LOW RISK — The defense layer successfully detected "
                "the simulated attack."
            )
        elif detected is False:
            lines.append(
                "🚨 HIGH RISK — The simulated attack was NOT detected. "
                "Recommended actions:"
            )
            lines.append("")
            lines.append(
                "- Configure alert rules for the operations listed above"
            )
            lines.append(
                "- Enable Cortex XDR cloud module for this subscription"
            )
            lines.append(
                "- Review CSPM policies for the misconfiguration types exploited"
            )
        else:
            lines.append("*Risk assessment unavailable — simulation may not have completed.*")
        lines.append("")

        # ── ATT&CK Navigator ─────────────────────────────────────
        lines.append("## ATT&CK Navigator")
        lines.append("")
        lines.append(
            "An ATT&CK Navigator layer file has been generated at "
            "`attack_navigator_layer.json`. "
            "Import it at <https://mitre-attack.github.io/attack-navigator/> "
            "to visualize coverage."
        )
        lines.append("")

        # ── Footer ────────────────────────────────────────────────
        lines.append("---")
        lines.append("*Generated by Azure-Cortex Orchestrator*")
        lines.append("")

        return "\n".join(lines)

    def _llm_usage_summary(self, state: OrchestratorState) -> dict[str, Any]:
        """Compute aggregate LLM usage statistics for the JSON report."""
        llm_usage = state.get("llm_usage", [])
        if not llm_usage:
            return {
                "total_calls": 0,
                "total_tokens": 0,
                "total_prompt_tokens": 0,
                "total_completion_tokens": 0,
                "total_estimated_cost_usd": 0.0,
                "total_duration_ms": 0.0,
            }
        return {
            "total_calls": len(llm_usage),
            "total_tokens": sum(r.get("total_tokens", 0) for r in llm_usage),
            "total_prompt_tokens": sum(r.get("prompt_tokens", 0) for r in llm_usage),
            "total_completion_tokens": sum(r.get("completion_tokens", 0) for r in llm_usage),
            "total_estimated_cost_usd": round(
                sum(r.get("estimated_cost_usd", 0.0) for r in llm_usage), 6,
            ),
            "total_duration_ms": round(
                sum(r.get("duration_ms", 0.0) for r in llm_usage), 2,
            ),
        }

    def _generate_attack_navigator_layer(self, state: OrchestratorState) -> dict[str, Any]:
        """
        Produce a JSON structure compatible with MITRE ATT&CK Navigator.

        Technique colour indicates detection outcome:
        - ``#ff6666`` (red)  — attack was **not** detected (gap)
        - ``#66ff66`` (green) — attack was detected
        """
        attack_plan = state.get("attack_plan", {})
        validation_result = state.get("validation_result", {})
        detected = validation_result.get("detected", False)

        techniques = []
        for technique in attack_plan.get("mitre_techniques", []):
            techniques.append({
                "techniqueID": technique.get("id", ""),
                "tactic": technique.get("tactic", "").lower().replace(" ", "-"),
                "color": "#66ff66" if detected else "#ff6666",
                "comment": technique.get("description", ""),
                "enabled": True,
                "score": 50 if detected else 100,
            })

        return {
            "name": f"Cortex Simulation - {state.get('scenario_id', '')}",
            "versions": {
                "attack": "14",
                "navigator": "4.9.1",
                "layer": "4.5",
            },
            "domain": "enterprise-attack",
            "description": f"Attack simulation run {state.get('run_id', '')}",
            "techniques": techniques,
        }

    def _generate_json(self, state: OrchestratorState) -> dict[str, Any]:
        """Build the JSON report data."""
        dry_run = state.get("dry_run", False)
        validation_result = state.get("validation_result", {})
        detected = validation_result.get("detected")

        if dry_run:
            risk_level = "dry_run"
        elif detected is True:
            risk_level = "low"
        elif detected is False:
            risk_level = "high"
        else:
            risk_level = "unknown"

        return {
            "metadata": {
                "run_id": state.get("run_id", ""),
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "scenario_id": state.get("scenario_id", ""),
                "dry_run": dry_run,
            },
            "goal": state.get("goal", ""),
            "attack_plan": state.get("attack_plan", {}),
            "infrastructure": {
                "deploy_status": state.get("deploy_status", ""),
                "deploy_retries": state.get("deploy_retries", 0),
                "deploy_error_history": state.get("deploy_error_history", []),
                "safety_violations": state.get("safety_violations", []),
                "terraform_code": state.get("terraform_code", ""),
            },
            "simulation_results": state.get("simulation_results", []),
            "validation_result": validation_result,
            "llm_usage": {
                "calls": state.get("llm_usage", []),
                "summary": self._llm_usage_summary(state),
            },
            "risk_level": risk_level,
            "attack_navigator_layer": self._generate_attack_navigator_layer(state),
        }
