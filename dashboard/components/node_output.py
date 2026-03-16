"""
Node output renderer — formats each pipeline node's output as styled HTML
for live display in the Pipeline Monitor during execution.
"""

from __future__ import annotations

import html as html_mod
from typing import Any

from dashboard.theme import COLORS


def render_node_output(node_name: str, output: dict[str, Any]) -> str | None:
    """
    Render a completed node's output as a styled HTML block.

    Returns None if the node has no meaningful output to display.
    """
    renderer = _RENDERERS.get(node_name)
    if renderer is None:
        return None
    result = renderer(output)
    if not result:
        return None
    return result


def _esc(text: str) -> str:
    return html_mod.escape(str(text))


# ── Cobra Intel ───────────────────────────────────────────────────

def _render_cobra_intel(output: dict) -> str | None:
    intel = output.get("cobra_intel")
    if not intel:
        return None
    summary = _esc(intel.get("summary", "No summary"))
    return _card("Cobra Intel", f"<div style='color:{COLORS['text']};font-size:0.85rem;'>{summary}</div>", "🔍")


# ── Generate Scenario ─────────────────────────────────────────────

def _render_generate_scenario(output: dict) -> str | None:
    scenario_id = output.get("scenario_id")
    goal = output.get("goal")
    if not scenario_id and not goal:
        return None
    parts = []
    if scenario_id:
        parts.append(f"<b>Scenario:</b> {_esc(scenario_id)}")
    if goal:
        parts.append(f"<b>Goal:</b> {_esc(goal)}")
    return _card("Generated Scenario", "<br>".join(parts), "🤖")


# ── Plan Attack ───────────────────────────────────────────────────

def _render_plan_attack(output: dict) -> str | None:
    plan = output.get("attack_plan", {})
    if not plan:
        return None

    parts = []

    # Summary
    summary = plan.get("summary", "")
    if summary:
        parts.append(
            f"<div style='color:{COLORS['text']};font-size:0.88rem;margin-bottom:10px;'>{_esc(summary)}</div>"
        )

    # MITRE Techniques
    techniques = plan.get("mitre_techniques", [])
    if techniques:
        parts.append(
            f"<div style='color:{COLORS['primary']};font-weight:600;font-size:0.85rem;"
            f"margin-bottom:6px;'>MITRE ATT&CK Techniques ({len(techniques)}):</div>"
        )
        for t in techniques:
            tid = _esc(t.get("id", ""))
            name = _esc(t.get("name", ""))
            tactic = _esc(t.get("tactic", ""))
            parts.append(
                f"<div style='display:flex;gap:8px;padding:3px 0;font-size:0.82rem;'>"
                f"<span style='color:{COLORS['info']};font-weight:600;min-width:90px;'>{tid}</span>"
                f"<span style='color:{COLORS['text']};'>{name}</span>"
                f"<span style='color:{COLORS['text_dim']};font-style:italic;'>({tactic})</span>"
                f"</div>"
            )

    # Attack Steps
    steps = plan.get("steps", [])
    if steps:
        parts.append(
            f"<div style='color:{COLORS['primary']};font-weight:600;font-size:0.85rem;"
            f"margin-top:10px;margin-bottom:6px;'>Attack Steps ({len(steps)}):</div>"
        )
        for s in steps:
            num = s.get("step_number", "?")
            desc = _esc(s.get("description", ""))
            tid = _esc(s.get("mitre_technique_id", ""))
            phase = _esc(s.get("kill_chain_phase", ""))
            tag = ""
            if tid:
                tag += f"<span style='color:{COLORS['info']};'>[{tid}]</span> "
            if phase:
                tag += f"<span style='color:{COLORS['text_dim']};'>({phase})</span>"
            parts.append(
                f"<div style='display:flex;gap:8px;padding:4px 0;border-left:2px solid {COLORS['primary']};"
                f"padding-left:10px;margin-bottom:2px;'>"
                f"<span style='color:{COLORS['primary']};font-weight:700;min-width:20px;'>{num}.</span>"
                f"<div style='font-size:0.82rem;'>"
                f"<div style='color:{COLORS['text']};'>{desc}</div>"
                f"<div style='font-size:0.75rem;margin-top:1px;'>{tag}</div>"
                f"</div></div>"
            )

    return _card("Attack Plan", "\n".join(parts), "📋")


# ── Generate Infrastructure ───────────────────────────────────────

def _render_generate_infrastructure(output: dict) -> str | None:
    tf_code = output.get("terraform_code", "")
    if not tf_code:
        return None
    # Show first 30 lines as preview
    lines = tf_code.strip().split("\n")
    preview = "\n".join(lines[:30])
    if len(lines) > 30:
        preview += f"\n\n... ({len(lines) - 30} more lines)"
    return _card(
        "Terraform Code",
        f"<pre style='background:{COLORS['surface_alt']};padding:10px;border-radius:6px;"
        f"font-size:0.78rem;overflow-x:auto;max-height:300px;overflow-y:auto;"
        f"border:1px solid {COLORS['border']};color:{COLORS['text']};margin:0;'>"
        f"{_esc(preview)}</pre>",
        "🏗️",
    )


# ── Safety Check ──────────────────────────────────────────────────

def _render_safety_check(output: dict) -> str | None:
    violations = output.get("safety_violations", [])
    status = output.get("deploy_status", "")
    if status == "unsafe":
        items = "".join(f"<li style='color:{COLORS['danger']};font-size:0.82rem;'>{_esc(v)}</li>" for v in violations)
        return _card(
            "Safety Check",
            f"<div style='color:{COLORS['danger']};font-weight:600;margin-bottom:6px;'>FAILED — Violations found:</div>"
            f"<ul style='margin:0;padding-left:20px;'>{items}</ul>",
            "🛡️",
        )
    return _card(
        "Safety Check",
        f"<div style='color:{COLORS['success']};font-weight:600;'>PASSED — No violations</div>",
        "🛡️",
    )


# ── Deploy ────────────────────────────────────────────────────────

def _render_deploy(output: dict) -> str | None:
    status = output.get("deploy_status", "")
    if status == "success":
        return _card(
            "Deployment",
            f"<div style='color:{COLORS['success']};font-weight:600;'>Infrastructure deployed successfully</div>",
            "🚀",
        )
    if status == "failed":
        err = _esc(output.get("deploy_error", "Unknown error"))
        return _card(
            "Deployment",
            f"<div style='color:{COLORS['danger']};font-weight:600;'>Deployment failed</div>"
            f"<div style='color:{COLORS['text_dim']};font-size:0.82rem;margin-top:4px;'>{err}</div>",
            "🚀",
        )
    return None


# ── Execute Attack ────────────────────────────────────────────────

def _render_execute_simulator(output: dict) -> str | None:
    results = output.get("simulation_results", [])
    if not results:
        return None
    parts = []
    for r in results:
        action = _esc(r.get("action", "?"))
        result = r.get("result", "unknown")
        target = _esc(r.get("target_resource", ""))
        color = COLORS["success"] if result == "success" else COLORS["danger"] if result == "failed" else COLORS["text_dim"]
        parts.append(
            f"<div style='display:flex;align-items:center;gap:8px;padding:3px 0;font-size:0.82rem;'>"
            f"<span style='color:{color};'>{'✓' if result == 'success' else '✗' if result == 'failed' else '•'}</span>"
            f"<span style='color:{COLORS['text']};font-weight:600;'>{action}</span>"
            f"<span style='color:{COLORS['text_dim']};'>{target}</span>"
            f"</div>"
        )
    return _card("Simulation Results", "\n".join(parts), "⚔️")


# ── Validator ─────────────────────────────────────────────────────

def _render_validator(output: dict) -> str | None:
    val = output.get("validation_result", {})
    if not val:
        return None
    detected = val.get("detected")
    if detected is True:
        source = _esc(val.get("source", "N/A"))
        conf = _esc(str(val.get("confidence", "N/A")))
        return _card(
            "Detection Verdict",
            f"<div style='color:{COLORS['success']};font-weight:700;font-size:0.95rem;'>DETECTED</div>"
            f"<div style='font-size:0.82rem;color:{COLORS['text_dim']};margin-top:4px;'>"
            f"Source: {source} | Confidence: {conf}</div>",
            "🎯",
        )
    if detected is False:
        return _card(
            "Detection Verdict",
            f"<div style='color:{COLORS['danger']};font-weight:700;font-size:0.95rem;'>NOT DETECTED</div>"
            f"<div style='font-size:0.82rem;color:{COLORS['text_dim']};margin-top:4px;'>Defense gap identified</div>",
            "🎯",
        )
    return None


# ── Erasure Validator ─────────────────────────────────────────────

def _render_erasure_validator(output: dict) -> str | None:
    result = output.get("erasure_result", {})
    if not result:
        return None
    erased = result.get("fully_erased", False)
    if erased:
        return _card(
            "Erasure Verification",
            f"<div style='color:{COLORS['success']};font-weight:600;'>All resources destroyed</div>",
            "🧹",
        )
    orphans = result.get("orphaned_resources", [])
    items = "".join(f"<li>{_esc(o)}</li>" for o in orphans[:5])
    return _card(
        "Erasure Verification",
        f"<div style='color:{COLORS['warning']};font-weight:600;'>Orphaned resources found:</div>"
        f"<ul style='margin:0;padding-left:20px;font-size:0.82rem;color:{COLORS['text_dim']};'>{items}</ul>",
        "🧹",
    )


# ── Generate Report ───────────────────────────────────────────────

def _render_generate_report(output: dict) -> str | None:
    path = output.get("report_path", "")
    if not path:
        return None
    return _card(
        "Report Generated",
        f"<div style='color:{COLORS['text']};font-size:0.85rem;'>Saved to: <code>{_esc(str(path))}</code></div>",
        "📊",
    )


# ── Card wrapper ──────────────────────────────────────────────────

def _card(title: str, body: str, icon: str) -> str:
    return (
        f"<div style='"
        f"background:{COLORS['surface']};border:1px solid {COLORS['border']};"
        f"border-radius:8px;padding:12px 16px;margin-bottom:8px;"
        f"border-left:3px solid {COLORS['primary']};'>"
        f"<div style='display:flex;align-items:center;gap:8px;margin-bottom:8px;'>"
        f"<span style='font-size:1.1rem;'>{icon}</span>"
        f"<span style='color:{COLORS['primary']};font-weight:700;font-size:0.9rem;'>{title}</span>"
        f"</div>"
        f"<div>{body}</div>"
        f"</div>"
    )


# ── Registry ──────────────────────────────────────────────────────

_RENDERERS: dict[str, Any] = {
    "fetch_cobra_intel": _render_cobra_intel,
    "generate_scenario": _render_generate_scenario,
    "plan_attack": _render_plan_attack,
    "generate_infrastructure": _render_generate_infrastructure,
    "safety_check": _render_safety_check,
    "deploy_infrastructure": _render_deploy,
    "execute_simulator": _render_execute_simulator,
    "validator": _render_validator,
    "erasure_validator": _render_erasure_validator,
    "generate_report": _render_generate_report,
}
