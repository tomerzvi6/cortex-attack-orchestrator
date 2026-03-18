"""
🚀 Launch Mission — Configure and run attack simulations with a live pipeline monitor.

Supports full interactive mode with UI checkpoints:
  1. Review Plan   — continue / modify goal / abort
  2. Approve Deploy — approve / reject deployment
  3. Confirm Teardown — tear down / keep alive
"""

from __future__ import annotations

import re
import sys
import uuid
from pathlib import Path
from typing import Any

import streamlit as st

_project_root = Path(__file__).resolve().parent.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from dashboard.theme import COLORS, apply_theme, metric_card
from dashboard.components.pipeline_graph import render_pipeline
from dashboard.components.node_output import render_node_output
from dashboard.components.scenario_card import render_scenario_card
from dashboard.services.orchestrator import (
    PIPELINE_NODES,
    NODE_LABELS,
    NodeEvent,
    run_phase,
    run_simulation,
    MAX_DEPLOY_RETRIES,
)
from azure_cortex_orchestrator.scenarios.registry import ScenarioRegistry
from azure_cortex_orchestrator.state import create_initial_state
from azure_cortex_orchestrator.config import load_settings, ConfigError
from azure_cortex_orchestrator.utils.observability import setup_logging

apply_theme()

# ── Helpers ────────────────────────────────────────────────────────

_SS = st.session_state  # shorthand


def _init_session_state() -> None:
    """Ensure all session state keys exist."""
    defaults = {
        "sim_phase": "idle",
        "sim_state": {},
        "sim_events": [],
        "sim_config": {},
        "sim_node_statuses": {},
        "sim_node_durations": {},
        "sim_visible_nodes": [],
        "sim_error": None,
    }
    for k, v in defaults.items():
        if k not in _SS:
            _SS[k] = v


_init_session_state()


def _reset_sim() -> None:
    """Reset simulation state for a fresh run."""
    _SS.sim_phase = "idle"
    _SS.sim_state = {}
    _SS.sim_events = []
    _SS.sim_config = {}
    _SS.sim_node_statuses = {}
    _SS.sim_node_durations = {}
    _SS.sim_visible_nodes = []
    _SS.sim_error = None


def _visible_nodes(is_freeform: bool, dry_run: bool, interactive: bool) -> list[dict]:
    """Determine which pipeline nodes to show."""
    skip = set()
    if not is_freeform:
        skip.add("generate_scenario")
    if dry_run:
        skip.update([
            "deploy_infrastructure", "execute_simulator", "validator",
            "confirm_teardown", "teardown", "erasure_validator",
        ])
    if not interactive:
        skip.update(["review_plan", "approve_deploy", "confirm_teardown"])
    return [n for n in PIPELINE_NODES if n["id"] not in skip]


# ── Per-node hints shown while a node is executing ────────────────
_NODE_HINTS: dict[str, str] = {
    "fetch_cobra_intel":       "fetching live threat intel from GitHub...",
    "generate_scenario":       "AI generating scenario from your prompt...",
    "plan_attack":             "AI mapping attack to MITRE ATT&CK techniques...",
    "generate_infrastructure": "AI generating Terraform code...",
    "safety_check":            "validating Terraform against safety guardrails...",
    "deploy_infrastructure":   "terraform init → plan → apply · ⏱️ may take 5–15 min",
    "execute_simulator":       "running attack steps via cloud SDK...",
    "validator":               "checking Cortex XDR for detections...",
    "teardown":                "terraform destroy · ⏱️ may take 5–10 min",
    "erasure_validator":       "verifying all cloud resources are removed...",
    "generate_report":         "writing Markdown + JSON + ATT&CK Navigator report...",
}


def _show_node_running(status_ph, node_id: str) -> None:
    """Update status_ph to show which node is currently executing with a duration hint."""
    label = NODE_LABELS.get(node_id, {}).get("label", node_id)
    hint = _NODE_HINTS.get(node_id, "")
    hint_html = (
        f" <span style='color:{COLORS['text_dim']};font-size:0.78rem;'>— {hint}</span>"
        if hint else ""
    )
    status_ph.markdown(
        f"<div style='color:{COLORS['primary']};font-size:0.85rem;'>"
        f"🔄 Running: <b>{label}</b>{hint_html}</div>",
        unsafe_allow_html=True,
    )


def _mark_remaining_as_skipped(node_statuses: dict, visible_nodes: list[dict]) -> None:
    """Mark all still-pending visible nodes as skipped (dry-run, abort, reject paths)."""
    for n in visible_nodes:
        if node_statuses.get(n["id"]) == "pending":
            node_statuses[n["id"]] = "skipped"


def _run_nodes_streaming(
    node_names: list[str],
    state: dict,
    node_statuses: dict,
    node_durations: dict,
    visible_nodes: list[dict],
    pipeline_ph,
    status_ph,
    output_container,
) -> bool:
    """
    Run a list of nodes, updating the pipeline visualisation and live
    output in real-time.  Returns True on success, False on error.
    """
    # Mark the first pending node as running and show its live status
    first_nid: str | None = None
    for n in visible_nodes:
        if n["id"] in node_names and node_statuses.get(n["id"]) == "pending":
            node_statuses[n["id"]] = "running"
            first_nid = n["id"]
            break
    pipeline_ph.html(render_pipeline(visible_nodes, node_statuses, node_durations))
    if first_nid:
        _show_node_running(status_ph, first_nid)

    with st.spinner("Running pipeline nodes..."):
        for event in run_phase(node_names, state):
            nid = event.node_name
            if event.status == "failed":
                node_statuses[nid] = "failed"
                _SS.sim_error = event.error
                failed_label = NODE_LABELS.get(nid, {}).get("label", nid)
                status_ph.markdown(
                    f"<div style='color:{COLORS['danger']};font-size:0.85rem;'>"
                    f"❌ <b>{failed_label}</b> failed: {event.error}</div>",
                    unsafe_allow_html=True,
                )
                pipeline_ph.html(render_pipeline(visible_nodes, node_statuses, node_durations))
                _SS.sim_events.append(event)
                return False

            # Node completed — update status and find next
            node_statuses[nid] = "completed"
            node_durations[nid] = event.duration_ms
            _SS.sim_events.append(event)

            # Find and mark the next pending node as running
            next_nid: str | None = None
            found = False
            for n in visible_nodes:
                if found and node_statuses.get(n["id"]) == "pending":
                    node_statuses[n["id"]] = "running"
                    next_nid = n["id"]
                    break
                if n["id"] == nid:
                    found = True

            pipeline_ph.html(render_pipeline(visible_nodes, node_statuses, node_durations))

            if next_nid:
                # Show which node is now executing so user knows what to expect
                _show_node_running(status_ph, next_nid)
            else:
                # Last node — show completion
                label = NODE_LABELS.get(nid, {}).get("label", nid)
                status_ph.markdown(
                    f"<div style='color:{COLORS['success']};font-size:0.85rem;'>"
                    f"✅ <b>{label}</b> completed</div>",
                    unsafe_allow_html=True,
                )

            # Live output card
            node_html = render_node_output(nid, event.output)
            if node_html:
                with output_container:
                    st.html(node_html)

    # Persist statuses
    _SS.sim_node_statuses = dict(node_statuses)
    _SS.sim_node_durations = dict(node_durations)
    _SS.sim_state = dict(state)
    return True


# ── Page header ───────────────────────────────────────────────────
st.markdown(
    f"""
    <div style="margin-bottom:20px;">
        <span style="font-size:1.6rem;font-weight:800;color:{COLORS['primary']};">
            🚀 Launch Mission
        </span>
        <span style="color:{COLORS['text_dim']};font-size:0.9rem;margin-left:12px;">
            Configure and execute an attack simulation
        </span>
    </div>
    """,
    unsafe_allow_html=True,
)

# ── Registry ──────────────────────────────────────────────────────
registry = ScenarioRegistry.get_instance()
scenarios = registry.list_all()
scenario_map = {s.id: s for s in scenarios}
scenario_ids = [s.id for s in scenarios]

# ── Layout: Config left · Pipeline right ──────────────────────────
col_config, col_spacer, col_pipeline = st.columns([4, 0.3, 5])

# ══════════════════════════════════════════════════════════════════
#  LEFT COLUMN — Configuration
# ══════════════════════════════════════════════════════════════════

with col_config:
    st.markdown(
        f"<h4 style='color:{COLORS['text']};margin-bottom:12px;'>⚙️ Configuration</h4>",
        unsafe_allow_html=True,
    )

    # Disable config while sim is running
    config_disabled = _SS.sim_phase != "idle"

    mode = st.radio(
        "Simulation Mode",
        options=["📋 Scenario Mode", "🤖 AI Freeform"],
        horizontal=True,
        disabled=config_disabled,
        help="Scenario Mode uses a pre-built attack scenario. AI Freeform generates one from your description.",
    )

    is_freeform = "Freeform" in mode

    selected_scenario_id = None
    selected_scenario = None
    goal = ""
    prompt_text = ""

    if not is_freeform:
        pre_selected = st.session_state.get("launch_scenario_id")
        default_idx = 0
        if pre_selected and pre_selected in scenario_ids:
            default_idx = scenario_ids.index(pre_selected)
            st.session_state.launch_scenario_id = None

        selected_scenario_id = st.selectbox(
            "Select Scenario",
            options=scenario_ids,
            index=default_idx,
            disabled=config_disabled,
            format_func=lambda sid: f"{scenario_map[sid].name}  ({sid})",
        )
        selected_scenario = scenario_map.get(selected_scenario_id)

        if selected_scenario:
            st.markdown(
                render_scenario_card(selected_scenario),
                unsafe_allow_html=True,
            )
            st.markdown("<div style='height:8px;'></div>", unsafe_allow_html=True)
            goal = st.text_area(
                "Attack Goal",
                value=selected_scenario.goal_template,
                height=100,
                disabled=config_disabled,
                help="Edit the attack goal or keep the scenario default.",
            )
    else:
        prompt_text = st.text_area(
            "Describe Your Attack",
            height=160,
            disabled=config_disabled,
            placeholder=(
                "Example: Simulate an attacker who compromises an IAM user with "
                "iam:AttachUserPolicy permission and escalates to AdministratorAccess "
                "in an AWS environment."
            ),
            help="Describe the attack in plain English. The AI will generate the full scenario.",
        )
        goal = prompt_text

    st.markdown("<div style='height:12px;'></div>", unsafe_allow_html=True)

    opt1, opt2 = st.columns(2)
    with opt1:
        dry_run = st.toggle("🔵 Dry Run", value=True, disabled=config_disabled,
                            help="Skip cloud deployment — plan + report only.")
    with opt2:
        interactive = st.toggle("👁️ Interactive", value=False, disabled=config_disabled,
                                help="Enable human checkpoints.")

    # Advanced options (matches CLI --run-id and --log-level)
    with st.expander("🔧 Advanced Options", expanded=False):
        adv1, adv2 = st.columns(2)
        with adv1:
            custom_run_id = st.text_input(
                "Run ID",
                value="",
                disabled=config_disabled,
                placeholder="Auto-generated UUID",
                help="Custom run ID (CLI: --run-id). Leave empty for auto-generated UUID.",
            )
        with adv2:
            log_level = st.selectbox(
                "Log Level",
                options=["INFO", "DEBUG", "WARNING", "ERROR"],
                index=0,
                disabled=config_disabled,
                help="Override log level for this run (CLI: --log-level).",
            )

    st.markdown("<div style='height:16px;'></div>", unsafe_allow_html=True)

    can_launch = bool(goal.strip()) if is_freeform else bool(selected_scenario_id)

    # Launch / Reset buttons
    if _SS.sim_phase == "idle":
        launch_clicked = st.button(
            "🚀  LAUNCH SIMULATION",
            use_container_width=True,
            disabled=not can_launch,
            type="primary",
        )
    else:
        launch_clicked = False
        if st.button("🔄  RESET / NEW RUN", use_container_width=True, type="secondary"):
            _reset_sim()
            st.rerun()


# ══════════════════════════════════════════════════════════════════
#  RIGHT COLUMN — Pipeline Monitor
# ══════════════════════════════════════════════════════════════════

with col_pipeline:
    st.markdown(
        f"<h4 style='color:{COLORS['text']};margin-bottom:12px;'>📡 Pipeline Monitor</h4>",
        unsafe_allow_html=True,
    )

    # ── LAUNCH: Start a new simulation ────────────────────────────
    if launch_clicked and can_launch:
        # Resolve run ID (CLI: --run-id)
        run_id = custom_run_id.strip() if custom_run_id.strip() else str(uuid.uuid4())

        # ── Configuration validation (mirrors CLI settings.validate()) ──
        try:
            _settings = load_settings()
            _settings.validate(dry_run=dry_run)
        except ConfigError as exc:
            st.error(f"**Configuration Error:** {exc}")
            st.info("Check your `.env` file or environment variables.")
            st.stop()

        # Initialize logging with chosen level (CLI: --log-level)
        _settings.log_level = log_level
        setup_logging(run_id=run_id, log_level=log_level, reports_dir=_settings.reports_dir)

        # ── Execution start banner (mirrors CLI startup banner) ──
        mode_label = "AI Freeform" if is_freeform else "Scenario"
        scenario_label = (selected_scenario_id or "(will be generated)") if not is_freeform else "(AI generated)"
        st.markdown(
            f"<div style='background:{COLORS['surface']};border:1px solid {COLORS['primary']};"
            f"border-radius:10px;padding:14px 20px;margin-bottom:12px;'>"
            f"<div style='color:{COLORS['primary']};font-weight:700;font-size:0.95rem;"
            f"margin-bottom:8px;'>🚀 SIMULATION STARTED</div>"
            f"<div style='color:{COLORS['text']};font-size:0.82rem;line-height:1.6;'>"
            f"<b>Run ID:</b> <code>{run_id}</code><br>"
            f"<b>Mode:</b> {mode_label}<br>"
            f"<b>Scenario:</b> {scenario_label}<br>"
            f"<b>Dry Run:</b> {dry_run}<br>"
            f"<b>Interactive:</b> {interactive}"
            f"</div></div>",
            unsafe_allow_html=True,
        )

        # Build initial state
        if is_freeform:
            state = dict(create_initial_state(
                goal=prompt_text,
                scenario_id="custom",
                dry_run=dry_run,
                interactive=False,  # We handle checkpoints in UI
                prompt=prompt_text,
                run_id=run_id,
            ))
        else:
            state = dict(create_initial_state(
                goal=goal,
                scenario_id=selected_scenario_id or "",
                dry_run=dry_run,
                interactive=False,
                run_id=run_id,
            ))

        vis = _visible_nodes(is_freeform, dry_run, interactive)
        node_statuses = {n["id"]: "pending" for n in vis}
        node_durations: dict[str, float] = {}

        _SS.sim_config = {
            "is_freeform": is_freeform,
            "dry_run": dry_run,
            "interactive": interactive,
            "scenario_id": selected_scenario_id or "",
            "goal": goal,
            "prompt": prompt_text,
        }
        _SS.sim_visible_nodes = vis
        _SS.sim_node_statuses = node_statuses
        _SS.sim_node_durations = node_durations
        _SS.sim_state = state
        _SS.sim_events = []
        _SS.sim_error = None

        # Phase 1 nodes: cobra_intel, (generate_scenario), plan_attack
        phase1 = ["fetch_cobra_intel"]
        if is_freeform:
            phase1.append("generate_scenario")
        phase1.append("plan_attack")

        pipeline_ph = st.empty()
        status_ph = st.empty()
        output_container = st.container()

        pipeline_ph.html(render_pipeline(vis, node_statuses, node_durations))

        ok = _run_nodes_streaming(
            phase1, state, node_statuses, node_durations, vis,
            pipeline_ph, status_ph, output_container,
        )

        if ok and interactive:
            # Pause for plan review
            _SS.sim_phase = "review_plan"
            node_statuses["review_plan"] = "running"
            _SS.sim_node_statuses = dict(node_statuses)
            pipeline_ph.html(render_pipeline(vis, node_statuses, node_durations))
            st.rerun()
        elif ok:
            # Non-interactive: continue to phase 2
            _SS.sim_phase = "run_infra"
            st.rerun()
        else:
            _SS.sim_phase = "error"
            st.rerun()

    # ── CHECKPOINT 1: Review Plan ─────────────────────────────────
    elif _SS.sim_phase == "review_plan":
        state = _SS.sim_state
        vis = _SS.sim_visible_nodes
        node_statuses = dict(_SS.sim_node_statuses)
        node_durations = dict(_SS.sim_node_durations)

        st.html(render_pipeline(vis, node_statuses, node_durations))

        # Replay live output from previous nodes
        for ev in _SS.sim_events:
            html = render_node_output(ev.node_name, ev.output)
            if html:
                st.html(html)

        # Checkpoint UI
        plan = state.get("attack_plan", {})
        # Build techniques HTML
        techniques = plan.get("mitre_techniques", [])
        techniques_html = ""
        if techniques:
            tech_items = "".join(
                f"<div style='display:flex;gap:8px;padding:2px 0;font-size:0.82rem;'>"
                f"<span style='color:{COLORS['info']};font-weight:600;min-width:90px;'>{t.get('id', '?')}</span>"
                f"<span style='color:{COLORS['text']};'>{t.get('name', t.get('technique_name', '?'))}</span>"
                f"</div>"
                for t in techniques
            )
            techniques_html = (
                f"<div style='margin-top:10px;'>"
                f"<b style='color:{COLORS['primary']};font-size:0.85rem;'>MITRE ATT&CK Techniques ({len(techniques)}):</b>"
                f"<div style='margin-top:4px;'>{tech_items}</div></div>"
            )

        # Build steps HTML
        steps = plan.get("steps", [])
        steps_html = ""
        if steps:
            step_parts = []
            for s in steps:
                tid = s.get("mitre_technique_id", "")
                tid_span = ""
                if tid:
                    tid_span = '<span style="color:' + COLORS['info'] + ';font-size:0.75rem;"> [' + tid + ']</span>'
                step_parts.append(
                    f"<div style='display:flex;gap:8px;padding:3px 0;border-left:2px solid {COLORS['primary']};"
                    f"padding-left:10px;margin-bottom:2px;font-size:0.82rem;'>"
                    f"<span style='color:{COLORS['primary']};font-weight:700;min-width:20px;'>{s.get('step_number', '?')}.</span>"
                    f"<div><span style='color:{COLORS['text']};'>{s.get('description', '')}</span>"
                    f"{tid_span}</div></div>"
                )
            step_items = "".join(step_parts)
            steps_html = (
                f"<div style='margin-top:10px;'>"
                f"<b style='color:{COLORS['primary']};font-size:0.85rem;'>Attack Steps ({len(steps)}):</b>"
                f"<div style='margin-top:4px;'>{step_items}</div></div>"
            )

        st.markdown(
            f"<div style='background:{COLORS['surface']};border:1px solid {COLORS['primary']};"
            f"border-radius:10px;padding:16px 20px;margin:12px 0;'>"
            f"<div style='color:{COLORS['primary']};font-weight:700;font-size:1.05rem;"
            f"margin-bottom:12px;'>👁️ ATTACK PLAN REVIEW</div>"
            f"<div style='color:{COLORS['text']};font-size:0.88rem;'>"
            f"<b>Goal:</b> {plan.get('goal', state.get('goal', 'N/A'))}<br>"
            f"<b>Scenario:</b> {state.get('scenario_id', 'N/A')}<br>"
            f"<b>Summary:</b> {plan.get('summary', 'N/A')}"
            f"</div>"
            f"{techniques_html}"
            f"{steps_html}"
            f"</div>",
            unsafe_allow_html=True,
        )

        new_goal = st.text_input(
            "Modify attack goal (leave empty to keep current):",
            value="",
            placeholder="Enter a new/refined attack goal…",
        )

        c1, c2, c3 = st.columns(3)
        with c1:
            if st.button("✅ Continue", use_container_width=True, type="primary"):
                node_statuses["review_plan"] = "completed"
                _SS.sim_node_statuses = node_statuses
                _SS.sim_phase = "run_infra"
                st.rerun()
        with c2:
            if st.button("✏️ Modify & Re-plan", use_container_width=True):
                if new_goal.strip():
                    state["goal"] = new_goal.strip()
                    state["replan_requested"] = True
                    state["attack_plan"] = {}
                    _SS.sim_state = state
                    # Reset plan_attack status so it re-runs
                    node_statuses["review_plan"] = "pending"
                    node_statuses["plan_attack"] = "pending"
                    _SS.sim_node_statuses = node_statuses
                    # Remove old plan_attack events
                    _SS.sim_events = [e for e in _SS.sim_events if e.node_name != "plan_attack"]
                    _SS.sim_phase = "replan"
                    st.rerun()
                else:
                    st.warning("Enter a new goal above before clicking Modify.")
        with c3:
            if st.button("🛑 Abort", use_container_width=True):
                state["user_aborted"] = True
                _SS.sim_state = state
                node_statuses["review_plan"] = "completed"
                _SS.sim_node_statuses = node_statuses
                _SS.sim_phase = "run_report_only"
                st.rerun()

    # ── RE-PLAN (user modified the goal) ──────────────────────────
    elif _SS.sim_phase == "replan":
        state = _SS.sim_state
        vis = _SS.sim_visible_nodes
        node_statuses = dict(_SS.sim_node_statuses)
        node_durations = dict(_SS.sim_node_durations)

        pipeline_ph = st.empty()
        status_ph = st.empty()
        output_container = st.container()

        # Replay existing events
        for ev in _SS.sim_events:
            html = render_node_output(ev.node_name, ev.output)
            if html:
                with output_container:
                    st.html(html)

        ok = _run_nodes_streaming(
            ["plan_attack"], state, node_statuses, node_durations, vis,
            pipeline_ph, status_ph, output_container,
        )
        state["replan_requested"] = False
        _SS.sim_state = state

        if ok:
            _SS.sim_phase = "review_plan"
            node_statuses["review_plan"] = "running"
            _SS.sim_node_statuses = node_statuses
            st.rerun()
        else:
            _SS.sim_phase = "error"
            st.rerun()

    # ── Phase 2: Generate infra + safety check ────────────────────
    elif _SS.sim_phase == "run_infra":
        state = _SS.sim_state
        vis = _SS.sim_visible_nodes
        node_statuses = dict(_SS.sim_node_statuses)
        node_durations = dict(_SS.sim_node_durations)

        pipeline_ph = st.empty()
        status_ph = st.empty()
        output_container = st.container()

        for ev in _SS.sim_events:
            html = render_node_output(ev.node_name, ev.output)
            if html:
                with output_container:
                    st.html(html)

        ok = _run_nodes_streaming(
            ["generate_infrastructure", "safety_check"],
            state, node_statuses, node_durations, vis,
            pipeline_ph, status_ph, output_container,
        )

        if not ok:
            _SS.sim_phase = "error"
            st.rerun()
        elif state.get("dry_run", False) or state.get("deploy_status") == "unsafe":
            # CLI approve_deploy is a no-op in dry_run/unsafe — mark pending nodes skipped
            _mark_remaining_as_skipped(node_statuses, vis)
            _SS.sim_node_statuses = dict(node_statuses)
            _SS.sim_phase = "run_report"
            st.rerun()
        elif _SS.sim_config.get("interactive", False):
            # Interactive: show approve_deploy checkpoint (matches CLI interactive behavior)
            _SS.sim_phase = "approve_deploy"
            node_statuses["approve_deploy"] = "running"
            _SS.sim_node_statuses = dict(node_statuses)
            st.rerun()
        else:
            _SS.sim_phase = "run_deploy"
            st.rerun()

    # ── CHECKPOINT 2: Approve Deploy ──────────────────────────────
    elif _SS.sim_phase == "approve_deploy":
        state = _SS.sim_state
        vis = _SS.sim_visible_nodes
        node_statuses = dict(_SS.sim_node_statuses)
        node_durations = dict(_SS.sim_node_durations)

        st.html(render_pipeline(vis, node_statuses, node_durations))

        for ev in _SS.sim_events:
            html = render_node_output(ev.node_name, ev.output)
            if html:
                st.html(html)

        # Deployment summary
        tf_code = state.get("terraform_code", "")
        resource_count = len(re.findall(r'^resource\s+"', tf_code, re.MULTILINE))
        resource_types = sorted(set(re.findall(r'resource\s+"([^"]+)"', tf_code)))
        violations = state.get("safety_violations", [])

        if violations:
            safety_html = f'<span style="color:{COLORS["danger"]};">FAILED ({len(violations)} violations)</span>'
        else:
            safety_html = f'<span style="color:{COLORS["success"]};">PASSED</span>'

        st.markdown(
            f"<div style='background:{COLORS['surface']};border:1px solid {COLORS['primary']};"
            f"border-radius:10px;padding:16px 20px;margin:12px 0;'>"
            f"<div style='color:{COLORS['primary']};font-weight:700;font-size:1.05rem;"
            f"margin-bottom:12px;'>✅ DEPLOYMENT APPROVAL</div>"
            f"<div style='color:{COLORS['text']};font-size:0.88rem;'>"
            f"<b>Resources to create:</b> {resource_count}<br>"
            f"<b>Resource types:</b> {', '.join(resource_types) or 'N/A'}<br>"
            f"<b>Terraform code size:</b> {len(tf_code)} chars<br>"
            f"<b>Safety check:</b> {safety_html}"
            f"</div></div>",
            unsafe_allow_html=True,
        )

        with st.expander("📄 View Full Terraform Code", expanded=False):
            st.code(tf_code, language="hcl")

        c1, c2 = st.columns(2)
        with c1:
            if st.button("🚀 Deploy", use_container_width=True, type="primary"):
                node_statuses["approve_deploy"] = "completed"
                _SS.sim_node_statuses = node_statuses
                _SS.sim_phase = "run_deploy"
                st.rerun()
        with c2:
            if st.button("🛑 Reject", use_container_width=True):
                state["user_aborted"] = True
                state["deploy_status"] = "user_rejected"
                _SS.sim_state = state
                node_statuses["approve_deploy"] = "completed"
                _SS.sim_node_statuses = node_statuses
                _SS.sim_phase = "run_report"
                st.rerun()

    # ── Phase 3: Deploy + Execute + Validate (with self-healing retries) ──
    elif _SS.sim_phase == "run_deploy":
        state = _SS.sim_state
        vis = _SS.sim_visible_nodes
        node_statuses = dict(_SS.sim_node_statuses)
        node_durations = dict(_SS.sim_node_durations)

        pipeline_ph = st.empty()
        status_ph = st.empty()
        output_container = st.container()

        for ev in _SS.sim_events:
            html = render_node_output(ev.node_name, ev.output)
            if html:
                with output_container:
                    st.html(html)

        # Run deploy_infrastructure first
        ok = _run_nodes_streaming(
            ["deploy_infrastructure"],
            state, node_statuses, node_durations, vis,
            pipeline_ph, status_ph, output_container,
        )

        # Self-healing retry loop (mirrors CLI route_after_deploy)
        deploy_status = state.get("deploy_status", "pending")
        deploy_retries = state.get("deploy_retries", 0)

        # Fix pipeline visual: deploy_infrastructure catches its own exceptions,
        # so _run_nodes_streaming marks it "completed" even on failure
        if deploy_status == "failed":
            node_statuses["deploy_infrastructure"] = "failed"
            pipeline_ph.html(render_pipeline(vis, node_statuses, node_durations))

        if deploy_status == "failed" and deploy_retries < MAX_DEPLOY_RETRIES:
            # Retry: re-run generate_infrastructure -> safety_check -> deploy
            status_ph.markdown(
                f"<div style='color:{COLORS['warning']};font-size:0.85rem;font-weight:600;'>"
                f"🔄 Self-healing attempt {deploy_retries}/{MAX_DEPLOY_RETRIES} "
                f"— AI is fixing Terraform code...</div>",
                unsafe_allow_html=True,
            )
            # Reset nodes for retry
            node_statuses["generate_infrastructure"] = "pending"
            node_statuses["safety_check"] = "pending"
            node_statuses["deploy_infrastructure"] = "pending"
            # Remove stale events for retried nodes
            retry_nodes = {"generate_infrastructure", "safety_check", "deploy_infrastructure"}
            _SS.sim_events = [e for e in _SS.sim_events if e.node_name not in retry_nodes]
            _SS.sim_node_statuses = node_statuses
            _SS.sim_state = state
            _SS.sim_phase = "run_deploy_retry"
            st.rerun()
        elif deploy_status == "failed" and deploy_retries >= MAX_DEPLOY_RETRIES:
            # Retries exhausted — teardown on failure (mirrors CLI route_after_deploy)
            status_ph.markdown(
                f"<div style='color:{COLORS['danger']};font-size:0.85rem;font-weight:600;'>"
                f"❌ Deploy failed after {MAX_DEPLOY_RETRIES} retries — tearing down...</div>",
                unsafe_allow_html=True,
            )
            _SS.sim_phase = "run_teardown"
            st.rerun()
        elif deploy_status == "success":
            # Deploy succeeded — continue with simulator + validator
            ok = _run_nodes_streaming(
                ["execute_simulator", "validator"],
                state, node_statuses, node_durations, vis,
                pipeline_ph, status_ph, output_container,
            )
            if not ok:
                _SS.sim_phase = "error"
                st.rerun()
            elif _SS.sim_config.get("interactive", False):
                _SS.sim_phase = "confirm_teardown"
                node_statuses["confirm_teardown"] = "running"
                _SS.sim_node_statuses = node_statuses
                st.rerun()
            else:
                _SS.sim_phase = "run_teardown"
                st.rerun()
        else:
            # Unexpected state
            _SS.sim_phase = "error"
            _SS.sim_error = f"Unexpected deploy status: {deploy_status}"
            st.rerun()

    # ── Phase 3b: Self-healing deploy retry ───────────────────────
    elif _SS.sim_phase == "run_deploy_retry":
        state = _SS.sim_state
        vis = _SS.sim_visible_nodes
        node_statuses = dict(_SS.sim_node_statuses)
        node_durations = dict(_SS.sim_node_durations)

        pipeline_ph = st.empty()
        status_ph = st.empty()
        output_container = st.container()

        for ev in _SS.sim_events:
            html = render_node_output(ev.node_name, ev.output)
            if html:
                with output_container:
                    st.html(html)

        retry_num = state.get("deploy_retries", 0)
        status_ph.markdown(
            f"<div style='color:{COLORS['warning']};font-size:0.85rem;font-weight:600;'>"
            f"🔄 Self-healing retry {retry_num}/{MAX_DEPLOY_RETRIES} "
            f"— regenerating infrastructure...</div>",
            unsafe_allow_html=True,
        )

        # Re-run generate_infrastructure (AI self-corrects) -> safety_check
        ok = _run_nodes_streaming(
            ["generate_infrastructure", "safety_check"],
            state, node_statuses, node_durations, vis,
            pipeline_ph, status_ph, output_container,
        )

        if not ok:
            _SS.sim_phase = "error"
            st.rerun()
        elif state.get("deploy_status") == "unsafe":
            # Safety check failed on retry — no infra deployed, go to report (matches CLI)
            _mark_remaining_as_skipped(node_statuses, vis)
            _SS.sim_node_statuses = dict(node_statuses)
            _SS.sim_phase = "run_report"
            st.rerun()
        else:
            # Re-attempt deploy
            _SS.sim_phase = "run_deploy"
            st.rerun()

    # ── CHECKPOINT 3: Confirm Teardown ────────────────────────────
    elif _SS.sim_phase == "confirm_teardown":
        state = _SS.sim_state
        vis = _SS.sim_visible_nodes
        node_statuses = dict(_SS.sim_node_statuses)
        node_durations = dict(_SS.sim_node_durations)

        st.html(render_pipeline(vis, node_statuses, node_durations))

        for ev in _SS.sim_events:
            html = render_node_output(ev.node_name, ev.output)
            if html:
                st.html(html)

        # Simulation summary
        sim_results = state.get("simulation_results", [])
        val = state.get("validation_result", {})
        success_count = sum(1 for r in sim_results if r.get("result") == "success")
        fail_count = sum(1 for r in sim_results if r.get("result") == "failed")

        st.markdown(
            f"<div style='background:{COLORS['surface']};border:1px solid {COLORS['primary']};"
            f"border-radius:10px;padding:16px 20px;margin:12px 0;'>"
            f"<div style='color:{COLORS['primary']};font-weight:700;font-size:1.05rem;"
            f"margin-bottom:12px;'>🗑️ TEARDOWN DECISION</div>"
            f"<div style='color:{COLORS['text']};font-size:0.88rem;'>"
            f"<b>Simulation actions:</b> {len(sim_results)} "
            f"({success_count} succeeded, {fail_count} failed)<br>"
            f"<b>Detection:</b> "
            f"{'Detected' if val.get('detected') is True else 'Not Detected' if val.get('detected') is False else 'N/A'}"
            f"</div></div>",
            unsafe_allow_html=True,
        )

        c1, c2 = st.columns(2)
        with c1:
            if st.button("💥 Tear Down", use_container_width=True, type="primary"):
                node_statuses["confirm_teardown"] = "completed"
                _SS.sim_node_statuses = node_statuses
                _SS.sim_phase = "run_teardown"
                st.rerun()
        with c2:
            if st.button("🔒 Keep Alive", use_container_width=True):
                state["skip_teardown"] = True
                _SS.sim_state = state
                node_statuses["confirm_teardown"] = "completed"
                _SS.sim_node_statuses = node_statuses
                _SS.sim_phase = "run_report"
                st.rerun()

    # ── Phase 4: Teardown + Erasure ───────────────────────────────
    elif _SS.sim_phase == "run_teardown":
        state = _SS.sim_state
        vis = _SS.sim_visible_nodes
        node_statuses = dict(_SS.sim_node_statuses)
        node_durations = dict(_SS.sim_node_durations)

        pipeline_ph = st.empty()
        status_ph = st.empty()
        output_container = st.container()

        for ev in _SS.sim_events:
            html = render_node_output(ev.node_name, ev.output)
            if html:
                with output_container:
                    st.html(html)

        _run_nodes_streaming(
            ["teardown", "erasure_validator"],
            state, node_statuses, node_durations, vis,
            pipeline_ph, status_ph, output_container,
        )

        _SS.sim_phase = "run_report"
        st.rerun()

    # ── Phase 5: Generate Report ──────────────────────────────────
    elif _SS.sim_phase in ("run_report", "run_report_only"):
        state = _SS.sim_state
        vis = _SS.sim_visible_nodes
        node_statuses = dict(_SS.sim_node_statuses)
        node_durations = dict(_SS.sim_node_durations)

        # Mark any still-pending nodes as skipped (abort / dry-run / reject / keep-alive paths)
        _mark_remaining_as_skipped(node_statuses, vis)
        _SS.sim_node_statuses = dict(node_statuses)

        pipeline_ph = st.empty()
        status_ph = st.empty()
        output_container = st.container()

        # Pre-render pipeline so skipped nodes are visible before report runs
        pipeline_ph.html(render_pipeline(vis, node_statuses, node_durations))

        for ev in _SS.sim_events:
            html = render_node_output(ev.node_name, ev.output)
            if html:
                with output_container:
                    st.html(html)

        _run_nodes_streaming(
            ["generate_report"],
            state, node_statuses, node_durations, vis,
            pipeline_ph, status_ph, output_container,
        )

        _SS.sim_phase = "complete"
        st.rerun()

    # ── COMPLETE: Show results ────────────────────────────────────
    elif _SS.sim_phase == "complete":
        state = _SS.sim_state
        vis = _SS.sim_visible_nodes
        node_statuses = dict(_SS.sim_node_statuses)
        node_durations = dict(_SS.sim_node_durations)

        st.html(render_pipeline(vis, node_statuses, node_durations))

        st.markdown(
            f"<div style='color:{COLORS['success']};font-size:1rem;font-weight:700;margin:8px 0;'>"
            f"✅ Simulation Complete!</div>",
            unsafe_allow_html=True,
        )

        # Replay all node outputs
        for ev in _SS.sim_events:
            html = render_node_output(ev.node_name, ev.output)
            if html:
                st.html(html)

        st.markdown("<div style='height:16px;'></div>", unsafe_allow_html=True)

        # Result metrics
        r1, r2, r3, r4 = st.columns(4)
        with r1:
            rid = state.get("run_id", "?")
            st.markdown(metric_card("Run ID", rid[:12] + "…", "🆔", COLORS["info"]), unsafe_allow_html=True)
        with r2:
            st.markdown(metric_card("Scenario", state.get("scenario_id", "?"), "📋", COLORS["accent"]), unsafe_allow_html=True)
        with r3:
            ds = state.get("deploy_status", "pending")
            ds_color = COLORS["success"] if ds == "success" else COLORS["info"] if ds == "pending" else COLORS["danger"]
            st.markdown(metric_card("Deploy", ds, "🚀", ds_color), unsafe_allow_html=True)
        with r4:
            val = state.get("validation_result", {})
            det = val.get("detected")
            if state.get("dry_run"):
                det_text, det_color = "Dry Run", COLORS["info"]
            elif det is True:
                det_text, det_color = "Detected", COLORS["success"]
            elif det is False:
                det_text, det_color = "Not Detected", COLORS["danger"]
            else:
                det_text, det_color = "N/A", COLORS["text_dim"]
            st.markdown(metric_card("Detection", det_text, "🎯", det_color), unsafe_allow_html=True)

        # MITRE Techniques table
        plan = state.get("attack_plan", {})
        techniques = plan.get("mitre_techniques", [])
        if techniques:
            st.markdown(
                f"<h4 style='color:{COLORS['text']};margin-top:20px;'>🗺️ MITRE ATT&CK Mapping</h4>",
                unsafe_allow_html=True,
            )
            tech_rows = [
                {"ID": t.get("id", ""), "Name": t.get("name", ""),
                 "Tactic": t.get("tactic", ""), "Description": t.get("description", "")[:100]}
                for t in techniques
            ]
            st.dataframe(tech_rows, use_container_width=True, hide_index=True)

        # Attack Steps
        steps = plan.get("steps", [])
        if steps:
            with st.expander("📝 Attack Steps", expanded=True):
                for s in steps:
                    num = s.get("step_number", "?")
                    desc = s.get("description", "")
                    tid = s.get("mitre_technique_id", "")
                    phase = s.get("kill_chain_phase", "")
                    st.markdown(
                        f"""<div style="display:flex;align-items:flex-start;gap:10px;padding:8px 12px;
                            margin-bottom:4px;background:{COLORS['surface']};
                            border-left:3px solid {COLORS['primary']};border-radius:0 8px 8px 0;">
                            <span style="color:{COLORS['primary']};font-weight:700;min-width:24px;">{num}.</span>
                            <div><div style="color:{COLORS['text']};font-size:0.88rem;">{desc}</div>
                            <div style="color:{COLORS['text_dim']};font-size:0.75rem;margin-top:2px;">
                            {f'MITRE: {tid}' if tid else ''} {f'• {phase}' if phase else ''}
                            </div></div></div>""",
                        unsafe_allow_html=True,
                    )

        # Simulation Timeline
        sim_results = state.get("simulation_results", [])
        if sim_results:
            with st.expander("⚔️ Simulation Timeline", expanded=False):
                for a in sim_results:
                    result = a.get("result", "unknown")
                    color = COLORS["success"] if result == "success" else COLORS["danger"] if result == "failed" else COLORS["text_dim"]
                    st.markdown(
                        f"""<div style="padding:6px 12px;margin-bottom:3px;background:{COLORS['surface']};
                            border-left:3px solid {color};border-radius:0 6px 6px 0;">
                            <span style="color:{color};font-weight:600;font-size:0.85rem;">{a.get('action', '?')}</span>
                            <span style="color:{COLORS['text_dim']};font-size:0.75rem;margin-left:8px;">
                            {a.get('target_resource', '')} — {a.get('details', '')[:60]}</span></div>""",
                        unsafe_allow_html=True,
                    )

        # Self-Healing Attempts (mirrors CLI report section)
        error_history = state.get("deploy_error_history", [])
        deploy_retries = state.get("deploy_retries", 0)
        if error_history:
            with st.expander(f"🔧 Self-Healing Attempts ({len(error_history)})", expanded=False):
                for i, err in enumerate(error_history, 1):
                    resolved = i < len(error_history) or state.get("deploy_status") == "success"
                    color = COLORS["success"] if resolved else COLORS["danger"]
                    icon = "✅" if resolved else "❌"
                    st.markdown(
                        f"""<div style="padding:8px 12px;margin-bottom:4px;background:{COLORS['surface']};
                            border-left:3px solid {color};border-radius:0 6px 6px 0;">
                            <div style="color:{color};font-weight:600;font-size:0.85rem;">
                            {icon} Attempt {i}/{MAX_DEPLOY_RETRIES} {'— Fixed' if resolved else '— Failed'}
                            </div>
                            <div style="color:{COLORS['text_dim']};font-size:0.78rem;margin-top:4px;">
                            {err[:200]}{'...' if len(err) > 200 else ''}</div></div>""",
                        unsafe_allow_html=True,
                    )

        # Detection Verdict
        val = state.get("validation_result", {})
        if val:
            st.markdown(
                f"<h4 style='color:{COLORS['text']};margin-top:16px;'>🎯 Detection Verdict</h4>",
                unsafe_allow_html=True,
            )
            det = val.get("detected")
            if state.get("dry_run"):
                st.info("🔵 **Dry Run** — no cloud resources were deployed.")
            elif det is True:
                st.success(f"🟢 **Detected** by {val.get('source', 'N/A')} (confidence: {val.get('confidence', 'N/A')})")
            elif det is False:
                st.error("🔴 **Not Detected** — defense gap identified.")

        # Terraform Code
        tf_code = state.get("terraform_code", "")
        if tf_code:
            with st.expander("🏗️ Generated Terraform Code", expanded=False):
                st.code(tf_code, language="hcl")

        # Report path
        report_path = state.get("report_path", "")
        if report_path:
            st.markdown(
                f"<div style='color:{COLORS['text_dim']};font-size:0.8rem;margin-top:12px;'>"
                f"📄 Report saved to: <code>{report_path}</code></div>",
                unsafe_allow_html=True,
            )

    # ── ERROR state ───────────────────────────────────────────────
    elif _SS.sim_phase == "error":
        vis = _SS.sim_visible_nodes
        node_statuses = dict(_SS.sim_node_statuses)
        node_durations = dict(_SS.sim_node_durations)

        # Mark any remaining pending nodes as skipped so pipeline renders cleanly
        _mark_remaining_as_skipped(node_statuses, vis)

        st.html(render_pipeline(vis, node_statuses, node_durations))

        for ev in _SS.sim_events:
            html = render_node_output(ev.node_name, ev.output)
            if html:
                st.html(html)

        st.error(f"❌ Simulation failed: {_SS.sim_error}")

    # ── IDLE: No run active ───────────────────────────────────────
    else:
        idle_nodes = _visible_nodes(is_freeform=False, dry_run=False, interactive=False)
        st.html(
            render_pipeline(
                idle_nodes,
                {n["id"]: "pending" for n in idle_nodes},
            ),
        )
        st.markdown(
            f"""<div style="text-align:center;padding:24px;color:{COLORS['text_dim']};font-size:0.9rem;
                border:1px dashed {COLORS['border']};border-radius:12px;margin-top:12px;">
                Configure a simulation on the left and click <b>Launch</b> to see the pipeline in action.
            </div>""",
            unsafe_allow_html=True,
        )
