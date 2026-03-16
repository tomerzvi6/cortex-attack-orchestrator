"""
🏠 Command Center — Overview dashboard with KPIs, recent runs, and quick actions.
"""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

_project_root = Path(__file__).resolve().parent.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from dashboard.theme import COLORS, apply_theme, metric_card, status_badge
from dashboard.services.analytics import get_aggregate_stats
from dashboard.services.report_loader import load_all_reports
from azure_cortex_orchestrator.scenarios.registry import ScenarioRegistry
from azure_cortex_orchestrator.config import load_settings
from azure_cortex_orchestrator.utils.run_manifest import RunManifest

apply_theme()

# ── Header ────────────────────────────────────────────────────────
st.markdown(
    f"""
    <div style="
        background: linear-gradient(135deg, {COLORS['surface']} 0%, {COLORS['surface_alt']} 100%);
        border: 1px solid {COLORS['border']};
        border-radius: 16px;
        padding: 32px 40px;
        margin-bottom: 28px;
    ">
        <div style="font-size:2rem;font-weight:800;color:{COLORS['primary']};margin-bottom:8px;">
            🛡️ Cortex Attack Simulation Engine
        </div>
        <div style="font-size:1rem;color:{COLORS['text_dim']};max-width:700px;line-height:1.5;">
            AI-driven multi-cloud attack simulation platform powered by LangGraph.
            Plan attacks against MITRE ATT&CK, deploy vulnerable infrastructure,
            execute simulations, and validate Cortex XDR detection — all from one interface.
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ── Orphaned run detection (mirrors CLI startup check) ───────────
try:
    _settings = load_settings()
    orphaned_runs = RunManifest.find_incomplete_runs(_settings.reports_dir)
    if orphaned_runs:
        orphan_details = ""
        for orphan in orphaned_runs:
            rid = orphan.get("run_id", "?")
            sid = orphan.get("scenario_id", "?")
            tf_dir = orphan.get("terraform_working_dir", "?")
            orphan_details += (
                f"- **Run** `{rid[:12]}...` (scenario: `{sid}`, "
                f"tf dir: `{tf_dir}`)\n"
            )
        st.warning(
            f"**{len(orphaned_runs)} orphaned run(s) detected** with deployed "
            f"infrastructure that was never torn down:\n\n{orphan_details}\n"
            f"To destroy manually, run `terraform destroy -auto-approve` in each "
            f"Terraform working directory listed above."
        )
except Exception:
    pass  # Don't block the page if manifest scanning fails

# ── KPI Metrics ───────────────────────────────────────────────────
try:
    stats = get_aggregate_stats()
    registry = ScenarioRegistry.get_instance()
    scenario_count = len(registry.list_all())
except Exception as _kpi_err:
    st.error(f"Failed to load dashboard data: {_kpi_err}")
    st.info("Check that your `.env` file exists and all dependencies are installed.")
    st.stop()

c1, c2, c3, c4 = st.columns(4)

with c1:
    st.markdown(
        metric_card("Total Runs", stats["total_runs"], "📊", COLORS["primary"]),
        unsafe_allow_html=True,
    )
with c2:
    det_color = COLORS["success"] if stats["detection_rate"] >= 50 else COLORS["danger"]
    st.markdown(
        metric_card("Detection Rate", f"{stats['detection_rate']}%", "🎯", det_color),
        unsafe_allow_html=True,
    )
with c3:
    st.markdown(
        metric_card("Avg Cost / Run", f"${stats['avg_cost']:.4f}", "💰", COLORS["accent"]),
        unsafe_allow_html=True,
    )
with c4:
    st.markdown(
        metric_card("Scenarios", scenario_count, "📚", COLORS["info"]),
        unsafe_allow_html=True,
    )

st.markdown("<div style='height:24px;'></div>", unsafe_allow_html=True)

# ── Quick Actions ─────────────────────────────────────────────────
st.markdown(
    f"<h3 style='color:{COLORS['text']};margin-bottom:12px;'>⚡ Quick Actions</h3>",
    unsafe_allow_html=True,
)

qa1, qa2, qa3 = st.columns(3)

with qa1:
    st.markdown(
        f"""
        <div style="
            background:{COLORS['surface']};border:1px solid {COLORS['border']};
            border-radius:12px;padding:24px;text-align:center;
            border-top:3px solid {COLORS['primary']};
        ">
            <div style="font-size:2rem;margin-bottom:8px;">🚀</div>
            <div style="font-weight:700;color:{COLORS['text']};margin-bottom:4px;">Launch Simulation</div>
            <div style="font-size:0.8rem;color:{COLORS['text_dim']};">Configure & run a new attack simulation</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    if st.button("Launch →", key="qa_launch", use_container_width=True):
        st.switch_page("pages/2_🚀_Launch_Mission.py")

with qa2:
    st.markdown(
        f"""
        <div style="
            background:{COLORS['surface']};border:1px solid {COLORS['border']};
            border-radius:12px;padding:24px;text-align:center;
            border-top:3px solid {COLORS['accent']};
        ">
            <div style="font-size:2rem;margin-bottom:8px;">📚</div>
            <div style="font-weight:700;color:{COLORS['text']};margin-bottom:4px;">Scenario Arsenal</div>
            <div style="font-size:0.8rem;color:{COLORS['text_dim']};">Browse pre-built attack scenarios</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    if st.button("Browse →", key="qa_scenarios", use_container_width=True):
        st.switch_page("pages/3_📚_Scenario_Arsenal.py")

with qa3:
    st.markdown(
        f"""
        <div style="
            background:{COLORS['surface']};border:1px solid {COLORS['border']};
            border-radius:12px;padding:24px;text-align:center;
            border-top:3px solid {COLORS['info']};
        ">
            <div style="font-size:2rem;margin-bottom:8px;">🔬</div>
            <div style="font-weight:700;color:{COLORS['text']};margin-bottom:4px;">MITRE Coverage</div>
            <div style="font-size:0.8rem;color:{COLORS['text_dim']};">Analyze ATT&CK technique coverage</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    if st.button("Analyze →", key="qa_mitre", use_container_width=True):
        st.switch_page("pages/5_🔬_MITRE_Coverage.py")

st.markdown("<div style='height:24px;'></div>", unsafe_allow_html=True)

# ── Recent Runs ───────────────────────────────────────────────────
recent = stats.get("recent_runs", [])

if recent:
    st.markdown(
        f"<h3 style='color:{COLORS['text']};margin-bottom:12px;'>🕐 Recent Runs</h3>",
        unsafe_allow_html=True,
    )

    for r in recent[:6]:
        meta = r.get("metadata", {})
        run_id = meta.get("run_id", "?")
        scenario_id = meta.get("scenario_id", "unknown")
        date_str = meta.get("generated_at", "")[:19]
        is_dry = meta.get("dry_run", False)
        risk = r.get("risk_level", "unknown")
        detected = r.get("validation_result", {}).get("detected")

        # Determine badge
        if is_dry:
            badge = status_badge("dry_run", "Dry Run")
        elif detected is True:
            badge = status_badge("detected", "Detected")
        elif detected is False:
            badge = status_badge("not_detected", "Not Detected")
        else:
            badge = status_badge("pending", "N/A")

        # Cost
        cost = r.get("llm_usage", {}).get("summary", {}).get("total_estimated_cost_usd", 0)

        # Cloud provider
        infra_code = r.get("infrastructure", {}).get("terraform_code", "")
        cloud = "AWS" if "aws" in (infra_code + scenario_id).lower() else "Azure"
        cloud_pill = (
            f'<span style="background:{COLORS["aws_orange"]};color:#000;padding:1px 8px;border-radius:10px;font-size:0.7rem;font-weight:600;">AWS</span>'
            if cloud == "AWS"
            else f'<span style="background:{COLORS["azure_blue"]};color:#fff;padding:1px 8px;border-radius:10px;font-size:0.7rem;font-weight:600;">Azure</span>'
        )

        row_left, row_right = st.columns([10, 1])
        with row_left:
            st.markdown(
                f"""
                <div style="
                    display:flex;align-items:center;gap:16px;
                    background:{COLORS['surface']};
                    border:1px solid {COLORS['border']};
                    border-radius:10px;
                    padding:12px 20px;
                    margin-bottom:6px;
                ">
                    <div style="min-width:90px;font-family:monospace;font-size:0.8rem;color:{COLORS['text_dim']};">
                        {run_id[:12]}…
                    </div>
                    <div style="flex:1;font-weight:600;color:{COLORS['text']};font-size:0.9rem;">
                        {scenario_id}
                    </div>
                    {cloud_pill}
                    {badge}
                    <div style="color:{COLORS['text_dim']};font-size:0.78rem;min-width:80px;text-align:right;">
                        ${cost:.4f}
                    </div>
                    <div style="color:{COLORS['text_dim']};font-size:0.78rem;min-width:140px;text-align:right;">
                        {date_str}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with row_right:
            if st.button("View", key=f"view_{run_id}"):
                st.session_state["intel_run_id"] = run_id
                st.switch_page("pages/4_📊_Intel_Reports.py")
else:
    st.info("No simulation runs yet. Launch your first mission to see data here.")

# ── Architecture Pipeline ─────────────────────────────────────────
st.markdown("<div style='height:24px;'></div>", unsafe_allow_html=True)

with st.expander("🏗️ System Architecture", expanded=False):
    st.markdown(
        f"""
        <div style="
            background:{COLORS['surface']};
            border:1px solid {COLORS['border']};
            border-radius:12px;
            padding:24px;
            font-family:monospace;
            font-size:0.82rem;
            color:{COLORS['text_dim']};
            line-height:1.7;
            overflow-x:auto;
        ">
            <span style="color:{COLORS['primary']};font-weight:700;">START</span><br>
            &nbsp;&nbsp;│<br>
            &nbsp;&nbsp;▼<br>
            <span style="color:{COLORS['info']};">🔍 fetch_cobra_intel</span> → Live attack intel from GitHub<br>
            &nbsp;&nbsp;│<br>
            &nbsp;&nbsp;├─ <span style="color:{COLORS['accent']};">🤖 generate_scenario</span> (AI freeform) ─┐<br>
            &nbsp;&nbsp;└─ <span style="color:{COLORS['accent']};">📋 plan_attack</span> (scenario mode) ──────┤<br>
            &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;│<br>
            &nbsp;&nbsp;▼<br>
            <span style="color:{COLORS['text']};">👁️ review_plan</span> → Human checkpoint #1<br>
            &nbsp;&nbsp;│<br>
            &nbsp;&nbsp;▼<br>
            <span style="color:{COLORS['accent']};">🏗️ generate_infrastructure</span> → AI → Terraform HCL<br>
            &nbsp;&nbsp;│<br>
            &nbsp;&nbsp;▼<br>
            <span style="color:{COLORS['warning']};">🛡️ safety_check</span> → Regex + terraform plan validation<br>
            &nbsp;&nbsp;│<br>
            &nbsp;&nbsp;▼<br>
            <span style="color:{COLORS['text']};">✅ approve_deploy</span> → Human checkpoint #2<br>
            &nbsp;&nbsp;│<br>
            &nbsp;&nbsp;├─ 🔵 dry_run → <span style="color:{COLORS['info']};">generate_report → END</span><br>
            &nbsp;&nbsp;├─ 🔴 unsafe → <span style="color:{COLORS['danger']};">generate_report → END</span><br>
            &nbsp;&nbsp;│<br>
            &nbsp;&nbsp;▼<br>
            <span style="color:{COLORS['primary']};">🚀 deploy_infrastructure</span> → terraform apply (↻ retry×3)<br>
            &nbsp;&nbsp;│<br>
            &nbsp;&nbsp;▼<br>
            <span style="color:{COLORS['danger']};">⚔️ execute_simulator</span> → Cloud SDK attack actions<br>
            &nbsp;&nbsp;│<br>
            &nbsp;&nbsp;▼<br>
            <span style="color:{COLORS['success']};">🔎 validator</span> → Cortex XDR / Simulated detection<br>
            &nbsp;&nbsp;│<br>
            &nbsp;&nbsp;▼<br>
            <span style="color:{COLORS['text']};">🗑️ confirm_teardown</span> → Human checkpoint #3<br>
            &nbsp;&nbsp;│<br>
            &nbsp;&nbsp;▼<br>
            <span style="color:{COLORS['warning']};">💥 teardown</span> → terraform destroy<br>
            &nbsp;&nbsp;│<br>
            &nbsp;&nbsp;▼<br>
            <span style="color:{COLORS['info']};">🧹 erasure_validator</span> → Verify all resources destroyed<br>
            &nbsp;&nbsp;│<br>
            &nbsp;&nbsp;▼<br>
            <span style="color:{COLORS['accent']};">📊 generate_report</span> → Markdown + JSON + ATT&CK Navigator<br>
            &nbsp;&nbsp;│<br>
            <span style="color:{COLORS['primary']};font-weight:700;">END</span>
        </div>
        """,
        unsafe_allow_html=True,
    )
