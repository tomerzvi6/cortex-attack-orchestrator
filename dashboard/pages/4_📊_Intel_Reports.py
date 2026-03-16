"""
📊 Intel Reports — Browse, analyze and compare past simulation reports.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import plotly.graph_objects as go
import streamlit as st

_project_root = Path(__file__).resolve().parent.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from dashboard.theme import COLORS, apply_theme, status_badge, metric_card
from dashboard.services.report_loader import (
    load_all_reports,
    get_report_markdown,
    get_navigator_json,
)
from dashboard.components.run_timeline import render_simulation_timeline, render_llm_cost_chart

apply_theme()

# ── Header ────────────────────────────────────────────────────────
st.markdown(
    f"""
    <div style="margin-bottom:20px;">
        <span style="font-size:1.6rem;font-weight:800;color:{COLORS['primary']};">
            📊 Intel Reports
        </span>
        <span style="color:{COLORS['text_dim']};font-size:0.9rem;margin-left:12px;">
            Detailed analysis of past simulation runs
        </span>
    </div>
    """,
    unsafe_allow_html=True,
)

# ── Load reports ──────────────────────────────────────────────────
reports = load_all_reports()

if not reports:
    st.info("No reports found. Run a simulation to generate reports.")
    st.stop()

# ── Report selector table ─────────────────────────────────────────
st.markdown(
    f"<h4 style='color:{COLORS['text']};margin-bottom:8px;'>Select a Run</h4>",
    unsafe_allow_html=True,
)

# Build selection data
report_options = []
for r in reports:
    meta = r.get("metadata", {})
    run_id = meta.get("run_id", "?")
    scenario_id = meta.get("scenario_id", "?")
    date_str = meta.get("generated_at", "")[:19]
    is_dry = meta.get("dry_run", False)
    detected = r.get("validation_result", {}).get("detected")
    risk = r.get("risk_level", "unknown")
    cost = r.get("llm_usage", {}).get("summary", {}).get("total_estimated_cost_usd", 0)

    if is_dry:
        status_label = "🔵 Dry Run"
    elif detected is True:
        status_label = "✅ Detected"
    elif detected is False:
        status_label = "❌ Not Detected"
    else:
        status_label = "⚪ N/A"

    report_options.append({
        "run_id": run_id,
        "label": f"{status_label}  {scenario_id}  —  {run_id[:12]}…  ({date_str})",
        "scenario_id": scenario_id,
        "date": date_str,
        "status": status_label,
        "risk": risk,
        "cost": cost,
    })

selected_idx = st.selectbox(
    "Run",
    options=range(len(report_options)),
    format_func=lambda i: report_options[i]["label"],
    label_visibility="collapsed",
)

if selected_idx is None:
    st.stop()

report = reports[selected_idx]
meta = report.get("metadata", {})
run_id = meta.get("run_id", "?")

st.markdown(f"<div style='height:12px;'></div>", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════
#  Report Detail View
# ══════════════════════════════════════════════════════════════════

# ── Executive Summary Metrics ─────────────────────────────────────
m1, m2, m3, m4 = st.columns(4)

with m1:
    st.markdown(
        metric_card("Run ID", run_id[:12] + "…", "🆔", COLORS["info"]),
        unsafe_allow_html=True,
    )
with m2:
    scenario_id = meta.get("scenario_id", "?")
    st.markdown(
        metric_card("Scenario", scenario_id, "📋", COLORS["accent"]),
        unsafe_allow_html=True,
    )
with m3:
    risk = report.get("risk_level", "unknown")
    risk_color = {"high": COLORS["danger"], "medium": COLORS["warning"], "low": COLORS["success"], "dry_run": COLORS["info"]}.get(risk, COLORS["text_dim"])
    st.markdown(
        metric_card("Risk Level", risk.replace("_", " ").title(), "⚠️", risk_color),
        unsafe_allow_html=True,
    )
with m4:
    cost = report.get("llm_usage", {}).get("summary", {}).get("total_estimated_cost_usd", 0)
    st.markdown(
        metric_card("Total LLM Cost", f"${cost:.4f}", "💰", COLORS["accent"]),
        unsafe_allow_html=True,
    )

st.markdown("<div style='height:16px;'></div>", unsafe_allow_html=True)

# ── Detection Verdict ─────────────────────────────────────────────
val = report.get("validation_result", {})
detected = val.get("detected")
is_dry = meta.get("dry_run", False)

if is_dry:
    st.info("🔵 **Dry Run** — no cloud resources were deployed.")
elif detected is True:
    source = val.get("source", "N/A")
    conf = val.get("confidence", "N/A")
    details = val.get("details", "")
    st.success(f"🟢 **Detected** by **{source}** — confidence: **{conf}**\n\n{details}")
elif detected is False:
    st.error("🔴 **Not Detected** — defense gap identified. This attack bypassed detection.")
else:
    st.warning("Detection result not available for this run.")

# ── Tabs for report sections ──────────────────────────────────────
tab_mitre, tab_infra, tab_timeline, tab_llm, tab_raw = st.tabs([
    "🗺️ MITRE Mapping",
    "🏗️ Infrastructure",
    "⚔️ Simulation Timeline",
    "🤖 LLM Observability",
    "📄 Raw Report",
])

# ── TAB: MITRE Mapping ───────────────────────────────────────────
with tab_mitre:
    plan = report.get("attack_plan", {})
    techniques = plan.get("mitre_techniques", [])
    steps = plan.get("steps", [])

    if techniques:
        st.markdown(f"<h4 style='color:{COLORS['text']};'>Mapped Techniques ({len(techniques)})</h4>", unsafe_allow_html=True)

        for t in techniques:
            tid = t.get("id", "")
            name = t.get("name", "")
            tactic = t.get("tactic", "")
            desc = t.get("description", "")
            url = t.get("url", "")

            link_html = f' <a href="{url}" target="_blank" style="color:{COLORS["info"]};font-size:0.75rem;">🔗 ATT&CK</a>' if url else ""

            st.markdown(
                f"""
                <div style="
                    display:flex;align-items:flex-start;gap:12px;
                    padding:12px 16px;margin-bottom:6px;
                    background:{COLORS['surface']};
                    border:1px solid {COLORS['border']};
                    border-radius:10px;
                    border-left:4px solid {COLORS['info']};
                ">
                    <div style="min-width:80px;">
                        <span style="background:{COLORS['surface_alt']};color:{COLORS['info']};
                            padding:3px 10px;border-radius:8px;font-size:0.82rem;
                            font-weight:700;border:1px solid {COLORS['border']};">
                            {tid}
                        </span>
                    </div>
                    <div style="flex:1;">
                        <div style="color:{COLORS['text']};font-weight:600;font-size:0.9rem;">
                            {name}{link_html}
                        </div>
                        <div style="color:{COLORS['text_dim']};font-size:0.78rem;margin-top:2px;">
                            <b>Tactic:</b> {tactic}
                        </div>
                        <div style="color:{COLORS['text_dim']};font-size:0.82rem;margin-top:4px;">
                            {desc}
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    if steps:
        st.markdown(f"<h4 style='color:{COLORS['text']};margin-top:20px;'>Attack Steps ({len(steps)})</h4>", unsafe_allow_html=True)
        for s in steps:
            st.markdown(
                f"""<div style="padding:8px 12px;margin-bottom:3px;background:{COLORS['surface']};
                    border-left:3px solid {COLORS['primary']};border-radius:0 8px 8px 0;">
                    <span style="color:{COLORS['primary']};font-weight:700;">{s.get('step_number', '?')}.</span>
                    <span style="color:{COLORS['text']};font-size:0.88rem;">{s.get('description', '')}</span>
                    <span style="color:{COLORS['text_dim']};font-size:0.75rem;margin-left:8px;">
                        [{s.get('mitre_technique_id', '')}]
                    </span>
                </div>""",
                unsafe_allow_html=True,
            )

# ── TAB: Infrastructure ──────────────────────────────────────────
with tab_infra:
    infra = report.get("infrastructure", {})

    ic1, ic2, ic3 = st.columns(3)
    with ic1:
        ds = infra.get("deploy_status", "?")
        ds_color = {"success": COLORS["success"], "pending": COLORS["info"], "failed": COLORS["danger"], "unsafe": COLORS["warning"]}.get(ds, COLORS["text_dim"])
        st.markdown(metric_card("Deploy Status", ds, "🚀", ds_color), unsafe_allow_html=True)
    with ic2:
        st.markdown(metric_card("Retries", infra.get("deploy_retries", 0), "🔄", COLORS["accent"]), unsafe_allow_html=True)
    with ic3:
        violations = infra.get("safety_violations", [])
        v_color = COLORS["danger"] if violations else COLORS["success"]
        st.markdown(metric_card("Safety Violations", len(violations), "🛡️", v_color), unsafe_allow_html=True)

    if violations:
        st.markdown(f"<h5 style='color:{COLORS['warning']};margin-top:16px;'>⚠️ Safety Violations</h5>", unsafe_allow_html=True)
        for v in violations:
            st.markdown(f"<div style='color:{COLORS['warning']};padding:4px 0;'>• {v}</div>", unsafe_allow_html=True)

    # Deploy errors
    errors = infra.get("deploy_error_history", [])
    if errors:
        with st.expander("🔧 Self-Healing Attempts"):
            for i, err in enumerate(errors):
                st.code(err, language="text")

    # Terraform code
    tf_code = infra.get("terraform_code", "")
    if tf_code:
        with st.expander("📝 Terraform Code", expanded=False):
            st.code(tf_code, language="hcl")

# ── TAB: Simulation Timeline ─────────────────────────────────────
with tab_timeline:
    sim_results = report.get("simulation_results", [])
    if sim_results:
        fig = render_simulation_timeline(sim_results)
        st.plotly_chart(fig, use_container_width=True)

        # Also show as table
        with st.expander("📋 Raw Simulation Data"):
            st.dataframe(
                [
                    {
                        "Timestamp": a.get("timestamp", ""),
                        "Action": a.get("action", ""),
                        "Target": a.get("target_resource", ""),
                        "Result": a.get("result", ""),
                        "Details": a.get("details", "")[:80],
                    }
                    for a in sim_results
                ],
                use_container_width=True,
                hide_index=True,
            )
    else:
        st.info("No simulation actions recorded for this run (likely a dry run).")

# ── TAB: LLM Observability ───────────────────────────────────────
with tab_llm:
    llm_usage = report.get("llm_usage", {})
    summary = llm_usage.get("summary", {})
    calls = llm_usage.get("calls", [])

    if summary:
        lm1, lm2, lm3, lm4 = st.columns(4)
        with lm1:
            st.markdown(metric_card("LLM Calls", summary.get("total_calls", 0), "🤖", COLORS["primary"]), unsafe_allow_html=True)
        with lm2:
            st.markdown(metric_card("Total Tokens", f"{summary.get('total_tokens', 0):,}", "📊", COLORS["info"]), unsafe_allow_html=True)
        with lm3:
            st.markdown(metric_card("Total Cost", f"${summary.get('total_estimated_cost_usd', 0):.4f}", "💰", COLORS["accent"]), unsafe_allow_html=True)
        with lm4:
            dur = summary.get("total_duration_ms", 0)
            st.markdown(metric_card("Total Latency", f"{dur/1000:.1f}s", "⏱️", COLORS["warning"]), unsafe_allow_html=True)

    if calls:
        fig = render_llm_cost_chart(llm_usage)
        st.plotly_chart(fig, use_container_width=True)

        with st.expander("📋 Per-Call Details"):
            st.dataframe(
                [
                    {
                        "Node": c.get("node", ""),
                        "Model": c.get("model", ""),
                        "Prompt Tokens": c.get("prompt_tokens", 0),
                        "Completion Tokens": c.get("completion_tokens", 0),
                        "Total Tokens": c.get("total_tokens", 0),
                        "Cost (USD)": f"${c.get('estimated_cost_usd', 0):.4f}",
                        "Latency": f"{c.get('duration_ms', 0):.0f}ms",
                    }
                    for c in calls
                ],
                use_container_width=True,
                hide_index=True,
            )

# ── TAB: Raw Report ──────────────────────────────────────────────
with tab_raw:
    tab_md, tab_json, tab_nav = st.tabs(["📄 Markdown", "📦 JSON", "🗺️ Navigator"])

    with tab_md:
        md_content = get_report_markdown(run_id)
        if md_content:
            st.markdown(md_content, unsafe_allow_html=True)
        else:
            st.info("Markdown report not available.")

    with tab_json:
        st.download_button(
            "📥 Download report.json",
            data=json.dumps(report, indent=2, default=str).encode(),
            file_name=f"report_{run_id[:12]}.json",
            mime="application/json",
        )
        with st.expander("Preview JSON", expanded=False):
            st.json(report)

    with tab_nav:
        nav_data = get_navigator_json(run_id)
        if nav_data:
            st.download_button(
                "📥 Download ATT&CK Navigator Layer",
                data=json.dumps(nav_data, indent=2).encode(),
                file_name=f"navigator_{run_id[:12]}.json",
                mime="application/json",
            )
            st.markdown(
                f"""
                <div style="color:{COLORS['text_dim']};font-size:0.85rem;margin:8px 0;">
                    Import this file into <a href="https://mitre-attack.github.io/attack-navigator/"
                    target="_blank" style="color:{COLORS['info']};">MITRE ATT&CK Navigator</a>
                    to visualise coverage.
                </div>
                """,
                unsafe_allow_html=True,
            )
            with st.expander("Preview Navigator JSON"):
                st.json(nav_data)
        else:
            st.info("Navigator layer not available for this run.")
