"""
📚 Scenario Arsenal — Visual scenario browser with cards, filtering, and details.
"""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

_project_root = Path(__file__).resolve().parent.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from dashboard.theme import COLORS, apply_theme, cloud_badge, status_badge
from dashboard.components.scenario_card import render_scenario_card
from azure_cortex_orchestrator.scenarios.registry import ScenarioRegistry

apply_theme()

# ── Header ────────────────────────────────────────────────────────
st.markdown(
    f"""
    <div style="margin-bottom:20px;">
        <span style="font-size:1.6rem;font-weight:800;color:{COLORS['primary']};">
            📚 Scenario Arsenal
        </span>
        <span style="color:{COLORS['text_dim']};font-size:0.9rem;margin-left:12px;">
            Pre-built attack scenarios ready to deploy
        </span>
    </div>
    """,
    unsafe_allow_html=True,
)

# ── Registry ──────────────────────────────────────────────────────
registry = ScenarioRegistry.get_instance()
scenarios = registry.list_all()

if not scenarios:
    st.info("No scenarios registered in the scenario registry.")
    st.stop()

# ── Filter bar ────────────────────────────────────────────────────
fc1, fc2, fc3 = st.columns([2, 2, 4])

with fc1:
    cloud_filter = st.selectbox(
        "Cloud Provider",
        options=["All", "Azure", "AWS"],
        index=0,
    )

with fc2:
    # Collect all unique tactics
    all_tactics: set[str] = set()
    for s in scenarios:
        for t in s.expected_mitre_techniques:
            all_tactics.add(t.get("tactic", ""))
    all_tactics.discard("")
    tactic_options = ["All"] + sorted(all_tactics)
    tactic_filter = st.selectbox("MITRE Tactic", options=tactic_options, index=0)

with fc3:
    search_query = st.text_input(
        "Search",
        placeholder="Search by name, ID, or description…",
    )

# ── Apply filters ─────────────────────────────────────────────────
filtered = scenarios

if cloud_filter != "All":
    filtered = [s for s in filtered if s.cloud_provider.lower() == cloud_filter.lower()]

if tactic_filter != "All":
    filtered = [
        s for s in filtered
        if any(tactic_filter.lower() in t.get("tactic", "").lower() for t in s.expected_mitre_techniques)
    ]

if search_query.strip():
    q = search_query.strip().lower()
    filtered = [
        s for s in filtered
        if q in s.id.lower() or q in s.name.lower() or q in s.description.lower()
    ]

# ── Stats bar ─────────────────────────────────────────────────────
azure_count = sum(1 for s in scenarios if s.cloud_provider.lower() == "azure")
aws_count = sum(1 for s in scenarios if s.cloud_provider.lower() == "aws")

st.markdown(
    f"""
    <div style="
        display:flex;gap:16px;align-items:center;
        margin: 12px 0 20px 0;
        padding:10px 16px;
        background:{COLORS['surface']};
        border:1px solid {COLORS['border']};
        border-radius:10px;
    ">
        <span style="color:{COLORS['text_dim']};font-size:0.85rem;">
            Showing <b style="color:{COLORS['text']};">{len(filtered)}</b> of {len(scenarios)} scenarios
        </span>
        <span style="color:{COLORS['text_dim']};font-size:0.8rem;">•</span>
        {cloud_badge('azure')} <span style="color:{COLORS['text_dim']};font-size:0.8rem;">{azure_count}</span>
        {cloud_badge('aws')} <span style="color:{COLORS['text_dim']};font-size:0.8rem;">{aws_count}</span>
    </div>
    """,
    unsafe_allow_html=True,
)

# ── Scenario cards — 2 columns ───────────────────────────────────
if not filtered:
    st.warning("No scenarios match your filters.")
else:
    # Two-column card grid
    for i in range(0, len(filtered), 2):
        cols = st.columns(2)
        for j, col in enumerate(cols):
            idx = i + j
            if idx >= len(filtered):
                break
            scenario = filtered[idx]
            with col:
                st.markdown(render_scenario_card(scenario), unsafe_allow_html=True)

                bc1, bc2 = st.columns(2)
                with bc1:
                    if st.button(f"🚀 Launch", key=f"launch_{scenario.id}", use_container_width=True):
                        st.session_state.launch_scenario_id = scenario.id
                        st.switch_page("pages/2_🚀_Launch_Mission.py")
                with bc2:
                    if st.button(f"📄 Details", key=f"details_{scenario.id}", use_container_width=True):
                        st.session_state[f"show_detail_{scenario.id}"] = not st.session_state.get(
                            f"show_detail_{scenario.id}", False
                        )

                # Detail expander
                if st.session_state.get(f"show_detail_{scenario.id}", False):
                    detail_html = f"""
                        <div style="
                            background:{COLORS['surface_alt']};
                            border:1px solid {COLORS['border']};
                            border-radius:10px;
                            padding:16px;
                            margin-top:8px;
                            margin-bottom:16px;
                        ">
                            <div style="color:{COLORS['primary']};font-weight:700;margin-bottom:8px;">
                                Attack Goal
                            </div>
                            <div style="color:{COLORS['text']};font-size:0.85rem;margin-bottom:16px;line-height:1.5;">
                                {scenario.goal_template}
                            </div>
                        """

                    # MITRE techniques
                    if scenario.expected_mitre_techniques:
                        detail_html += f"<div style='color:{COLORS['primary']};font-weight:700;margin-bottom:8px;'>MITRE ATT&CK Techniques</div>"
                        for t in scenario.expected_mitre_techniques:
                            detail_html += f"""<div style="display:flex;gap:8px;align-items:center;margin-bottom:4px;">
                                    <span style="background:{COLORS['surface']};color:{COLORS['info']};
                                        padding:2px 8px;border-radius:8px;font-size:0.78rem;
                                        border:1px solid {COLORS['border']};font-weight:600;">
                                        {t.get('id', '')}
                                    </span>
                                    <span style="color:{COLORS['text']};font-size:0.82rem;">
                                        {t.get('name', '')}
                                    </span>
                                    <span style="color:{COLORS['text_dim']};font-size:0.75rem;">
                                        ({t.get('tactic', '')})
                                    </span>
                                </div>"""

                    # Simulation steps
                    if scenario.simulation_steps:
                        detail_html += f"<div style='color:{COLORS['primary']};font-weight:700;margin:12px 0 8px;'>Simulation Steps</div>"
                        for step in scenario.simulation_steps:
                            detail_html += f"""<div style="display:flex;gap:8px;padding:6px 0;border-bottom:1px solid {COLORS['border']};">
                                    <span style="color:{COLORS['primary']};font-weight:700;min-width:20px;">{step.order}.</span>
                                    <div>
                                        <div style="color:{COLORS['text']};font-size:0.85rem;font-weight:600;">{step.name}</div>
                                        <div style="color:{COLORS['text_dim']};font-size:0.78rem;">{step.description}</div>
                                        <code style="color:{COLORS['accent']};font-size:0.72rem;background:{COLORS['surface']};
                                            padding:1px 6px;border-radius:4px;">{step.sdk_action}</code>
                                    </div>
                                </div>"""

                    # Terraform hints
                    hints = scenario.terraform_hints
                    if hints:
                        resource_types = hints.get("resource_types", [])
                        if resource_types:
                            detail_html += f"<div style='color:{COLORS['primary']};font-weight:700;margin:12px 0 8px;'>Terraform Resources</div>"
                            pills = " ".join(
                                f'<span style="background:{COLORS["surface"]};color:{COLORS["text_dim"]};'
                                f'padding:2px 8px;border-radius:8px;font-size:0.72rem;'
                                f'border:1px solid {COLORS["border"]};margin-right:4px;">{rt}</span>'
                                for rt in resource_types
                            )
                            detail_html += pills

                    # Detection expectations
                    det_exp = scenario.detection_expectations
                    if det_exp:
                        ops = det_exp.get("expected_activity_log_operations", [])
                        window = det_exp.get("detection_window_minutes", "?")
                        if ops:
                            detail_html += f"""<div style='margin-top:12px;'>
                                    <span style='color:{COLORS["primary"]};font-weight:700;'>Detection Expectations</span>
                                    <span style='color:{COLORS["text_dim"]};font-size:0.78rem;margin-left:8px;'>
                                        (window: {window} min)
                                    </span>
                                </div>"""
                            for op in ops:
                                detail_html += f'<div style="color:{COLORS["warning"]};font-size:0.8rem;padding:2px 0;">⚠️ {op}</div>'

                    detail_html += "</div>"
                    st.markdown(detail_html, unsafe_allow_html=True)

                st.markdown("<div style='height:16px;'></div>", unsafe_allow_html=True)
