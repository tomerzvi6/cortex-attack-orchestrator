"""
🔬 MITRE Coverage — Interactive ATT&CK technique heatmap and coverage analytics.
"""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

_project_root = Path(__file__).resolve().parent.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from dashboard.theme import COLORS, apply_theme, metric_card
from dashboard.services.analytics import get_mitre_coverage, get_aggregate_stats
from dashboard.components.mitre_heatmap import render_mitre_heatmap, render_tactic_donut

apply_theme()

# ── Header ────────────────────────────────────────────────────────
st.markdown(
    f"""
    <div style="margin-bottom:20px;">
        <span style="font-size:1.6rem;font-weight:800;color:{COLORS['primary']};">
            🔬 MITRE ATT&CK Coverage
        </span>
        <span style="color:{COLORS['text_dim']};font-size:0.9rem;margin-left:12px;">
            Aggregate analytics from all simulation runs
        </span>
    </div>
    """,
    unsafe_allow_html=True,
)

# ── Load data ─────────────────────────────────────────────────────
coverage = get_mitre_coverage()
stats = get_aggregate_stats()
techniques = coverage.get("techniques", {})
tactic_counts = coverage.get("tactic_counts", {})

if not techniques:
    st.info(
        "No MITRE technique data available yet. Run some simulations to see coverage analytics."
    )
    st.stop()

# ── KPI Cards ─────────────────────────────────────────────────────
k1, k2, k3, k4 = st.columns(4)

with k1:
    st.markdown(
        metric_card("Unique Techniques", coverage["total_unique_techniques"], "🗺️", COLORS["primary"]),
        unsafe_allow_html=True,
    )
with k2:
    total_sims = sum(t["count"] for t in techniques.values())
    st.markdown(
        metric_card("Total Simulations", total_sims, "⚔️", COLORS["accent"]),
        unsafe_allow_html=True,
    )
with k3:
    total_detected = sum(t["detected_count"] for t in techniques.values())
    det_rate = (total_detected / total_sims * 100) if total_sims > 0 else 0
    det_color = COLORS["success"] if det_rate >= 50 else COLORS["danger"]
    st.markdown(
        metric_card("Technique Detection Rate", f"{det_rate:.0f}%", "🎯", det_color),
        unsafe_allow_html=True,
    )
with k4:
    tactics_covered = len(tactic_counts)
    st.markdown(
        metric_card("Tactics Covered", f"{tactics_covered}/14", "📊", COLORS["info"]),
        unsafe_allow_html=True,
    )

st.markdown("<div style='height:20px;'></div>", unsafe_allow_html=True)

# ── Main heatmap ──────────────────────────────────────────────────
st.markdown(
    f"<h4 style='color:{COLORS['text']};margin-bottom:8px;'>Technique Coverage Heatmap</h4>",
    unsafe_allow_html=True,
)
fig_heatmap = render_mitre_heatmap(techniques)
st.plotly_chart(fig_heatmap, use_container_width=True)

# ── Two-column: Tactic donut + Detection gaps ────────────────────
col_donut, col_gaps = st.columns(2)

with col_donut:
    st.markdown(
        f"<h4 style='color:{COLORS['text']};margin-bottom:8px;'>Tactic Distribution</h4>",
        unsafe_allow_html=True,
    )
    fig_donut = render_tactic_donut(tactic_counts)
    st.plotly_chart(fig_donut, use_container_width=True)

with col_gaps:
    st.markdown(
        f"<h4 style='color:{COLORS['text']};margin-bottom:8px;'>🚨 Detection Gap Analysis</h4>",
        unsafe_allow_html=True,
    )

    # Find techniques that were tested but never detected
    gaps = []
    partial = []
    for tid, info in sorted(techniques.items(), key=lambda x: -x[1]["count"]):
        if info["count"] > 0 and info["detected_count"] == 0:
            gaps.append((tid, info))
        elif info["count"] > 0 and info["detected_count"] < info["count"]:
            partial.append((tid, info))

    if gaps:
        st.markdown(
            f"""<div style="
                background:{COLORS['surface']};
                border:1px solid {COLORS['danger']};
                border-radius:10px;
                padding:16px;
                margin-bottom:12px;
            ">
                <div style="color:{COLORS['danger']};font-weight:700;margin-bottom:8px;">
                    ❌ Never Detected ({len(gaps)} technique{'s' if len(gaps) != 1 else ''})
                </div>
            """,
            unsafe_allow_html=True,
        )
        for tid, info in gaps:
            st.markdown(
                f"""<div style="display:flex;gap:8px;align-items:center;padding:4px 0;">
                    <span style="background:{COLORS['surface_alt']};color:{COLORS['danger']};
                        padding:2px 8px;border-radius:8px;font-size:0.78rem;font-weight:600;
                        border:1px solid {COLORS['danger']}40;">{tid}</span>
                    <span style="color:{COLORS['text']};font-size:0.85rem;">{info['name']}</span>
                    <span style="color:{COLORS['text_dim']};font-size:0.75rem;">
                        ({info['count']} run{'s' if info['count'] != 1 else ''})
                    </span>
                </div>""",
                unsafe_allow_html=True,
            )
        st.markdown("</div>", unsafe_allow_html=True)
    else:
        st.markdown(
            f"""<div style="
                background:{COLORS['surface']};
                border:1px solid {COLORS['success']};
                border-radius:10px;
                padding:16px;
            ">
                <div style="color:{COLORS['success']};font-weight:700;">
                    ✅ All tested techniques were detected at least once!
                </div>
            </div>""",
            unsafe_allow_html=True,
        )

    if partial:
        st.markdown(
            f"<div style='margin-top:12px;color:{COLORS['warning']};font-weight:700;'>⚠️ Partial Detection ({len(partial)})</div>",
            unsafe_allow_html=True,
        )
        for tid, info in partial:
            rate = info["detected_count"] / info["count"] * 100
            st.markdown(
                f"""<div style="display:flex;gap:8px;align-items:center;padding:3px 0;">
                    <span style="background:{COLORS['surface_alt']};color:{COLORS['warning']};
                        padding:2px 8px;border-radius:8px;font-size:0.78rem;font-weight:600;
                        border:1px solid {COLORS['warning']}40;">{tid}</span>
                    <span style="color:{COLORS['text']};font-size:0.82rem;">{info['name']}</span>
                    <span style="color:{COLORS['text_dim']};font-size:0.75rem;">
                        {info['detected_count']}/{info['count']} ({rate:.0f}%)
                    </span>
                </div>""",
                unsafe_allow_html=True,
            )

st.markdown("<div style='height:20px;'></div>", unsafe_allow_html=True)

# ── Full technique table ──────────────────────────────────────────
with st.expander("📋 Full Technique Breakdown", expanded=False):
    table_data = []
    for tid, info in sorted(techniques.items()):
        det_rate = (info["detected_count"] / info["count"] * 100) if info["count"] > 0 else 0
        table_data.append({
            "Technique ID": tid,
            "Name": info["name"],
            "Tactic": info["tactic"],
            "Simulated": info["count"],
            "Detected": info["detected_count"],
            "Detection Rate": f"{det_rate:.0f}%",
            "Runs": len(info["runs"]),
        })
    st.dataframe(table_data, use_container_width=True, hide_index=True)
