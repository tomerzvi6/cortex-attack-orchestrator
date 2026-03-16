"""
Cortex Attack Orchestrator — Dashboard Entry Point

Multi-page Streamlit application with Palo Alto Networks dark theme.

Run with:
    streamlit run dashboard/app.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

# Ensure imports resolve
_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

# Must be the very first Streamlit call
st.set_page_config(
    page_title="Cortex Attack Orchestrator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Page registry ─────────────────────────────────────────────────
command_center = st.Page("pages/1_🏠_Command_Center.py",  title="Command Center",   icon="🏠", default=True)
launch_mission = st.Page("pages/2_🚀_Launch_Mission.py",  title="Launch Mission",    icon="🚀")
scenario_lib   = st.Page("pages/3_📚_Scenario_Arsenal.py", title="Scenario Arsenal", icon="📚")
intel_reports  = st.Page("pages/4_📊_Intel_Reports.py",   title="Intel Reports",     icon="📊")
mitre_coverage = st.Page("pages/5_🔬_MITRE_Coverage.py",  title="MITRE Coverage",    icon="🔬")

pg = st.navigation(
    {
        "Operations": [command_center, launch_mission],
        "Intelligence": [scenario_lib, intel_reports, mitre_coverage],
    }
)

# ── Apply theme ──────────────────────────────────────────────────
from dashboard.theme import COLORS, apply_theme  # noqa: E402

apply_theme()

# ── Sidebar branding ─────────────────────────────────────────────
with st.sidebar:
    st.markdown(
        f"""
        <div style="padding:12px 0 20px 0;border-bottom:1px solid {COLORS['border']};margin-bottom:16px;">
            <div style="font-size:1.4rem;font-weight:800;color:{COLORS['primary']};letter-spacing:-0.02em;">
                🛡️ Cortex Orchestrator
            </div>
            <div style="font-size:0.78rem;color:{COLORS['text_dim']};margin-top:4px;">
                AI-Driven Cloud Attack Simulation
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

# ── Init session state ───────────────────────────────────────────
if "launch_scenario_id" not in st.session_state:
    st.session_state.launch_scenario_id = None

# ── Run selected page ────────────────────────────────────────────
pg.run()
