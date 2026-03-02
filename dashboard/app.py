"""
Streamlit-based demo dashboard for the Azure-Cortex Orchestrator.

Run with:
    streamlit run dashboard/app.py
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st

# Ensure the project root is importable
_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from azure_cortex_orchestrator.graph import compile_graph
from azure_cortex_orchestrator.scenarios.registry import ScenarioRegistry
from azure_cortex_orchestrator.state import create_initial_state

# ── Page config ───────────────────────────────────────────────────
st.set_page_config(
    page_title="Cortex Attack Orchestrator",
    layout="wide",
    page_icon="🛡️",
)

# ── Constants ─────────────────────────────────────────────────────
REPORTS_DIR = _project_root / "azure_cortex_orchestrator" / "reports"

ARCHITECTURE_DIAGRAM = """\
┌───────────────────────────────────────────────────────────────┐
│                     LangGraph StateGraph                      │
│                                                               │
│  START                                                        │
│    │                                                          │
│    ▼                                                          │
│  ┌──────────────┐     ┌─────────────────────────┐             │
│  │ plan_attack   │────▶│ generate_infrastructure │◀─┐         │
│  │ (OpenAI+ATT&CK)│    │ (OpenAI+Terraform)      │  │ retry  │
│  └──────────────┘     └──────────┬──────────────┘  │         │
│                                  │                  │         │
│                                  ▼                  │         │
│                       ┌──────────────────┐          │         │
│                       │  safety_check    │          │         │
│                       │  (guardrails)    │          │         │
│                       └────────┬─────────┘          │         │
│                     ┌──────────┼──────────┐         │         │
│                     │          │          │         │         │
│              [dry-run]    [unsafe]    [safe]        │         │
│                     │          │          │         │         │
│                     ▼          ▼          ▼         │         │
│                  report     report   ┌─────────────┐│         │
│                                     │deploy_infra  ├┘         │
│                                     │(terraform)   │          │
│                                     └──────┬───────┘          │
│                                            │                  │
│                                            ▼                  │
│                                   ┌────────────────┐          │
│                                   │execute_simulator│         │
│                                   │(Azure SDK)      │         │
│                                   └───────┬────────┘          │
│                                           │                   │
│                                           ▼                   │
│                                   ┌────────────────┐          │
│                                   │   validator     │         │
│                                   │(Cortex/Simulated)│        │
│                                   └───────┬────────┘          │
│                                           │                   │
│                                           ▼                   │
│                                   ┌────────────────┐          │
│                                   │   teardown     │          │
│                                   │(tf destroy)    │          │
│                                   └───────┬────────┘          │
│                                           │                   │
│                                           ▼                   │
│                                   ┌────────────────┐          │
│                                   │generate_report │          │
│                                   │(Markdown+JSON) │          │
│                                   └───────┬────────┘          │
│                                           │                   │
│                                          END                  │
└───────────────────────────────────────────────────────────────┘
"""


# ── Helpers ───────────────────────────────────────────────────────

def _get_registry() -> ScenarioRegistry:
    return ScenarioRegistry.get_instance()


def _list_past_runs() -> list[dict[str, str]]:
    """Scan reports/ for existing run folders and return metadata."""
    runs: list[dict[str, str]] = []
    if not REPORTS_DIR.is_dir():
        return runs
    for child in sorted(REPORTS_DIR.iterdir(), reverse=True):
        if child.is_dir() and (child / "report.md").exists():
            # Try to derive a date from report.json metadata
            date_str = ""
            json_path = child / "report.json"
            if json_path.exists():
                try:
                    data = json.loads(json_path.read_text(encoding="utf-8"))
                    date_str = data.get("metadata", {}).get("generated_at", "")
                except Exception:
                    pass
            runs.append({"run_id": child.name, "date": date_str, "path": str(child)})
    return runs


# ── Sidebar ───────────────────────────────────────────────────────

st.sidebar.header("🛡️ Cortex Attack Orchestrator")

registry = _get_registry()
scenarios = registry.list_all()
scenario_map = {s.id: s for s in scenarios}
scenario_ids = [s.id for s in scenarios]

selected_scenario_id = st.sidebar.selectbox(
    "Scenario",
    options=scenario_ids,
    index=0 if scenario_ids else None,
    help="Choose an attack scenario from the registry.",
)

selected_scenario = scenario_map.get(selected_scenario_id)  # type: ignore[arg-type]

default_goal = selected_scenario.goal_template if selected_scenario else ""
custom_goal = st.sidebar.text_area(
    "Custom Goal (optional)",
    value=default_goal,
    height=100,
    help="Override the scenario's default attack goal.",
)

dry_run = st.sidebar.checkbox("Dry Run Mode", value=True)

run_clicked = st.sidebar.button("🚀 Run Simulation")

# ── Tabs ──────────────────────────────────────────────────────────

tab_dashboard, tab_reports, tab_library = st.tabs(
    ["Dashboard", "Reports", "Scenario Library"],
)

# ══════════════════════════════════════════════════════════════════
#  TAB 1: Dashboard
# ══════════════════════════════════════════════════════════════════

with tab_dashboard:
    if run_clicked and selected_scenario_id:
        # --- Run the simulation with live status updates -----------
        with st.status("Running simulation…", expanded=True) as status:
            st.write("⏳ Compiling LangGraph orchestration graph…")
            compiled = compile_graph()

            goal = custom_goal or default_goal
            initial_state = create_initial_state(
                goal=goal,
                scenario_id=selected_scenario_id,
                dry_run=dry_run,
            )

            st.write("📝 Starting graph execution…")

            node_names = [
                "plan_attack",
                "generate_infrastructure",
                "safety_check",
                "deploy_infrastructure",
                "execute_simulator",
                "validator",
                "teardown",
                "generate_report",
            ]

            # Stream node-level updates and accumulate full state
            final_state = dict(initial_state)
            try:
                for event in compiled.stream(initial_state, stream_mode="updates"):
                    for node_name, node_output in event.items():
                        st.write(f"✅ **{node_name}** completed")
                        # Merge node output into accumulated state
                        if isinstance(node_output, dict):
                            final_state.update(node_output)
            except Exception as exc:
                st.error(f"Graph execution failed: {exc}")
                status.update(label="Execution failed", state="error")
                st.stop()

            status.update(label="Simulation complete!", state="complete")

        # --- Display results --------------------------------------
        if final_state:
            st.markdown("---")

            # Metric cards
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Run ID", final_state.get("run_id", "?")[:12] + "…")
            c2.metric("Scenario", final_state.get("scenario_id", "?"))
            c3.metric("Deploy Status", final_state.get("deploy_status", "?"))

            validation = final_state.get("validation_result", {})
            detected = validation.get("detected")
            if final_state.get("dry_run"):
                det_label = "Dry Run"
            elif detected is True:
                det_label = "✅ Detected"
            elif detected is False:
                det_label = "❌ Not Detected"
            else:
                det_label = "N/A"
            c4.metric("Detection Result", det_label)

            # MITRE ATT&CK table
            attack_plan = final_state.get("attack_plan", {})
            techniques = attack_plan.get("mitre_techniques", [])
            if techniques:
                st.subheader("MITRE ATT&CK Mapping")
                st.table(
                    [
                        {
                            "ID": t.get("id", ""),
                            "Name": t.get("name", ""),
                            "Tactic": t.get("tactic", ""),
                            "Description": t.get("description", "")[:120],
                        }
                        for t in techniques
                    ]
                )

            # Simulation timeline
            sim_results = final_state.get("simulation_results", [])
            if sim_results:
                st.subheader("Simulation Timeline")
                st.table(
                    [
                        {
                            "Timestamp": a.get("timestamp", ""),
                            "Action": a.get("action", ""),
                            "Target": a.get("target_resource", ""),
                            "Result": a.get("result", ""),
                            "Details": a.get("details", "")[:80],
                        }
                        for a in sim_results
                    ]
                )

            # Detection verdict
            if validation:
                st.subheader("Detection Verdict")
                if final_state.get("dry_run"):
                    st.info("🔵 **Dry Run** — no cloud resources were deployed.")
                elif detected is True:
                    st.success(
                        f"🟢 **Detected** by {validation.get('source', 'N/A')} "
                        f"(confidence: {validation.get('confidence', 'N/A')})"
                    )
                elif detected is False:
                    st.error("🔴 **Not Detected** — defense gap identified.")
                else:
                    st.warning("Detection result unavailable.")

            # Terraform code (expandable)
            tf_code = final_state.get("terraform_code", "")
            if tf_code:
                with st.expander("Generated Terraform Code"):
                    st.code(tf_code, language="hcl")

    else:
        # Welcome state
        st.title("Welcome to the Cortex Attack Orchestrator")
        st.markdown(
            "Use the sidebar to select a scenario and click **🚀 Run Simulation** "
            "to begin an AI-driven cloud attack simulation."
        )
        st.subheader("Architecture")
        st.code(ARCHITECTURE_DIAGRAM, language="text")

# ══════════════════════════════════════════════════════════════════
#  TAB 2: Reports
# ══════════════════════════════════════════════════════════════════

with tab_reports:
    st.subheader("Past Simulation Reports")
    past_runs = _list_past_runs()

    if not past_runs:
        st.info("No reports found yet. Run a simulation to generate one.")
    else:
        run_labels = [
            f"{r['run_id'][:12]}… — {r['date'][:19]}" if r["date"] else r["run_id"]
            for r in past_runs
        ]
        selected_idx = st.selectbox(
            "Select a run",
            options=range(len(run_labels)),
            format_func=lambda i: run_labels[i],
        )

        if selected_idx is not None:
            run_info = past_runs[selected_idx]
            run_path = Path(run_info["path"])

            # Render Markdown report
            md_path = run_path / "report.md"
            if md_path.exists():
                st.markdown(md_path.read_text(encoding="utf-8"), unsafe_allow_html=True)

            # Download JSON report
            json_path = run_path / "report.json"
            if json_path.exists():
                st.download_button(
                    "📥 Download report.json",
                    data=json_path.read_bytes(),
                    file_name=f"report_{run_info['run_id'][:12]}.json",
                    mime="application/json",
                )

# ══════════════════════════════════════════════════════════════════
#  TAB 3: Scenario Library
# ══════════════════════════════════════════════════════════════════

with tab_library:
    st.subheader("Scenario Library")

    if not scenarios:
        st.info("No scenarios registered.")
    else:
        for scenario in scenarios:
            with st.container():
                st.markdown(f"### {scenario.name}")
                st.markdown(f"**ID:** `{scenario.id}`")
                st.markdown(scenario.description)

                # MITRE technique badges
                if scenario.expected_mitre_techniques:
                    badge_md = " ".join(
                        f"`{t['id']} — {t['name']}`"
                        for t in scenario.expected_mitre_techniques
                    )
                    st.markdown(f"**MITRE Techniques:** {badge_md}")

                # Simulation steps count
                step_count = len(scenario.simulation_steps)
                st.markdown(f"**Simulation steps:** {step_count}")

                # Terraform resource types
                resource_types = scenario.terraform_hints.get("resource_types", [])
                if resource_types:
                    st.markdown(
                        "**Resource types:** "
                        + ", ".join(f"`{r}`" for r in resource_types)
                    )

                st.divider()
