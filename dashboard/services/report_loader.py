"""
Report data loading and caching service.

Scans the reports/ directory for completed runs, parses report.json files,
and provides cached aggregate statistics for the dashboard.
"""

from __future__ import annotations

import json
from pathlib import Path

import streamlit as st

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
REPORTS_DIR = _PROJECT_ROOT / "azure_cortex_orchestrator" / "reports"


@st.cache_data(ttl=30)
def load_all_reports() -> list[dict]:
    """
    Scan reports/ directory and load every report.json.

    Returns a list of parsed dicts, sorted newest-first.
    """
    reports: list[dict] = []
    if not REPORTS_DIR.is_dir():
        return reports

    for child in REPORTS_DIR.iterdir():
        if not child.is_dir():
            continue
        json_path = child / "report.json"
        if not json_path.exists():
            continue
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
            data["_run_dir"] = str(child)
            reports.append(data)
        except Exception:
            continue

    # Sort by generated_at descending
    reports.sort(
        key=lambda r: r.get("metadata", {}).get("generated_at", ""),
        reverse=True,
    )
    return reports


def get_report(run_id: str) -> dict | None:
    """Load a single report by run_id."""
    run_dir = REPORTS_DIR / run_id
    json_path = run_dir / "report.json"
    if not json_path.exists():
        return None
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["_run_dir"] = str(run_dir)
        return data
    except Exception:
        return None


def get_report_markdown(run_id: str) -> str | None:
    """Load the Markdown report for a given run_id."""
    md_path = REPORTS_DIR / run_id / "report.md"
    if not md_path.exists():
        return None
    return md_path.read_text(encoding="utf-8")


def get_navigator_json(run_id: str) -> dict | None:
    """Load the ATT&CK Navigator layer JSON for a given run_id."""
    nav_path = REPORTS_DIR / run_id / "attack_navigator_layer.json"
    if not nav_path.exists():
        return None
    try:
        return json.loads(nav_path.read_text(encoding="utf-8"))
    except Exception:
        return None
