"""
Cross-run analytics service.

Aggregates data from all historical reports to produce:
- KPI metrics (total runs, detection rate, avg cost, etc.)
- MITRE technique frequency and detection-rate maps
- Cloud provider breakdown
"""

from __future__ import annotations

from collections import Counter

import streamlit as st

from dashboard.services.report_loader import load_all_reports


@st.cache_data(ttl=30)
def get_aggregate_stats() -> dict:
    """
    Compute dashboard-level KPI metrics from all historical reports.

    Returns dict with keys:
        total_runs, detection_rate, avg_cost, total_cost,
        cloud_breakdown, risk_breakdown, scenarios_used,
        recent_runs (last 8).
    """
    reports = load_all_reports()
    total = len(reports)
    if total == 0:
        return {
            "total_runs": 0,
            "detection_rate": 0.0,
            "avg_cost": 0.0,
            "total_cost": 0.0,
            "cloud_breakdown": {},
            "risk_breakdown": {},
            "scenarios_used": set(),
            "recent_runs": [],
        }

    detected_count = 0
    dry_run_count = 0
    total_cost = 0.0
    cloud_counter: Counter[str] = Counter()
    risk_counter: Counter[str] = Counter()
    scenarios: set[str] = set()

    for r in reports:
        meta = r.get("metadata", {})
        scenario_id = meta.get("scenario_id", "unknown")
        scenarios.add(scenario_id)

        is_dry = meta.get("dry_run", False)
        if is_dry:
            dry_run_count += 1

        val = r.get("validation_result", {})
        if val.get("detected") is True:
            detected_count += 1

        usage = r.get("llm_usage", {})
        summary = usage.get("summary", {})
        total_cost += summary.get("total_estimated_cost_usd", 0.0)

        risk_counter[r.get("risk_level", "unknown")] += 1

        # Infer cloud provider from scenario or infrastructure
        infra = r.get("infrastructure", {})
        tf_code = infra.get("terraform_code", "")
        if "aws" in tf_code.lower() or "aws" in scenario_id.lower():
            cloud_counter["aws"] += 1
        else:
            cloud_counter["azure"] += 1

    live_runs = total - dry_run_count
    detection_rate = (detected_count / live_runs * 100) if live_runs > 0 else 0.0

    return {
        "total_runs": total,
        "detection_rate": round(detection_rate, 1),
        "avg_cost": round(total_cost / total, 4) if total else 0.0,
        "total_cost": round(total_cost, 4),
        "cloud_breakdown": dict(cloud_counter),
        "risk_breakdown": dict(risk_counter),
        "scenarios_used": scenarios,
        "recent_runs": reports[:8],
    }


@st.cache_data(ttl=30)
def get_mitre_coverage() -> dict:
    """
    Build a MITRE technique frequency + detection map from all runs.

    Returns dict:
        techniques: {
            "T1562.008": {
                "name": "...", "tactic": "...",
                "count": N, "detected_count": N,
                "runs": [run_id, ...]
            },
            ...
        }
        tactic_counts: {"Defense Evasion": N, ...}
        total_unique_techniques: int
    """
    reports = load_all_reports()
    techniques: dict[str, dict] = {}
    tactic_counter: Counter[str] = Counter()

    for r in reports:
        run_id = r.get("metadata", {}).get("run_id", "?")
        detected = r.get("validation_result", {}).get("detected", False)

        plan = r.get("attack_plan", {})
        for tech in plan.get("mitre_techniques", []):
            tid = tech.get("id", "")
            if not tid:
                continue

            if tid not in techniques:
                techniques[tid] = {
                    "name": tech.get("name", ""),
                    "tactic": tech.get("tactic", ""),
                    "count": 0,
                    "detected_count": 0,
                    "runs": [],
                }

            techniques[tid]["count"] += 1
            techniques[tid]["runs"].append(run_id)
            if detected:
                techniques[tid]["detected_count"] += 1

            tactic_counter[tech.get("tactic", "Unknown")] += 1

    return {
        "techniques": techniques,
        "tactic_counts": dict(tactic_counter),
        "total_unique_techniques": len(techniques),
    }
