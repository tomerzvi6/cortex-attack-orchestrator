"""
Simulation timeline component — Plotly Gantt-style chart for attack actions.
"""

from __future__ import annotations

import plotly.graph_objects as go

from dashboard.theme import COLORS

_RESULT_COLORS = {
    "success": COLORS["success"],
    "failed": COLORS["danger"],
    "skipped": COLORS["text_dim"],
}


def render_simulation_timeline(sim_results: list[dict]) -> go.Figure:
    """
    Render a horizontal bar chart showing the simulation action timeline.

    Args:
        sim_results: List of SimulationAction dicts from the report.

    Returns:
        plotly.graph_objects.Figure
    """
    if not sim_results:
        fig = go.Figure()
        fig.add_annotation(text="No simulation actions recorded", showarrow=False,
                           font=dict(size=14, color=COLORS["text_dim"]))
        fig.update_layout(paper_bgcolor=COLORS["bg"], plot_bgcolor=COLORS["bg"], height=200)
        return fig

    labels = []
    colors = []
    hover_texts = []

    for i, action in enumerate(sim_results):
        act_name = action.get("action", f"Step {i+1}")
        result = action.get("result", "unknown")
        target = action.get("target_resource", "")
        details = action.get("details", "")
        ts = action.get("timestamp", "")

        labels.append(f"{i+1}. {act_name}")
        colors.append(_RESULT_COLORS.get(result, COLORS["text_dim"]))
        hover_texts.append(
            f"<b>{act_name}</b><br>"
            f"Result: {result}<br>"
            f"Target: {target}<br>"
            f"Details: {details[:80]}<br>"
            f"Time: {ts}"
        )

    fig = go.Figure(go.Bar(
        y=labels,
        x=[1] * len(labels),
        orientation="h",
        marker_color=colors,
        hovertext=hover_texts,
        hoverinfo="text",
        showlegend=False,
    ))

    fig.update_layout(
        title=dict(
            text="Simulation Timeline",
            font=dict(color=COLORS["text"], size=16),
        ),
        paper_bgcolor=COLORS["bg"],
        plot_bgcolor=COLORS["surface"],
        font=dict(color=COLORS["text_dim"]),
        xaxis=dict(visible=False),
        yaxis=dict(
            autorange="reversed",
            tickfont=dict(size=11, color=COLORS["text"]),
            gridcolor=COLORS["border"],
        ),
        height=max(200, len(labels) * 50 + 80),
        margin=dict(l=250, r=30, t=50, b=20),
    )

    return fig


def render_llm_cost_chart(llm_usage: dict) -> go.Figure:
    """
    Render a bar chart of LLM cost per node.

    Args:
        llm_usage: The llm_usage section from report.json.

    Returns:
        plotly.graph_objects.Figure
    """
    calls = llm_usage.get("calls", [])
    if not calls:
        fig = go.Figure()
        fig.add_annotation(text="No LLM usage data", showarrow=False,
                           font=dict(size=14, color=COLORS["text_dim"]))
        fig.update_layout(paper_bgcolor=COLORS["bg"], plot_bgcolor=COLORS["bg"], height=200)
        return fig

    nodes = [c.get("node", "?") for c in calls]
    costs = [c.get("estimated_cost_usd", 0) for c in calls]
    tokens = [c.get("total_tokens", 0) for c in calls]
    durations = [c.get("duration_ms", 0) for c in calls]

    hover_texts = [
        f"<b>{n}</b><br>"
        f"Cost: ${c:.4f}<br>"
        f"Tokens: {t:,}<br>"
        f"Latency: {d:.0f}ms"
        for n, c, t, d in zip(nodes, costs, tokens, durations)
    ]

    fig = go.Figure()

    fig.add_trace(go.Bar(
        x=nodes,
        y=costs,
        marker_color=COLORS["accent"],
        hovertext=hover_texts,
        hoverinfo="text",
        name="Cost (USD)",
    ))

    fig.update_layout(
        title=dict(
            text="LLM Cost Breakdown by Node",
            font=dict(color=COLORS["text"], size=16),
        ),
        paper_bgcolor=COLORS["bg"],
        plot_bgcolor=COLORS["surface"],
        font=dict(color=COLORS["text_dim"]),
        xaxis=dict(gridcolor=COLORS["border"]),
        yaxis=dict(
            title="Cost (USD)",
            gridcolor=COLORS["border"],
            tickformat="$.4f",
        ),
        height=350,
        margin=dict(t=50, b=40),
    )

    return fig
