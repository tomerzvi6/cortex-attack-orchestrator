"""
MITRE ATT&CK heatmap component — interactive Plotly visualisation.
"""

from __future__ import annotations

import plotly.graph_objects as go

from dashboard.theme import COLORS

# Canonical MITRE ATT&CK tactic ordering
TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


def render_mitre_heatmap(techniques: dict[str, dict]) -> go.Figure:
    """
    Build a Plotly heatmap of MITRE technique usage.

    Args:
        techniques: Dict from analytics.get_mitre_coverage()["techniques"].
                    Keys are technique IDs, values have:
                    name, tactic, count, detected_count, runs.

    Returns:
        plotly.graph_objects.Figure
    """
    if not techniques:
        fig = go.Figure()
        fig.add_annotation(text="No MITRE data available yet", showarrow=False,
                           font=dict(size=16, color=COLORS["text_dim"]))
        fig.update_layout(
            paper_bgcolor=COLORS["bg"],
            plot_bgcolor=COLORS["bg"],
        )
        return fig

    # Group techniques by tactic
    tactic_groups: dict[str, list[tuple[str, dict]]] = {t: [] for t in TACTIC_ORDER}
    for tid, info in techniques.items():
        tactic = info.get("tactic", "Unknown")
        # Find closest tactic match
        matched = False
        for canonical in TACTIC_ORDER:
            if canonical.lower() in tactic.lower() or tactic.lower() in canonical.lower():
                tactic_groups[canonical].append((tid, info))
                matched = True
                break
        if not matched:
            tactic_groups.setdefault(tactic, []).append((tid, info))

    # Filter to tactics that have data
    active_tactics = [t for t in TACTIC_ORDER if tactic_groups.get(t)]

    if not active_tactics:
        fig = go.Figure()
        fig.add_annotation(text="No mappable techniques found", showarrow=False,
                           font=dict(size=16, color=COLORS["text_dim"]))
        fig.update_layout(paper_bgcolor=COLORS["bg"], plot_bgcolor=COLORS["bg"])
        return fig

    # Build data for grouped bar chart (techniques per tactic, colored by count)
    x_labels = []
    y_counts = []
    y_detected = []
    colors = []
    hover_texts = []

    for tactic in active_tactics:
        for tid, info in sorted(tactic_groups[tactic], key=lambda x: -x[1]["count"]):
            label = f"{tid}\n{info['name'][:25]}"
            x_labels.append(label)
            y_counts.append(info["count"])
            y_detected.append(info["detected_count"])
            det_rate = (info["detected_count"] / info["count"] * 100) if info["count"] > 0 else 0
            hover_texts.append(
                f"<b>{tid}</b>: {info['name']}<br>"
                f"Tactic: {info['tactic']}<br>"
                f"Simulated: {info['count']}x<br>"
                f"Detected: {info['detected_count']}x ({det_rate:.0f}%)<br>"
                f"Runs: {len(info['runs'])}"
            )
            # Color: green if high detection, red if low
            if info["count"] == 0:
                colors.append(COLORS["text_dim"])
            elif det_rate >= 70:
                colors.append(COLORS["success"])
            elif det_rate >= 30:
                colors.append(COLORS["warning"])
            else:
                colors.append(COLORS["danger"])

    fig = go.Figure()

    fig.add_trace(go.Bar(
        x=x_labels,
        y=y_counts,
        name="Simulations",
        marker_color=COLORS["primary"],
        hovertext=hover_texts,
        hoverinfo="text",
        opacity=0.85,
    ))

    fig.add_trace(go.Bar(
        x=x_labels,
        y=y_detected,
        name="Detected",
        marker_color=COLORS["success"],
        hovertext=hover_texts,
        hoverinfo="text",
        opacity=0.85,
    ))

    fig.update_layout(
        barmode="overlay",
        title=dict(
            text="MITRE ATT&CK Technique Coverage",
            font=dict(color=COLORS["text"], size=18),
        ),
        paper_bgcolor=COLORS["bg"],
        plot_bgcolor=COLORS["surface"],
        font=dict(color=COLORS["text_dim"], size=11),
        xaxis=dict(
            tickangle=-45,
            gridcolor=COLORS["border"],
            tickfont=dict(size=9),
        ),
        yaxis=dict(
            title="Count",
            gridcolor=COLORS["border"],
        ),
        legend=dict(
            bgcolor=COLORS["surface"],
            bordercolor=COLORS["border"],
            font=dict(color=COLORS["text"]),
        ),
        margin=dict(b=120, t=60),
        height=450,
    )

    return fig


def render_tactic_donut(tactic_counts: dict[str, int]) -> go.Figure:
    """Render a donut chart of MITRE tactic distribution."""
    if not tactic_counts:
        fig = go.Figure()
        fig.update_layout(paper_bgcolor=COLORS["bg"], plot_bgcolor=COLORS["bg"])
        return fig

    labels = list(tactic_counts.keys())
    values = list(tactic_counts.values())

    tactic_colors = [
        COLORS["primary"], COLORS["accent"], COLORS["info"],
        COLORS["success"], COLORS["warning"], COLORS["danger"],
        "#A855F7", "#EC4899", "#14B8A6", "#F97316",
        "#6366F1", "#8B5CF6", "#D946EF", "#0EA5E9",
    ]

    fig = go.Figure(go.Pie(
        labels=labels,
        values=values,
        hole=0.5,
        marker=dict(colors=tactic_colors[:len(labels)]),
        textfont=dict(color=COLORS["text"], size=11),
        hovertemplate="<b>%{label}</b><br>Count: %{value}<br>Share: %{percent}<extra></extra>",
    ))

    fig.update_layout(
        title=dict(
            text="Tactic Distribution",
            font=dict(color=COLORS["text"], size=16),
        ),
        paper_bgcolor=COLORS["bg"],
        plot_bgcolor=COLORS["bg"],
        font=dict(color=COLORS["text_dim"]),
        legend=dict(
            bgcolor=COLORS["surface"],
            bordercolor=COLORS["border"],
            font=dict(color=COLORS["text"], size=10),
        ),
        height=380,
        margin=dict(t=50, b=20),
    )

    return fig
