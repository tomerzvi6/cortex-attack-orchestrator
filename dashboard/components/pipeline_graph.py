"""
Pipeline graph visualisation — renders the LangGraph node pipeline
as a styled vertical flow using pure HTML/CSS.
"""

from __future__ import annotations

from dashboard.theme import COLORS

# ── Status icons & colors ─────────────────────────────────────────
_STATUS_MAP = {
    "pending":   ("⏳", COLORS["border_light"], COLORS["text_dim"]),
    "running":   ("🔄", COLORS["primary"],      COLORS["primary"]),
    "completed": ("✅", COLORS["success"],       COLORS["success"]),
    "failed":    ("❌", COLORS["danger"],        COLORS["danger"]),
    "skipped":   ("⏭️",  COLORS["text_dim"],     COLORS["text_dim"]),
}


def render_pipeline(
    nodes: list[dict],
    node_statuses: dict[str, str],
    node_durations: dict[str, float] | None = None,
) -> str:
    """
    Build an HTML string for the vertical pipeline visualisation.

    Args:
        nodes: List of node dicts from orchestrator.PIPELINE_NODES.
        node_statuses: {node_id: "pending"|"running"|"completed"|"failed"|"skipped"}
        node_durations: Optional {node_id: duration_ms}

    Returns:
        HTML string safe for st.markdown(unsafe_allow_html=True).
    """
    durations = node_durations or {}
    html_parts = [
        f'<div style="display:flex;flex-direction:column;gap:0;padding:8px 0;">'
    ]

    for i, node in enumerate(nodes):
        nid = node["id"]
        status = node_statuses.get(nid, "pending")
        icon_emoji, border_color, text_color = _STATUS_MAP.get(
            status, _STATUS_MAP["pending"]
        )
        node_icon = node.get("icon", "")
        label = node.get("label", nid)
        desc = node.get("description", "")

        dur = durations.get(nid)
        dur_text = f'<span style="color:{COLORS["text_dim"]};font-size:0.75rem;margin-left:8px;">{dur:.0f}ms</span>' if dur else ""

        pulse_class = "pulse-active" if status == "running" else ""

        html_parts.append(f'''
        <div class="{pulse_class}" style="
            display:flex;align-items:center;gap:12px;
            padding:10px 16px;
            background:{COLORS['surface']};
            border-left:3px solid {border_color};
            border-radius:0 8px 8px 0;
            margin-bottom:2px;
            opacity:{'1' if status != 'pending' else '0.5'};
            transition: all 0.3s ease;
        ">
            <span style="font-size:1.3rem;min-width:28px;text-align:center;">
                {node_icon}
            </span>
            <div style="flex:1;">
                <div style="font-weight:600;color:{text_color};font-size:0.9rem;">
                    {label} {dur_text}
                </div>
                <div style="font-size:0.75rem;color:{COLORS['text_dim']};">
                    {desc}
                </div>
            </div>
            <span style="font-size:1.1rem;">{icon_emoji}</span>
        </div>''')

        # Connector line between nodes
        if i < len(nodes) - 1:
            html_parts.append(f'''
        <div style="
            margin-left:30px;
            width:2px;height:8px;
            background:{COLORS['border']};
        "></div>''')

    html_parts.append("</div>")
    return "\n".join(html_parts)
