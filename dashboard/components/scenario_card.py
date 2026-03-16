"""
Scenario card component — renders a styled scenario card.
"""

from __future__ import annotations

from dashboard.theme import COLORS, cloud_badge


def render_scenario_card(scenario, *, show_launch: bool = False) -> str:
    """
    Build HTML for a single scenario card.

    Args:
        scenario: Scenario dataclass from the registry.
        show_launch: If True, include a launch hint.

    Returns:
        HTML string.
    """
    provider = getattr(scenario, "cloud_provider", "azure")
    badge = cloud_badge(provider)

    techs = getattr(scenario, "expected_mitre_techniques", [])
    tech_pills = ""
    for t in techs[:4]:
        tid = t.get("id", "")
        tname = t.get("name", "")
        tech_pills += (
            f'<span style="background:{COLORS["surface_alt"]};color:{COLORS["info"]};'
            f'padding:2px 8px;border-radius:10px;font-size:0.72rem;margin-right:4px;'
            f'border:1px solid {COLORS["border"]};">'
            f'{tid}</span>'
        )
    if len(techs) > 4:
        tech_pills += f'<span style="color:{COLORS["text_dim"]};font-size:0.72rem;">+{len(techs)-4} more</span>'

    steps = getattr(scenario, "simulation_steps", [])
    step_count = len(steps)

    desc = getattr(scenario, "description", "")
    if len(desc) > 180:
        desc = desc[:177] + "…"

    return f"""
    <div style="
        background:{COLORS['surface']};
        border:1px solid {COLORS['border']};
        border-radius:12px;
        padding:20px;
        transition:all 0.2s ease;
        height:100%;
    " onmouseover="this.style.borderColor='{COLORS['primary']}'" 
       onmouseout="this.style.borderColor='{COLORS['border']}'">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
            <span style="font-weight:700;color:{COLORS['text']};font-size:1rem;">
                {scenario.name}
            </span>
            {badge}
        </div>
        <div style="color:{COLORS['text_dim']};font-size:0.82rem;margin-bottom:12px;line-height:1.4;">
            {desc}
        </div>
        <div style="margin-bottom:10px;">
            {tech_pills}
        </div>
        <div style="display:flex;justify-content:space-between;align-items:center;">
            <span style="color:{COLORS['text_dim']};font-size:0.78rem;">
                ⚡ {step_count} steps
            </span>
            <span style="
                font-size:0.72rem;color:{COLORS['text_dim']};
                background:{COLORS['surface_alt']};
                padding:2px 8px;border-radius:8px;
                border:1px solid {COLORS['border']};
            ">{scenario.id}</span>
        </div>
    </div>
    """
