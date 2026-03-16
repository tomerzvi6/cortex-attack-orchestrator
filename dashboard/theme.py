"""
Palo Alto Networks–inspired dark theme for the Cortex Attack Orchestrator dashboard.

Provides:
    - apply_theme()              — inject custom CSS + page config
    - status_badge(status, text) — colored badge HTML
    - COLORS dict                — centralized palette
"""

from __future__ import annotations

import streamlit as st

# ── Color Palette ─────────────────────────────────────────────────
COLORS = {
    "bg":           "#0D1117",
    "surface":      "#161B22",
    "surface_alt":  "#1C2333",
    "border":       "#30363D",
    "border_light": "#484F58",
    "text":         "#E6EDF3",
    "text_dim":     "#8B949E",
    "primary":      "#00C6B6",   # Palo Alto teal
    "primary_dim":  "#00897B",
    "accent":       "#FF6B35",   # warm orange
    "danger":       "#F85149",
    "success":      "#3FB950",
    "warning":      "#D29922",
    "info":         "#58A6FF",
    "azure_blue":   "#0078D4",
    "aws_orange":   "#FF9900",
}

# ── Badge helpers ─────────────────────────────────────────────────

_BADGE_STYLES = {
    "detected":     (COLORS["success"],  "#0D1117"),
    "not_detected": (COLORS["danger"],   "#FFFFFF"),
    "dry_run":      (COLORS["info"],     "#0D1117"),
    "pending":      (COLORS["text_dim"], "#0D1117"),
    "success":      (COLORS["success"],  "#0D1117"),
    "failed":       (COLORS["danger"],   "#FFFFFF"),
    "running":      (COLORS["primary"],  "#0D1117"),
    "skipped":      (COLORS["text_dim"], "#0D1117"),
    "unsafe":       (COLORS["warning"],  "#0D1117"),
    "azure":        (COLORS["azure_blue"], "#FFFFFF"),
    "aws":          (COLORS["aws_orange"], "#0D1117"),
    "high":         (COLORS["danger"],   "#FFFFFF"),
    "medium":       (COLORS["warning"],  "#0D1117"),
    "low":          (COLORS["success"],  "#0D1117"),
}


def status_badge(status: str, label: str | None = None) -> str:
    """Return an HTML <span> styled as a colored pill badge."""
    bg, fg = _BADGE_STYLES.get(status, (COLORS["text_dim"], "#0D1117"))
    text = label or status.replace("_", " ").title()
    return (
        f'<span style="background:{bg};color:{fg};padding:2px 10px;'
        f'border-radius:12px;font-size:0.8rem;font-weight:600;'
        f'letter-spacing:0.03em;">{text}</span>'
    )


def cloud_badge(provider: str) -> str:
    """Return a small cloud-provider pill (Azure / AWS)."""
    key = provider.lower()
    if key == "azure":
        return status_badge("azure", "Azure ☁️")
    if key == "aws":
        return status_badge("aws", "AWS ☁️")
    return status_badge("pending", provider)


# ── Metric card helper ────────────────────────────────────────────

def metric_card(title: str, value: str | int | float, icon: str = "", color: str = COLORS["primary"]) -> str:
    """Return styled HTML for a single KPI metric card."""
    return f"""
    <div style="
        background:{COLORS['surface']};
        border:1px solid {COLORS['border']};
        border-radius:12px;
        padding:20px 24px;
        text-align:center;
        border-top:3px solid {color};
    ">
        <div style="font-size:1.6rem;margin-bottom:4px;">{icon}</div>
        <div style="font-size:2rem;font-weight:700;color:{color};line-height:1.1;">
            {value}
        </div>
        <div style="font-size:0.85rem;color:{COLORS['text_dim']};margin-top:6px;text-transform:uppercase;letter-spacing:0.05em;">
            {title}
        </div>
    </div>
    """


# ── CSS Injection ─────────────────────────────────────────────────

_CUSTOM_CSS = f"""
<style>
    /* ── Root overrides ──────────────────────────────────────── */
    .stApp {{
        background-color: {COLORS['bg']};
        color: {COLORS['text']};
    }}

    /* ── Sidebar ─────────────────────────────────────────────── */
    section[data-testid="stSidebar"] {{
        background-color: {COLORS['surface']} !important;
        border-right: 1px solid {COLORS['border']};
    }}
    section[data-testid="stSidebar"] .stMarkdown {{
        color: {COLORS['text']};
    }}

    /* ── Headers ─────────────────────────────────────────────── */
    h1, h2, h3, h4, h5, h6 {{
        color: {COLORS['text']} !important;
    }}
    h1 {{
        color: {COLORS['primary']} !important;
    }}

    /* ── Metric widget ───────────────────────────────────────── */
    [data-testid="stMetricValue"] {{
        color: {COLORS['primary']} !important;
    }}
    [data-testid="stMetricLabel"] {{
        color: {COLORS['text_dim']} !important;
    }}

    /* ── Tabs ────────────────────────────────────────────────── */
    .stTabs [data-baseweb="tab-list"] {{
        gap: 0;
        background-color: {COLORS['surface']};
        border-radius: 8px;
        padding: 4px;
    }}
    .stTabs [data-baseweb="tab"] {{
        color: {COLORS['text_dim']};
        border-radius: 6px;
        padding: 8px 20px;
        font-weight: 500;
    }}
    .stTabs [aria-selected="true"] {{
        background-color: {COLORS['surface_alt']} !important;
        color: {COLORS['primary']} !important;
        border-bottom: 2px solid {COLORS['primary']};
    }}

    /* ── Buttons ─────────────────────────────────────────────── */
    .stButton > button {{
        background-color: {COLORS['primary']};
        color: #0D1117;
        border: none;
        border-radius: 8px;
        font-weight: 600;
        padding: 0.5rem 1.2rem;
        transition: all 0.2s ease;
    }}
    .stButton > button:hover {{
        background-color: {COLORS['primary_dim']};
        transform: translateY(-1px);
        box-shadow: 0 4px 12px rgba(0,198,182,0.3);
    }}

    /* ── Inputs ───────────────────────────────────────────────── */
    .stTextInput > div > div > input,
    .stTextArea > div > div > textarea,
    .stSelectbox > div > div {{
        background-color: {COLORS['surface_alt']} !important;
        color: {COLORS['text']} !important;
        border-color: {COLORS['border']} !important;
        border-radius: 8px;
    }}

    /* ── Cards / containers ──────────────────────────────────── */
    div[data-testid="stExpander"] {{
        background-color: {COLORS['surface']};
        border: 1px solid {COLORS['border']};
        border-radius: 10px;
    }}

    /* ── Code blocks ─────────────────────────────────────────── */
    pre {{
        background-color: {COLORS['surface_alt']} !important;
        border: 1px solid {COLORS['border']} !important;
        border-radius: 8px;
    }}

    /* ── Tables / dataframes ─────────────────────────────────── */
    .stDataFrame {{
        border: 1px solid {COLORS['border']};
        border-radius: 8px;
        overflow: hidden;
    }}

    /* ── Dividers ────────────────────────────────────────────── */
    hr {{
        border-color: {COLORS['border']} !important;
    }}

    /* ── Alerts ──────────────────────────────────────────────── */
    .stAlert {{
        border-radius: 8px;
    }}

    /* ── Scrollbar ───────────────────────────────────────────── */
    ::-webkit-scrollbar {{
        width: 8px;
        height: 8px;
    }}
    ::-webkit-scrollbar-track {{
        background: {COLORS['bg']};
    }}
    ::-webkit-scrollbar-thumb {{
        background: {COLORS['border']};
        border-radius: 4px;
    }}
    ::-webkit-scrollbar-thumb:hover {{
        background: {COLORS['border_light']};
    }}

    /* ── Keyframe animations ─────────────────────────────────── */
    @keyframes pulse-teal {{
        0%   {{ box-shadow: 0 0 0 0 rgba(0,198,182,0.5); }}
        70%  {{ box-shadow: 0 0 0 10px rgba(0,198,182,0); }}
        100% {{ box-shadow: 0 0 0 0 rgba(0,198,182,0); }}
    }}

    .pulse-active {{
        animation: pulse-teal 1.5s infinite;
    }}

    /* ── Navigation styling ──────────────────────────────────── */
    nav[data-testid="stSidebarNav"] a {{
        color: {COLORS['text']} !important;
    }}
    nav[data-testid="stSidebarNav"] a:hover {{
        color: {COLORS['primary']} !important;
    }}
</style>
"""

# ── Page setup ────────────────────────────────────────────────────

def apply_theme() -> None:
    """
    Apply the Palo Alto dark theme.

    Call this at the TOP of every page, before any other st.* calls
    (except st.set_page_config which must come first).
    """
    st.markdown(_CUSTOM_CSS, unsafe_allow_html=True)
