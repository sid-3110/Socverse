"""
config/theme.py
Dark theme design tokens and Streamlit CSS injection.
"""
from __future__ import annotations


# --------------------------------------------------------------------------- #
# Design tokens — referenced by both CSS and Plotly figures.
# --------------------------------------------------------------------------- #
COLORS: dict[str, str] = {
    "bg":            "#0b0f17",   # app background
    "surface":       "#131a26",   # cards / panels
    "surface_alt":   "#1b2433",   # elevated elements
    "border":        "#243044",
    "text":          "#e6edf3",
    "text_muted":    "#8b98a9",
    "primary":       "#3b82f6",   # links, active nodes
    "accent":        "#22d3ee",   # packets / highlights
    "success":       "#22c55e",
    "warning":       "#f59e0b",
    "danger":        "#ef4444",   # attacks / critical alerts
    "critical":      "#dc2626",
}

# Severity → color, used by the SOC engine and alert cards.
SEVERITY_COLORS: dict[str, str] = {
    "info":     COLORS["primary"],
    "low":      COLORS["success"],
    "medium":   COLORS["warning"],
    "high":     COLORS["danger"],
    "critical": COLORS["critical"],
}

FONT_STACK: str = (
    "'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif"
)


def inject_theme() -> str:
    """Return a <style> block applying the dark theme to Streamlit."""
    c = COLORS
    return f"""
    <style>
      .stApp {{
        background: {c['bg']};
        color: {c['text']};
        font-family: {FONT_STACK};
      }}
      section[data-testid="stSidebar"] {{
        background: {c['surface']};
        border-right: 1px solid {c['border']};
      }}
      .sv-card {{
        background: {c['surface']};
        border: 1px solid {c['border']};
        border-radius: 12px;
        padding: 16px 18px;
        margin-bottom: 14px;
      }}
      .sv-title {{
        font-size: 1.05rem;
        font-weight: 600;
        color: {c['text']};
        margin-bottom: 6px;
      }}
      .sv-muted {{ color: {c['text_muted']}; font-size: 0.85rem; }}
      .sv-badge {{
        display: inline-block; padding: 2px 10px; border-radius: 999px;
        font-size: 0.72rem; font-weight: 600; letter-spacing: .02em;
      }}
      h1, h2, h3, h4 {{ color: {c['text']}; }}
      .stButton > button {{
        background: {c['surface_alt']};
        color: {c['text']};
        border: 1px solid {c['border']};
        border-radius: 8px;
      }}
      .stButton > button:hover {{
        border-color: {c['primary']};
        color: {c['accent']};
      }}
    </style>
    """