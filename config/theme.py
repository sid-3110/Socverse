"""
config/theme.py
Design-system foundation: tokens + Streamlit CSS injection.

Single source of truth for color, typography, spacing, radius, shadow, and the
device-group / status palettes. Consumed by:
  * inject_theme()       -> Streamlit chrome (SOC Console)
  * css_variables()      -> the network iframe (ui/viz/component.py) as --sv-*
  * Plotly/Cytoscape via the COLORS / GROUP_COLORS / STATUS_COLORS dicts.

Backward compatible: COLORS, SEVERITY_COLORS, FONT_STACK, inject_theme()
keep their original names and shapes.
"""
from __future__ import annotations


# --------------------------------------------------------------------------- #
# Core palette — referenced by both CSS and Plotly figures.
# --------------------------------------------------------------------------- #
COLORS: dict[str, str] = {
    "bg":            "#0a0e16",   # app background (slightly deeper)
    "bg_alt":        "#0e1422",   # gradient companion
    "surface":       "#131a26",   # cards / panels
    "surface_alt":   "#1b2433",   # elevated elements
    "surface_glass": "rgba(27, 36, 51, 0.62)",  # glass cards
    "border":        "#243044",
    "border_soft":   "#1c2636",
    "text":          "#e6edf3",
    "text_muted":    "#8b98a9",
    "text_dim":      "#5b6677",
    "primary":       "#3b82f6",   # links, active nodes
    "primary_soft":  "rgba(59, 130, 246, 0.16)",
    "accent":        "#22d3ee",   # packets / highlights
    "accent_soft":   "rgba(34, 211, 238, 0.14)",
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

# Device-group palette — MUST match the renderer's GROUP_FILL.
GROUP_COLORS: dict[str, str] = {
    "security": "#f43f5e",
    "network":  "#3b82f6",
    "server":   "#22c55e",
    "endpoint": "#a855f7",
    "cloud":    "#06b6d4",
    "other":    "#94a3b8",
}

# Operational status → ring color — MUST match the renderer's STATUS_RING.
STATUS_COLORS: dict[str, str] = {
    "healthy":      "#22c55e",
    "warning":      "#f59e0b",
    "critical":     "#ef4444",
    "offline":      "#64748b",
    "under-attack": "#f97316",
    "compromised":  "#ec4899",
}

# --------------------------------------------------------------------------- #
# Scales — spacing / radius / shadow / typography.
# --------------------------------------------------------------------------- #
SPACE: dict[str, str] = {
    "1": "4px", "2": "8px", "3": "12px", "4": "16px",
    "5": "20px", "6": "24px", "8": "32px", "10": "40px",
}
RADIUS: dict[str, str] = {
    "sm": "8px", "md": "12px", "lg": "16px", "xl": "20px", "pill": "999px",
}
SHADOW: dict[str, str] = {
    "sm": "0 1px 2px rgba(0,0,0,.30)",
    "md": "0 6px 18px rgba(0,0,0,.35)",
    "lg": "0 14px 44px rgba(0,0,0,.48)",
    "glow_primary": "0 0 0 1px rgba(59,130,246,.35), 0 8px 28px rgba(59,130,246,.18)",
    "glow_danger":  "0 0 0 1px rgba(239,68,68,.40), 0 8px 28px rgba(239,68,68,.22)",
}

FONT_STACK: str = (
    "'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif"
)
MONO_STACK: str = (
    "'JetBrains Mono', 'SF Mono', 'Fira Code', ui-monospace, "
    "Menlo, Consolas, monospace"
)


# --------------------------------------------------------------------------- #
# CSS variables — shared by Streamlit chrome AND the network iframe.
# --------------------------------------------------------------------------- #
def css_variables() -> str:
    """Return a ':root { --sv-*: ... }' block. No selector wrapper tags."""
    c = COLORS
    g = GROUP_COLORS
    s = STATUS_COLORS
    return f"""
    :root {{
      --sv-bg: {c['bg']};
      --sv-bg-alt: {c['bg_alt']};
      --sv-surface: {c['surface']};
      --sv-surface-alt: {c['surface_alt']};
      --sv-glass: {c['surface_glass']};
      --sv-border: {c['border']};
      --sv-border-soft: {c['border_soft']};
      --sv-text: {c['text']};
      --sv-text-muted: {c['text_muted']};
      --sv-text-dim: {c['text_dim']};
      --sv-primary: {c['primary']};
      --sv-primary-soft: {c['primary_soft']};
      --sv-accent: {c['accent']};
      --sv-accent-soft: {c['accent_soft']};
      --sv-success: {c['success']};
      --sv-warning: {c['warning']};
      --sv-danger: {c['danger']};
      --sv-critical: {c['critical']};

      --sv-grp-security: {g['security']};
      --sv-grp-network: {g['network']};
      --sv-grp-server: {g['server']};
      --sv-grp-endpoint: {g['endpoint']};
      --sv-grp-cloud: {g['cloud']};
      --sv-grp-other: {g['other']};

      --sv-st-healthy: {s['healthy']};
      --sv-st-warning: {s['warning']};
      --sv-st-critical: {s['critical']};
      --sv-st-offline: {s['offline']};
      --sv-st-attack: {s['under-attack']};
      --sv-st-compromised: {s['compromised']};

      --sv-r-sm: {RADIUS['sm']}; --sv-r-md: {RADIUS['md']};
      --sv-r-lg: {RADIUS['lg']}; --sv-r-xl: {RADIUS['xl']};
      --sv-r-pill: {RADIUS['pill']};

      --sv-sp-1: {SPACE['1']}; --sv-sp-2: {SPACE['2']}; --sv-sp-3: {SPACE['3']};
      --sv-sp-4: {SPACE['4']}; --sv-sp-5: {SPACE['5']}; --sv-sp-6: {SPACE['6']};

      --sv-shadow-sm: {SHADOW['sm']};
      --sv-shadow-md: {SHADOW['md']};
      --sv-shadow-lg: {SHADOW['lg']};
      --sv-glow-primary: {SHADOW['glow_primary']};
      --sv-glow-danger: {SHADOW['glow_danger']};

      --sv-font: {FONT_STACK};
      --sv-mono: {MONO_STACK};
    }}
    """


def inject_theme() -> str:
    """Return a <style> block applying the design system to Streamlit."""
    c = COLORS
    return f"""
    <style>
      {css_variables()}

      .stApp {{
        background:
          radial-gradient(1200px 600px at 80% -10%, rgba(59,130,246,.08), transparent 60%),
          radial-gradient(900px 500px at -10% 110%, rgba(34,211,238,.06), transparent 55%),
          {c['bg']};
        color: {c['text']};
        font-family: {FONT_STACK};
      }}
      section[data-testid="stSidebar"] {{
        background: {c['surface']};
        border-right: 1px solid {c['border']};
      }}

      /* ---- Cards ---- */
      .sv-card {{
        background: {c['surface']};
        border: 1px solid {c['border']};
        border-radius: 14px;
        padding: 16px 18px;
        margin-bottom: 14px;
        box-shadow: {SHADOW['sm']};
      }}
      .sv-card-glass {{
        background: {c['surface_glass']};
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
        border: 1px solid {c['border']};
        border-radius: 16px;
        padding: 16px 18px;
        margin-bottom: 14px;
        box-shadow: {SHADOW['md']};
      }}
      .sv-title {{
        font-size: 1.05rem; font-weight: 700; letter-spacing: -.01em;
        color: {c['text']}; margin-bottom: 6px;
      }}
      .sv-muted {{ color: {c['text_muted']}; font-size: 0.85rem; }}
      .sv-mono {{ font-family: {MONO_STACK}; }}

      /* ---- Metric cards ---- */
      .sv-metric {{
        background: linear-gradient(180deg, {c['surface_alt']}, {c['surface']});
        border: 1px solid {c['border']};
        border-radius: 14px; padding: 14px 16px;
        box-shadow: {SHADOW['sm']};
      }}
      .sv-metric .sv-metric-label {{
        color: {c['text_muted']}; font-size: .74rem; font-weight: 600;
        text-transform: uppercase; letter-spacing: .06em;
      }}
      .sv-metric .sv-metric-value {{
        color: {c['text']}; font-size: 1.7rem; font-weight: 800;
        line-height: 1.15; margin-top: 4px;
      }}
      .sv-metric .sv-metric-delta {{ font-size: .78rem; font-weight: 600; }}
      .sv-up {{ color: {c['success']}; }}
      .sv-down {{ color: {c['danger']}; }}

      /* ---- Badges ---- */
      .sv-badge {{
        display: inline-block; padding: 2px 10px; border-radius: 999px;
        font-size: 0.72rem; font-weight: 700; letter-spacing: .02em;
        border: 1px solid transparent;
      }}
      .sv-badge-info     {{ color: {c['primary']};  background: rgba(59,130,246,.14);  border-color: rgba(59,130,246,.35); }}
      .sv-badge-low      {{ color: {c['success']};  background: rgba(34,197,94,.14);   border-color: rgba(34,197,94,.35); }}
      .sv-badge-medium   {{ color: {c['warning']};  background: rgba(245,158,11,.14);  border-color: rgba(245,158,11,.35); }}
      .sv-badge-high     {{ color: {c['danger']};   background: rgba(239,68,68,.14);   border-color: rgba(239,68,68,.35); }}
      .sv-badge-critical {{ color: #fff; background: {c['critical']}; border-color: {c['critical']}; }}

      h1, h2, h3, h4 {{ color: {c['text']}; letter-spacing: -.01em; }}

      /* ---- Buttons ---- */
      .stButton > button {{
        background: {c['surface_alt']};
        color: {c['text']};
        border: 1px solid {c['border']};
        border-radius: 10px;
        font-weight: 600;
        transition: border-color .15s ease, color .15s ease, box-shadow .15s ease;
      }}
      .stButton > button:hover {{
        border-color: {c['primary']};
        color: {c['accent']};
        box-shadow: {SHADOW['glow_primary']};
      }}

      /* ---- Tables / dataframes ---- */
      [data-testid="stDataFrame"] {{
        border: 1px solid {c['border']};
        border-radius: 12px;
        overflow: hidden;
      }}
    </style>
    """