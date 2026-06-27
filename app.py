"""SOCVerse — application entrypoint (visual shell only).

Presentation only: page config, animated brand header, first-load splash.
All engines/state/logic live behind get_state() and the render_* functions,
which are imported and called unchanged.
"""

import streamlit as st

# ---------------------------------------------------------------------------
# Page config MUST be the first Streamlit call. Do not move anything above it.
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="SOCVerse",
    page_icon="\U0001F6E1",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# ---------------------------------------------------------------------------
# Animated shield logo (inline SVG). uid namespaces gradient/filter ids so
# multiple instances on the page never collide.
# ---------------------------------------------------------------------------
def _logo_svg(size: int = 40, uid: str = "hdr") -> str:
    return (
        '<svg class="sv-logo" width="{s}" height="{s}" viewBox="0 0 64 64" '
        'fill="none" xmlns="http://www.w3.org/2000/svg" '
        'role="img" aria-label="SOCVerse">'
        '<defs>'
        '<linearGradient id="grad-{u}" x1="0" y1="0" x2="64" y2="64" '
        'gradientUnits="userSpaceOnUse">'
        '<stop stop-color="#60a5fa"/>'
        '<stop offset="0.5" stop-color="#3b82f6"/>'
        '<stop offset="1" stop-color="#1d4ed8"/>'
        '</linearGradient>'
        '<radialGradient id="core-{u}" cx="0.5" cy="0.42" r="0.6">'
        '<stop stop-color="#bfdbfe"/>'
        '<stop offset="1" stop-color="#3b82f6" stop-opacity="0"/>'
        '</radialGradient>'
        '<filter id="glow-{u}" x="-40%" y="-40%" width="180%" height="180%">'
        '<feGaussianBlur stdDeviation="1.4" result="b"/>'
        '<feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>'
        '</filter>'
        '</defs>'
        '<path class="sv-logo-shield" filter="url(#glow-{u})" '
        'd="M32 4 L56 13 V31 C56 45 45 56 32 60 C19 56 8 45 8 31 V13 Z" '
        'stroke="url(#grad-{u})" stroke-width="2.6" '
        'fill="url(#grad-{u})" fill-opacity="0.10" '
        'stroke-linejoin="round"/>'
        '<circle class="sv-logo-core" cx="32" cy="30" r="13" fill="url(#core-{u})"/>'
        '<circle class="sv-logo-ring" cx="32" cy="30" r="13" '
        'stroke="#93c5fd" stroke-width="1.4" fill="none" stroke-opacity="0.7"/>'
        '<g class="sv-logo-sweep" style="transform-origin:32px 30px">'
        '<path d="M32 30 L32 17 A13 13 0 0 1 44 26 Z" '
        'fill="#60a5fa" fill-opacity="0.35"/>'
        '</g>'
        '<g class="sv-logo-orbit" style="transform-origin:32px 30px">'
        '<circle cx="32" cy="17" r="2.2" fill="#dbeafe"/>'
        '</g>'
        '<circle cx="32" cy="30" r="2.6" fill="#bfdbfe"/>'
        '</svg>'
    ).format(s=size, u=uid)


# ---------------------------------------------------------------------------
# Brand + splash CSS. Plain (non-f) string: literal { } are CSS, never touched.
# Splash auto-fades purely via CSS animation -> NO Python sleep / st.empty().
# ---------------------------------------------------------------------------
_BRAND_CSS = """
<style>
@keyframes sv-draw { from { stroke-dashoffset: 240; } to { stroke-dashoffset: 0; } }
@keyframes sv-pulse { 0%,100% { opacity:.55; } 50% { opacity:1; } }
@keyframes sv-spin { to { transform: rotate(360deg); } }
@keyframes sv-orbit { to { transform: rotate(360deg); } }
@keyframes sv-shine { 0% { background-position: -160% 0; } 60%,100% { background-position: 260% 0; } }
@keyframes sv-fadein { from { opacity:0; transform: translateY(6px);} to { opacity:1; transform:none;} }
@keyframes sv-splash-out { 0%,70% { opacity:1; visibility:visible; } 100% { opacity:0; visibility:hidden; } }
@keyframes sv-load { 0% { left:-40%; } 100% { left:110%; } }

.sv-logo-shield { stroke-dasharray: 240; animation: sv-draw 1.1s ease-out forwards; }
.sv-logo-core { animation: sv-pulse 2.4s ease-in-out infinite; }
.sv-logo-sweep { animation: sv-spin 3.4s linear infinite; }
.sv-logo-orbit { animation: sv-orbit 6s linear infinite; }

/* header text block sits in its own Streamlit column, vertically centered */
.sv-brandtext { display:flex; align-items:center; flex-wrap:wrap; gap:.6rem;
  height:100%; min-height:44px; animation: sv-fadein .5s ease-out both; }
.sv-wordmark {
  font-weight:800; letter-spacing:.5px; line-height:1; font-size:1.85rem;
  color:#bfdbfe; /* solid fallback so it is NEVER invisible */
  background: linear-gradient(90deg,#bfdbfe 0%,#3b82f6 35%,#bfdbfe 50%,#3b82f6 65%,#1d4ed8 100%);
  background-size: 220% auto;
  -webkit-background-clip:text; background-clip:text;
  -webkit-text-fill-color:transparent;
  animation: sv-shine 6s linear infinite;
}
.sv-brandver {
  font-size:.62rem; font-weight:700; letter-spacing:1.5px;
  color: var(--sv-muted, #94a3b8);
  border:1px solid var(--sv-border, #1e293b);
  border-radius:999px; padding:.12rem .5rem; text-transform:uppercase; white-space:nowrap;
}
.sv-brandtag { font-size:.78rem; color: var(--sv-muted, #94a3b8); white-space:nowrap; }
.sv-brandrule { height:2px; border:0; margin:.1rem 0 .5rem 0;
  background: linear-gradient(90deg, var(--sv-primary,#3b82f6), transparent 70%); opacity:.7; }
.sv-logowrap { display:flex; align-items:center; justify-content:center; height:100%; min-height:44px; }

.sv-splash {
  position:fixed; inset:0; z-index:99990;
  display:flex; flex-direction:column; align-items:center; justify-content:center; gap:1.1rem;
  background: radial-gradient(circle at 50% 38%, #0b1220 0%, #060912 70%, #04060d 100%);
  animation: sv-splash-out 2.4s ease-in forwards;
}
.sv-splash::before { content:""; position:absolute; inset:0; opacity:.25;
  background-image:
    linear-gradient(rgba(59,130,246,.10) 1px, transparent 1px),
    linear-gradient(90deg, rgba(59,130,246,.10) 1px, transparent 1px);
  background-size: 34px 34px; }
.sv-splash-word {
  font-weight:800; letter-spacing:1px; font-size:2.1rem; z-index:1; color:#bfdbfe;
  background: linear-gradient(90deg,#bfdbfe,#3b82f6 50%,#1d4ed8);
  background-size:220% auto; -webkit-background-clip:text; background-clip:text;
  -webkit-text-fill-color:transparent; animation: sv-shine 3s linear infinite; }
.sv-splash-sub { z-index:1; font-size:.72rem; letter-spacing:3px; text-transform:uppercase; color:#64748b; }
.sv-splash-bar { z-index:1; width:160px; height:3px; border-radius:999px;
  background: rgba(148,163,184,.18); overflow:hidden; position:relative; }
.sv-splash-bar::after { content:""; position:absolute; left:0; top:0; height:100%; width:40%;
  border-radius:999px; background: linear-gradient(90deg,#60a5fa,#3b82f6); animation: sv-load 1.1s ease-in-out infinite; }
</style>
"""


def _splash_html() -> str:
    return (
        '<div class="sv-splash">'
        + _logo_svg(74, "splash")
        + '<div class="sv-splash-word">SOCVerse</div>'
        '<div class="sv-splash-sub">Security Operations</div>'
        '<div class="sv-splash-bar"></div>'
        '</div>'
    )


def _brand_header() -> None:
    # Native columns keep the logo and the text in ONE row reliably, instead of
    # relying on Streamlit to keep a single HTML blob's inline layout intact.
    c_logo, c_text = st.columns([1, 22], gap="small")
    with c_logo:
        st.markdown(
            '<div class="sv-logowrap">' + _logo_svg(40, "hdr") + '</div>',
            unsafe_allow_html=True,
        )
    with c_text:
        st.markdown(
            '<div class="sv-brandtext">'
            '<span class="sv-wordmark">SOCVerse</span>'
            '<span class="sv-brandver">v0.1.0</span>'
            '<span class="sv-brandtag">Security Operations Center &middot; Live Range</span>'
            '</div>',
            unsafe_allow_html=True,
        )
    st.markdown('<hr class="sv-brandrule"/>', unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Boot
# ---------------------------------------------------------------------------
st.markdown(_BRAND_CSS, unsafe_allow_html=True)

if not st.session_state.get("_sv_booted", False):
    st.markdown(_splash_html(), unsafe_allow_html=True)
    st.session_state["_sv_booted"] = True

from ui.state import get_state
from ui.layout import render_layout
from ui.viz.page import render_viz_page

try:
    from ui.theme import inject_theme
    inject_theme()
except Exception:
    pass

state = get_state()

_brand_header()

tab_map, tab_console = st.tabs(["Live Network Map", "SOC Console"])
with tab_map:
    render_viz_page(state)
with tab_console:
    render_layout(state)
