"""SOCVerse entrypoint. The live network map is the primary screen; the full
SOC console (tabbed) lives alongside it."""
from __future__ import annotations

import streamlit as st

st.set_page_config(
    page_title="SOCVerse",
    page_icon="\U0001F6E1",
    layout="wide",
    initial_sidebar_state="collapsed",
)

from ui.state import get_state
from ui.layout import render_layout
from ui.viz.page import render_viz_page

try:
    from ui.theme import inject_theme
    inject_theme()
except Exception:  # theme is cosmetic; never block startup on it
    pass

state = get_state()

tab_map, tab_console = st.tabs(["Live Network Map", "SOC Console"])
with tab_map:
    render_viz_page(state)
with tab_console:
    render_layout(state)
