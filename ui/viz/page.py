"""Phase 2 primary screen: the live enterprise network visualization.

Thin Streamlit host around the client-side renderer. It builds the snapshot
from app state, exposes a compact attack-launcher (which mutates state on the
Python side and re-renders), and embeds the interactive component. All rich UI
(graph, asset console, packet animation, timeline, minimap) lives in the
browser via component.render_network - this page just feeds it data.
"""
from __future__ import annotations

import streamlit as st

from ui.viz.snapshot import snapshot_from_state
from ui.viz.component import render_network


def _attack_options(state) -> list[tuple[str, str]]:
    opts: list[tuple[str, str]] = []
    for item in state.attack_catalog:
        key = item.get("key") or item.get("registry_key") or item.get("name")
        label = item.get("name") or key
        if key:
            opts.append((str(label), str(key)))
    return opts


def render_viz_page(state, *, height: int = 760) -> None:
    st.markdown("#### Live Enterprise Network")

    hosts = list(state.hostnames)
    src_default = hosts.index("ATTACKER") if "ATTACKER" in hosts else 0
    tgt_default = len(hosts) - 1 if hosts else 0
    opts = _attack_options(state)
    labels = [o[0] for o in opts]
    label_to_key = {o[0]: o[1] for o in opts}

    c1, c2, c3, c4 = st.columns([3, 3, 3, 2])
    with c1:
        choice = st.selectbox("Attack", labels, key="viz_attack") if labels else None
    with c2:
        source = st.selectbox("Source", hosts, index=src_default, key="viz_source") if hosts else None
    with c3:
        target = st.selectbox("Target", hosts, index=tgt_default, key="viz_target") if hosts else None
    with c4:
        st.write("")
        run = st.button("Run attack", use_container_width=True)

    if run and choice and source and target:
        try:
            state.run_attack(label_to_key[choice], source=source, target=target)
            st.toast(f"Ran {choice}: {source} -> {target}")
        except Exception as exc:  # noqa: BLE001
            st.error(f"Attack failed: {exc}")

    snapshot = snapshot_from_state(state)
    render_network(snapshot, height=height)
