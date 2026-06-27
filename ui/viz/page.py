"""Phase 2 primary screen: the live enterprise network visualization.

Thin Streamlit host around the client-side renderer. It builds the snapshot
from app state, exposes a compact attack-launcher (which mutates state on the
Python side and re-renders), and embeds the interactive component. All rich UI
(graph, asset console, packet animation, timeline, minimap) lives in the
browser via component.render_network - this page just feeds it data.

Module 6 (visual only): adds a status banner and a styled control bar around
the exact same data flow. The snapshot, render_network call, and run_attack
semantics are unchanged; a Clear button calls the existing state.reset_soc().
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


def _esc(v) -> str:
    return (
        str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        if v is not None
        else ""
    )


def _page_css() -> None:
    st.markdown(
        """
<style>
:root{
  --svp-glass: var(--sv-surface-glass, rgba(255,255,255,0.025));
  --svp-border: var(--sv-border-soft, rgba(255,255,255,0.08));
  --svp-text: var(--sv-text, #e6edf3);
  --svp-dim: var(--sv-text-dim, #8b949e);
  --svp-primary: var(--sv-primary, #3b82f6);
  --svp-radius: var(--sv-radius, 12px);
}
.sv-vizbanner{display:flex;align-items:center;gap:.9rem;flex-wrap:wrap;
  background:var(--svp-glass);border:1px solid var(--svp-border);
  border-left:4px solid var(--svp-accent,#22c55e);border-radius:var(--svp-radius);
  padding:.6rem .9rem;margin:.1rem 0 .7rem}
.sv-vizdot{width:.62rem;height:.62rem;border-radius:50%;
  background:var(--svp-accent,#22c55e);box-shadow:0 0 0 0 var(--svp-accent,#22c55e);
  animation:svp-pulse 2s infinite}
@keyframes svp-pulse{
  0%{box-shadow:0 0 0 0 color-mix(in srgb,var(--svp-accent,#22c55e) 70%,transparent)}
  70%{box-shadow:0 0 0 .55rem transparent}
  100%{box-shadow:0 0 0 0 transparent}}
.sv-vizstatus{font-weight:700;letter-spacing:.04em;color:var(--svp-text);font-size:.92rem}
.sv-vizscn{color:var(--svp-dim);font-size:.78rem}
.sv-vizspacer{flex:1}
.sv-vizkpi{display:flex;gap:.35rem;align-items:baseline}
.sv-vizkpi b{font-size:1.05rem;color:var(--svp-text);font-variant-numeric:tabular-nums}
.sv-vizkpi span{font-size:.66rem;text-transform:uppercase;letter-spacing:.07em;color:var(--svp-dim)}
.sv-vizsep{width:1px;align-self:stretch;background:var(--svp-border);margin:0 .15rem}
.sv-vizatk{color:#f59e0b;font-weight:600;font-size:.8rem}
</style>
        """,
        unsafe_allow_html=True,
    )


def _banner(state, snapshot) -> None:
    meta = snapshot.get("meta", {}) if isinstance(snapshot, dict) else {}
    status = meta.get("status", "healthy")
    under = status == "under_attack"
    accent = "#ef4444" if under else "#22c55e"
    label = "UNDER ATTACK" if under else "OPERATIONAL"
    scenario = meta.get("scenario", "Enterprise Baseline")
    attack_name = meta.get("attack")

    try:
        stats = state.soc.stats()
    except Exception:  # noqa: BLE001
        stats = {}
    nodes = len(snapshot.get("nodes", []) or [])
    links = len(snapshot.get("edges", []) or [])

    atk_html = (
        f"<span class='sv-vizatk'>&#9889; {_esc(attack_name)}</span>" if attack_name else ""
    )
    kpi = lambda v, l: f"<div class='sv-vizkpi'><b>{_esc(v)}</b><span>{l}</span></div>"
    st.markdown(
        f"<div class='sv-vizbanner' style='--svp-accent:{accent}'>"
        f"<span class='sv-vizdot'></span>"
        f"<span class='sv-vizstatus'>{label}</span>"
        f"<span class='sv-vizscn'>{_esc(scenario)}</span>"
        f"{atk_html}"
        f"<span class='sv-vizspacer'></span>"
        f"{kpi(nodes, 'devices')}<span class='sv-vizsep'></span>"
        f"{kpi(links, 'links')}<span class='sv-vizsep'></span>"
        f"{kpi(stats.get('total_alerts', 0), 'alerts')}<span class='sv-vizsep'></span>"
        f"{kpi(stats.get('open_alerts', 0), 'open')}"
        f"</div>",
        unsafe_allow_html=True,
    )


def render_viz_page(state, *, height: int = 760) -> None:
    _page_css()
    st.markdown("#### Live Enterprise Network")

    hosts = list(state.hostnames)
    src_default = hosts.index("ATTACKER") if "ATTACKER" in hosts else 0
    tgt_default = len(hosts) - 1 if hosts else 0
    opts = _attack_options(state)
    labels = [o[0] for o in opts]
    label_to_key = {o[0]: o[1] for o in opts}

    c1, c2, c3, c4, c5 = st.columns([3, 3, 3, 2, 2])
    with c1:
        choice = st.selectbox("Attack", labels, key="viz_attack") if labels else None
    with c2:
        source = st.selectbox("Source", hosts, index=src_default, key="viz_source") if hosts else None
    with c3:
        target = st.selectbox("Target", hosts, index=tgt_default, key="viz_target") if hosts else None
    with c4:
        st.write("")
        run = st.button("Run attack", use_container_width=True, type="primary")
    with c5:
        st.write("")
        clear = st.button("Clear", use_container_width=True)

    if run and choice and source and target:
        try:
            state.run_attack(label_to_key[choice], source=source, target=target)
            st.toast(f"Ran {choice}: {source} -> {target}")
        except Exception as exc:  # noqa: BLE001
            st.error(f"Attack failed: {exc}")

    if clear:
        try:
            state.reset_soc()
            st.toast("Simulation cleared")
            st.rerun()
        except Exception as exc:  # noqa: BLE001
            st.error(f"Reset failed: {exc}")

    snapshot = snapshot_from_state(state)
    _banner(state, snapshot)
    render_network(snapshot, height=height)
