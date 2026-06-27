"""Tabbed application shell. Tab 1 is the Operations 3-pane; the rest are
dedicated pages, each a pure view over the live engines in AppState."""
from __future__ import annotations

import streamlit as st

from config.settings import CONFIG
from config.theme import SEVERITY_COLORS
from core.enums import Severity
from core.soc.siem import SiemQuery
from ui.state import AppState

_PAGES = [
    "Operations",
    "Alerts",
    "Network",
    "MITRE ATT&CK",
    "Logs & SIEM",
    "Packet Inspector",
    "Device Library",
    "Settings",
]


def render_layout(state: AppState) -> None:
    _header()
    tabs = st.tabs(_PAGES)
    with tabs[0]:
        _ops(state)
    with tabs[1]:
        _alerts_page(state)
    with tabs[2]:
        _network_page(state)
    with tabs[3]:
        _mitre_page(state)
    with tabs[4]:
        _siem_page(state)
    with tabs[5]:
        _packet_page(state)
    with tabs[6]:
        _device_library(state)
    with tabs[7]:
        _settings_page(state)


def _header() -> None:
    st.markdown(
        f"<div class='sv-title' style='font-size:1.6rem'>{CONFIG.icon} {CONFIG.name}"
        f"<span class='sv-muted' style='font-size:0.9rem'>&nbsp;&nbsp;{CONFIG.tagline}</span></div>",
        unsafe_allow_html=True,
    )
    st.markdown("<hr style='margin:0.3rem 0 0.6rem 0;opacity:0.2'>", unsafe_allow_html=True)


# ----------------------------------------------------------------- Operations
def _ops(state: AppState) -> None:
    left, center, right = st.columns([1.1, 2.4, 1.5], gap="medium")
    with left:
        _control_rail(state)
    with center:
        _network_canvas(state)
    with right:
        _soc_dashboard(state)


def _control_rail(state: AppState) -> None:
    st.markdown("#### Attack Simulation")
    options: dict[str, str] = {}
    for item in state.attack_catalog:
        key = item.get("key") or item.get("registry_key") or item.get("name")
        label = item.get("label") or item.get("name") or key
        if key:
            options[label] = key

    if not options:
        st.info("No attacks registered.")
    else:
        label = st.selectbox("Technique", list(options.keys()))
        attack_key = options[label]
        hosts = state.hostnames
        source = st.selectbox("Source", hosts, index=_idx(hosts, "ATTACKER"))
        target = st.selectbox("Target", hosts, index=_idx(hosts, "WEB-01"))
        if st.button("Launch attack", use_container_width=True, type="primary"):
            result = state.run_attack(attack_key, source, target)
            st.success(f"{result.name} complete")
            st.caption(result.summary() if hasattr(result, "summary") else "")

    st.markdown("#### Controls")
    if st.button("Reset SOC", use_container_width=True):
        state.reset_soc()
        st.rerun()


def _network_canvas(state: AppState) -> None:
    st.markdown("#### Enterprise Network")
    data = state.topology.graph_data()
    st.caption(f"{len(data['nodes'])} devices, {len(data['edges'])} links")
    st.dataframe(_node_rows(data), use_container_width=True, height=440)


def _soc_dashboard(state: AppState) -> None:
    st.markdown("#### SOC Dashboard")
    stats = state.soc.stats()
    c1, c2, c3 = st.columns(3)
    c1.metric("Events", stats["total_events"])
    c2.metric("Alerts", stats["total_alerts"])
    c3.metric("Open", stats["open_alerts"])
    by_sev = stats.get("by_severity", {})
    if by_sev:
        st.caption("Severity: " + ", ".join(f"{k}={v}" for k, v in by_sev.items()))

    alerts = state.soc.alerts()
    if not alerts:
        st.info("No alerts yet. Launch an attack.")
        return
    st.markdown("##### Recent alerts")
    for a in sorted(alerts, key=lambda x: int(x.severity), reverse=True)[:6]:
        clr = SEVERITY_COLORS.get(a.severity_key, "#888888")
        st.markdown(
            f"<div class='sv-card' style='border-left:4px solid {clr}'>"
            f"<b>[{a.severity.label}]</b> {a.title}"
            f"<br><span class='sv-muted'>{a.mitre_id} &middot; {a.tactic}</span></div>",
            unsafe_allow_html=True,
        )


# ---------------------------------------------------------------------- Alerts
def _alerts_page(state: AppState) -> None:
    st.markdown("#### Alert Investigation")
    alerts = state.soc.alerts()
    if not alerts:
        st.info("No alerts yet. Launch an attack from the Operations tab.")
        return
    for a in sorted(alerts, key=lambda x: int(x.severity), reverse=True):
        with st.expander(f"[{a.severity.label}] {a.title}"):
            st.markdown(f"**MITRE:** {a.mitre_id} - {a.technique} ({a.tactic})")
            st.markdown(f"**Business impact:** {a.business_impact}")
            if a.iocs:
                st.markdown("**Indicators of compromise:**")
                for i in a.iocs:
                    st.markdown(f"- `{i.type}` {i.value}  ({i.context})")
            if a.containment:
                st.markdown("**Containment:**")
                for c in a.containment:
                    st.markdown(f"- {c}")
            if a.investigation:
                st.markdown("**Investigation steps:**")
                for s in a.investigation:
                    st.markdown(f"- {s}")
            if a.false_positives:
                st.markdown("**False-positive checks:**")
                for f in a.false_positives:
                    st.markdown(f"- {f}")
            st.markdown(f"**Recommendation:** {a.recommendation}")


# --------------------------------------------------------------------- Network
def _network_page(state: AppState) -> None:
    st.markdown("#### Network Map")
    data = state.topology.graph_data()
    st.caption(f"{len(data['nodes'])} devices, {len(data['edges'])} links")
    st.dataframe(_node_rows(data), use_container_width=True, height=560)
    with st.expander("Links"):
        st.dataframe(
            [{"source": e.get("source"), "target": e.get("target")} for e in data["edges"]],
            use_container_width=True,
        )


# ----------------------------------------------------------------------- MITRE
def _mitre_page(state: AppState) -> None:
    st.markdown("#### MITRE ATT&CK Coverage")
    roll = state.soc.mitre()
    techs = roll.techniques()
    if not techs:
        st.info("No techniques observed yet.")
        return
    st.dataframe(
        [{"technique": t.technique_id, "name": t.name, "tactic": t.tactic, "count": t.count}
         for t in techs],
        use_container_width=True,
    )
    tactics = roll.tactics()
    if tactics:
        st.caption("Tactics seen: " + ", ".join(f"{k} ({v})" for k, v in tactics.items()))


# ------------------------------------------------------------------ Logs/SIEM
def _siem_page(state: AppState) -> None:
    st.markdown("#### Logs & SIEM")
    names = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    choice = st.radio("Minimum severity", names, index=1, horizontal=True)
    query = SiemQuery(min_severity=Severity[choice])
    text = st.text_input("Text contains", "")
    if text:
        query.text_contains = text
    hits = state.soc.siem.search(query, limit=400)
    st.caption(f"{len(hits)} matching events")
    st.dataframe(
        [
            {
                "time": str(getattr(e, "timestamp", ""))[11:19],
                "sev": e.severity.label,
                "type": getattr(e.event_type, "name", str(e.event_type)),
                "source": e.source,
                "message": e.message,
                "mitre": getattr(e, "mitre_id", None),
            }
            for e in reversed(hits)
        ],
        use_container_width=True,
        height=520,
    )


# ----------------------------------------------------------- Packet Inspector
def _packet_page(state: AppState) -> None:
    st.markdown("#### Packet Inspector")
    res = state.last_result
    if res is None:
        st.info("Launch an attack to inspect packet traversal.")
        return
    st.caption(res.summary() if hasattr(res, "summary") else res.name)
    traversals = getattr(res, "traversals", []) or []
    for i, t in enumerate(traversals[:12], start=1):
        pkt = t.packet
        with st.expander(f"Flow {i}: {pkt.source_ip} -> {pkt.dest_ip}  [{pkt.status}]"):
            st.dataframe(
                [
                    {
                        "seq": h.seq,
                        "device": h.device,
                        "action": getattr(h.action, "name", str(h.action)),
                        "ttl": h.ttl,
                        "reason": h.reason,
                    }
                    for h in pkt.history
                ],
                use_container_width=True,
            )


# ------------------------------------------------------------ Device Library
def _device_library(state: AppState) -> None:
    st.markdown("#### Device Library")
    try:
        from core.devices.factory import DeviceFactory
        try:
            catalog = DeviceFactory().catalog()
        except TypeError:
            catalog = DeviceFactory.catalog()
    except Exception as exc:  # noqa: BLE001
        st.warning(f"Device catalog unavailable: {exc}")
        return
    for d in catalog:
        with st.expander(f"{d.get('label') or d.get('key')}  ({d.get('type')})"):
            st.markdown(f"**Purpose:** {d.get('purpose', '-')}")
            osi = d.get("osi_layers")
            if osi:
                st.markdown(f"**OSI layers:** {osi}")
            vendors = d.get("vendors")
            if vendors:
                st.markdown(f"**Vendors:** {vendors}")


# ---------------------------------------------------------------------- Settings
def _settings_page(state: AppState) -> None:
    st.markdown("#### Settings")
    st.json(
        {
            "name": getattr(CONFIG, "name", None),
            "version": getattr(CONFIG, "version", None),
            "tagline": getattr(CONFIG, "tagline", None),
            "default_ttl": getattr(CONFIG, "default_ttl", None),
            "packet_animation_ms": getattr(CONFIG, "packet_animation_ms", None),
            "db_path": str(getattr(CONFIG, "db_path", None)),
        }
    )
    st.caption("Configuration is defined in config/settings.py and is read-only here.")


# ------------------------------------------------------------------- helpers
def _node_rows(data: dict) -> list[dict]:
    return [
        {
            "device": n["id"],
            "type": n.get("type"),
            "vlan": n.get("vlan"),
            "ip": n.get("ip"),
            "status": n.get("status"),
        }
        for n in data["nodes"]
    ]


def _idx(items: list[str], wanted: str) -> int:
    return items.index(wanted) if wanted in items else 0
