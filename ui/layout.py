"""Tabbed application shell. Tab 1 is the Operations 3-pane; the rest are
dedicated pages, each a pure view over the live engines in AppState.

Module 5 (visual only): KPI tiles, severity pills, styled log stream.
Settings update: the Settings tab is now interactive - Appearance controls and
Data management. Preferences live in st.session_state (per-session) and are
applied as scoped CSS overrides; no engine, config file, or core logic changes.
"""
from __future__ import annotations

import csv
import io
import json

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

# Severity -> hex, used by pills and the log stream.
_SEV_HEX = {
    "INFO": "#6b7280",
    "LOW": "#3b82f6",
    "MEDIUM": "#f59e0b",
    "HIGH": "#f97316",
    "CRITICAL": "#ef4444",
}
_STATUS_HEX = {
    "up": "#22c55e", "online": "#22c55e", "active": "#22c55e", "healthy": "#22c55e",
    "down": "#ef4444", "offline": "#ef4444", "critical": "#ef4444",
    "compromised": "#ec4899", "degraded": "#f59e0b", "warning": "#f59e0b",
}

# Session-scoped UI preferences (Settings tab). Keys are namespaced sv_pref_*.
_PREF_DEFAULTS = {
    "sv_pref_accent": "#3b82f6",
    "sv_pref_density": "Comfortable",
    "sv_pref_logview": "Log stream",
}


def render_layout(state: AppState) -> None:
    for k, v in _PREF_DEFAULTS.items():
        st.session_state.setdefault(k, v)
    _console_css()
    _apply_appearance()
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


# --------------------------------------------------------------- console CSS
def _console_css() -> None:
    """Scoped styling for the SOC console widgets. Reads --sv-* tokens from
    theme.py and provides fallbacks so it renders standalone."""
    st.markdown(
        """
<style>
:root{
  --svc-surface: var(--sv-surface, #11161d);
  --svc-glass: var(--sv-surface-glass, rgba(255,255,255,0.025));
  --svc-border: var(--sv-border-soft, rgba(255,255,255,0.08));
  --svc-text: var(--sv-text, #e6edf3);
  --svc-dim: var(--sv-text-dim, #8b949e);
  --svc-primary: var(--sv-primary, #3b82f6);
  --svc-radius: var(--sv-radius, 12px);
  --svc-mono: var(--sv-mono, ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace);
  --svc-pad: .7rem;
}
.sv-kpis{display:flex;gap:.7rem;flex-wrap:wrap;margin:.2rem 0 .6rem}
.sv-kpi{flex:1 1 120px;min-width:120px;background:var(--svc-glass);
  border:1px solid var(--svc-border);border-radius:var(--svc-radius);
  padding:var(--svc-pad) calc(var(--svc-pad) + .15rem);position:relative;overflow:hidden;
  transition:transform .15s ease,border-color .15s ease;}
.sv-kpi:hover{transform:translateY(-2px);border-color:var(--svc-primary)}
.sv-kpi::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;
  background:var(--svc-accent,var(--svc-primary));opacity:.9}
.sv-kpi-lbl{font-size:.66rem;letter-spacing:.08em;text-transform:uppercase;
  color:var(--svc-dim);font-weight:600}
.sv-kpi-val{font-size:1.55rem;font-weight:700;line-height:1.1;color:var(--svc-text);
  font-variant-numeric:tabular-nums;margin-top:.15rem}
.sv-kpi-sub{font-size:.7rem;color:var(--svc-dim);margin-top:.1rem}
.sv-pill{display:inline-block;padding:.08rem .5rem;border-radius:999px;
  font-size:.66rem;font-weight:700;letter-spacing:.04em;line-height:1.55;
  border:1px solid transparent;white-space:nowrap}
.sv-sevbar{display:flex;gap:.4rem;flex-wrap:wrap;margin:.3rem 0 .2rem}
.sv-alertcard{background:var(--svc-glass);border:1px solid var(--svc-border);
  border-left-width:4px;border-radius:10px;padding:.55rem .75rem;margin:.35rem 0;
  transition:border-color .15s ease}
.sv-alertcard:hover{border-color:var(--svc-primary)}
.sv-alertcard b{color:var(--svc-text)}
.sv-logwrap{max-height:540px;overflow:auto;border:1px solid var(--svc-border);
  border-radius:var(--svc-radius);background:var(--svc-surface);padding:.25rem}
.sv-logrow{display:grid;grid-template-columns:74px 78px 130px 1fr 90px;gap:.55rem;
  align-items:center;padding:.3rem .55rem;border-bottom:1px solid var(--svc-border);
  font-family:var(--svc-mono);font-size:.74rem;border-left:3px solid transparent}
.sv-logrow:last-child{border-bottom:none}
.sv-logrow:hover{background:var(--svc-glass)}
.sv-logtime{color:var(--svc-dim)}
.sv-logsrc{color:var(--svc-text);font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sv-logmsg{color:var(--svc-text);opacity:.92;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sv-logmitre{color:var(--svc-primary);font-size:.68rem;text-align:right}
.sv-sec{font-size:.78rem;font-weight:700;letter-spacing:.06em;text-transform:uppercase;
  color:var(--svc-dim);margin:.5rem 0 .25rem;display:flex;align-items:center;gap:.4rem}
.sv-sec::after{content:"";flex:1;height:1px;background:var(--svc-border)}
.sv-swatch{display:inline-block;width:.85rem;height:.85rem;border-radius:3px;
  vertical-align:middle;margin-right:.35rem;border:1px solid var(--svc-border)}
</style>
        """,
        unsafe_allow_html=True,
    )


def _apply_appearance() -> None:
    """Translate session-state preferences into a live CSS override. Pure
    presentation - reruns on every interaction, so changes take effect at once."""
    accent = st.session_state.get("sv_pref_accent", _PREF_DEFAULTS["sv_pref_accent"])
    density = st.session_state.get("sv_pref_density", _PREF_DEFAULTS["sv_pref_density"])
    pad = ".45rem" if density == "Compact" else ".7rem"
    st.markdown(
        f"<style>:root{{--sv-primary:{accent};--svc-primary:{accent};"
        f"--svp-primary:{accent};--svc-pad:{pad};}}</style>",
        unsafe_allow_html=True,
    )


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
    st.dataframe(
        _node_rows(data),
        use_container_width=True,
        height=440,
        column_config=_NODE_COLS,
    )


def _soc_dashboard(state: AppState) -> None:
    st.markdown("#### SOC Dashboard")
    stats = state.soc.stats()
    by_sev = stats.get("by_severity", {})
    crit = by_sev.get("CRITICAL", 0) + by_sev.get("HIGH", 0)
    st.markdown(
        _kpis(
            [
                ("Events", stats["total_events"], None, "--svc-primary"),
                ("Alerts", stats["total_alerts"], None, "#f59e0b"),
                ("Open", stats["open_alerts"], None, "#ef4444"),
                ("Crit/High", crit, "priority", "#ec4899"),
            ]
        ),
        unsafe_allow_html=True,
    )
    if by_sev:
        st.markdown(
            "<div class='sv-sevbar'>"
            + "".join(_pill(f"{k} {v}", _SEV_HEX.get(k, "#6b7280")) for k, v in by_sev.items())
            + "</div>",
            unsafe_allow_html=True,
        )

    alerts = state.soc.alerts()
    if not alerts:
        st.info("No alerts yet. Launch an attack.")
        return
    st.markdown("<div class='sv-sec'>Recent alerts</div>", unsafe_allow_html=True)
    for a in sorted(alerts, key=lambda x: int(x.severity), reverse=True)[:6]:
        clr = SEVERITY_COLORS.get(a.severity_key, _SEV_HEX.get(a.severity.label, "#888"))
        st.markdown(
            f"<div class='sv-alertcard' style='border-left-color:{clr}'>"
            f"{_pill(a.severity.label, clr)} <b>{a.title}</b>"
            f"<br><span class='sv-muted' style='font-size:.72rem'>{a.mitre_id} &middot; {a.tactic}</span></div>",
            unsafe_allow_html=True,
        )


# ---------------------------------------------------------------------- Alerts
def _alerts_page(state: AppState) -> None:
    st.markdown("#### Alert Investigation")
    alerts = state.soc.alerts()
    if not alerts:
        st.info("No alerts yet. Launch an attack from the Operations tab.")
        return

    counts: dict[str, int] = {}
    for a in alerts:
        counts[a.severity.label] = counts.get(a.severity.label, 0) + 1
    st.markdown(
        _kpis(
            [("Total alerts", len(alerts), None, "--svc-primary")]
            + [
                (lbl, counts.get(lbl, 0), None, _SEV_HEX.get(lbl, "#6b7280"))
                for lbl in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
                if counts.get(lbl)
            ]
        ),
        unsafe_allow_html=True,
    )

    for a in sorted(alerts, key=lambda x: int(x.severity), reverse=True):
        clr = SEVERITY_COLORS.get(a.severity_key, _SEV_HEX.get(a.severity.label, "#888"))
        with st.expander(f"[{a.severity.label}] {a.title}"):
            st.markdown(
                f"<div class='sv-alertcard' style='border-left-color:{clr};margin:0 0 .5rem'>"
                f"{_pill(a.severity.label, clr)} "
                f"<span class='sv-muted'>{a.mitre_id} &middot; {a.tactic}</span></div>",
                unsafe_allow_html=True,
            )
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
    nodes = data["nodes"]
    up = sum(1 for n in nodes if str(n.get("status", "")).lower() in ("up", "online", "active", "healthy"))
    st.markdown(
        _kpis(
            [
                ("Devices", len(nodes), None, "--svc-primary"),
                ("Links", len(data["edges"]), None, "#a855f7"),
                ("Online", up, None, "#22c55e"),
                ("Offline", len(nodes) - up, None, "#ef4444"),
            ]
        ),
        unsafe_allow_html=True,
    )
    st.dataframe(
        _node_rows(data),
        use_container_width=True,
        height=520,
        column_config=_NODE_COLS,
    )
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
    tactics = roll.tactics()
    st.markdown(
        _kpis(
            [
                ("Techniques", len(techs), None, "--svc-primary"),
                ("Tactics", len(tactics) if tactics else 0, None, "#a855f7"),
                ("Observations", sum(t.count for t in techs), None, "#f59e0b"),
            ]
        ),
        unsafe_allow_html=True,
    )
    st.dataframe(
        [{"technique": t.technique_id, "name": t.name, "tactic": t.tactic, "count": t.count}
         for t in techs],
        use_container_width=True,
        column_config={
            "technique": st.column_config.TextColumn("Technique", width="small"),
            "name": st.column_config.TextColumn("Name"),
            "tactic": st.column_config.TextColumn("Tactic"),
            "count": st.column_config.NumberColumn("Count", format="%d"),
        },
    )
    if tactics:
        st.markdown(
            "<div class='sv-sevbar'>"
            + "".join(_pill(f"{k} {v}", "#a855f7") for k, v in tactics.items())
            + "</div>",
            unsafe_allow_html=True,
        )


# ------------------------------------------------------------------ Logs/SIEM
def _siem_page(state: AppState) -> None:
    st.markdown("#### Logs & SIEM")
    names = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    c1, c2, c3 = st.columns([2, 2, 1])
    with c1:
        choice = st.radio("Minimum severity", names, index=1, horizontal=True)
    with c2:
        text = st.text_input("Text contains", "")
    with c3:
        default_stream = st.session_state.get("sv_pref_logview", "Log stream") == "Log stream"
        as_stream = st.toggle("Log stream", value=default_stream)

    query = SiemQuery(min_severity=Severity[choice])
    if text:
        query.text_contains = text
    hits = state.soc.siem.search(query, limit=400)
    st.caption(f"{len(hits)} matching events")

    rows = list(reversed(hits))
    if as_stream:
        st.markdown(_log_stream(rows), unsafe_allow_html=True)
    else:
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
                for e in rows
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
        clr = _STATUS_HEX.get(str(pkt.status).lower(), "#6b7280")
        with st.expander(f"Flow {i}: {pkt.source_ip} -> {pkt.dest_ip}  [{pkt.status}]"):
            st.markdown(
                f"{_pill(str(pkt.status).upper(), clr)} "
                f"<span class='sv-muted'>{pkt.source_ip} &rarr; {pkt.dest_ip}</span>",
                unsafe_allow_html=True,
            )
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
            if d.get("type"):
                st.markdown(_pill(str(d.get("type")), "#3b82f6"), unsafe_allow_html=True)
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

    # ---- Appearance -------------------------------------------------------
    st.markdown("<div class='sv-sec'>Appearance</div>", unsafe_allow_html=True)
    a1, a2, a3 = st.columns([2, 2, 2])
    with a1:
        st.color_picker("Accent color", key="sv_pref_accent")
    with a2:
        st.radio("UI density", ["Comfortable", "Compact"], key="sv_pref_density", horizontal=True)
    with a3:
        st.radio("Default log view", ["Log stream", "Table"], key="sv_pref_logview", horizontal=True)

    accent = st.session_state.get("sv_pref_accent", _PREF_DEFAULTS["sv_pref_accent"])
    st.markdown(
        f"<span class='sv-muted' style='font-size:.78rem'>"
        f"<span class='sv-swatch' style='background:{accent}'></span>"
        f"Live preview: {_pill('ACCENT', accent)} {_pill('CRITICAL', '#ef4444')} "
        f"applied across KPI tiles, links, and accents.</span>",
        unsafe_allow_html=True,
    )
    if st.button("Reset appearance to defaults"):
        for k, v in _PREF_DEFAULTS.items():
            st.session_state[k] = v
        st.rerun()

    # ---- Data management --------------------------------------------------
    st.markdown("<div class='sv-sec'>Data management</div>", unsafe_allow_html=True)
    stats = state.soc.stats()
    st.markdown(
        _kpis(
            [
                ("Events", stats.get("total_events", 0), None, "--svc-primary"),
                ("Alerts", stats.get("total_alerts", 0), None, "#f59e0b"),
                ("Sim runs", len(getattr(state, "history", []) or []), None, "#a855f7"),
            ]
        ),
        unsafe_allow_html=True,
    )

    d1, d2 = st.columns(2)
    with d1:
        snap_json = _snapshot_json(state)
        st.download_button(
            "Download snapshot (JSON)",
            data=snap_json,
            file_name="socverse_snapshot.json",
            mime="application/json",
            use_container_width=True,
        )
    with d2:
        st.download_button(
            "Download logs (CSV)",
            data=_logs_csv(state),
            file_name="socverse_logs.csv",
            mime="text/csv",
            use_container_width=True,
        )

    r1, r2 = st.columns(2)
    with r1:
        if st.button("Clear simulation history", use_container_width=True):
            hist = getattr(state, "history", None)
            if hist is not None:
                hist.clear()
            state.last_result = None
            st.toast("Simulation history cleared")
            st.rerun()
    with r2:
        if st.button("Reset SOC (events + alerts)", use_container_width=True, type="primary"):
            state.reset_soc()
            st.toast("SOC engine reset")
            st.rerun()
    st.caption(
        "Resets affect only the in-memory simulation state for this session. "
        "Engine configuration in config/settings.py is read-only here."
    )

    # ---- Configuration (read-only) ---------------------------------------
    with st.expander("Engine configuration (read-only)"):
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


# ------------------------------------------------------------------- helpers
def _esc(v) -> str:
    return (
        str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        if v is not None
        else ""
    )


def _pill(label: str, hex_color: str) -> str:
    return (
        f"<span class='sv-pill' style='color:{hex_color};"
        f"border-color:{hex_color}55;background:{hex_color}1a'>{_esc(label)}</span>"
    )


def _kpis(items) -> str:
    """items: list of (label, value, sub, accent_hex_or_var)."""
    cards = []
    for label, value, sub, accent in items:
        sub_html = f"<div class='sv-kpi-sub'>{_esc(sub)}</div>" if sub else ""
        cards.append(
            f"<div class='sv-kpi' style='--svc-accent:{accent}'>"
            f"<div class='sv-kpi-lbl'>{_esc(label)}</div>"
            f"<div class='sv-kpi-val'>{_esc(value)}</div>{sub_html}</div>"
        )
    return "<div class='sv-kpis'>" + "".join(cards) + "</div>"


def _log_stream(events) -> str:
    rows = []
    for e in events:
        lbl = e.severity.label
        clr = _SEV_HEX.get(lbl, "#6b7280")
        t = str(getattr(e, "timestamp", ""))[11:19]
        etype = getattr(e.event_type, "name", str(e.event_type))
        mitre = getattr(e, "mitre_id", None) or ""
        rows.append(
            f"<div class='sv-logrow' style='border-left-color:{clr}'>"
            f"<span class='sv-logtime'>{_esc(t)}</span>"
            f"{_pill(lbl, clr)}"
            f"<span class='sv-logsrc' title='{_esc(e.source)}'>{_esc(e.source)}</span>"
            f"<span class='sv-logmsg' title='{_esc(etype)}: {_esc(e.message)}'>{_esc(e.message)}</span>"
            f"<span class='sv-logmitre'>{_esc(mitre)}</span></div>"
        )
    if not rows:
        rows.append("<div class='sv-logrow'><span class='sv-logmsg'>No events.</span></div>")
    return "<div class='sv-logwrap'>" + "".join(rows) + "</div>"


def _snapshot_json(state: AppState) -> str:
    """Serialize the current render snapshot for download. Falls back to a
    minimal payload if the snapshot serializer is unavailable."""
    try:
        from ui.viz.snapshot import snapshot_from_state
        snap = snapshot_from_state(state)
    except Exception:  # noqa: BLE001
        snap = {
            "meta": {"name": getattr(CONFIG, "name", "SOCVerse")},
            "soc": {"stats": state.soc.stats()},
        }
    return json.dumps(snap, indent=2, default=str)


def _logs_csv(state: AppState) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["time", "severity", "type", "source", "message", "mitre"])
    try:
        hits = state.soc.siem.search(SiemQuery(min_severity=Severity["INFO"]), limit=2000)
    except Exception:  # noqa: BLE001
        hits = []
    for e in hits:
        w.writerow([
            str(getattr(e, "timestamp", "")),
            getattr(getattr(e, "severity", None), "label", ""),
            getattr(getattr(e, "event_type", None), "name", str(getattr(e, "event_type", ""))),
            getattr(e, "source", ""),
            getattr(e, "message", ""),
            getattr(e, "mitre_id", "") or "",
        ])
    return buf.getvalue()


_NODE_COLS = {
    "device": st.column_config.TextColumn("Device", width="medium"),
    "type": st.column_config.TextColumn("Type", width="small"),
    "vlan": st.column_config.TextColumn("VLAN", width="small"),
    "ip": st.column_config.TextColumn("IP Address"),
    "status": st.column_config.TextColumn("Status", width="small"),
}


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
