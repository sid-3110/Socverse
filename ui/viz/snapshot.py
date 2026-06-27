"""VizSnapshot serializer: the single read-only seam between the live engines
and the browser renderer.

`build_snapshot()` walks the topology, every device, the last AttackResult and
the SOC engine, and emits ONE JSON-safe dict. The renderer consumes this dict
and never calls back into Python, which is what keeps the visualization smooth.

This module imports no Streamlit and no Plotly - it is pure domain serialization
and can be unit-tested in isolation.
"""
from __future__ import annotations

from typing import Any

from config.settings import CONFIG
from utils.helpers import now_iso

# Soft dependency on the device knowledge base (Module 2). Until it exists,
# dossiers ship without the educational fields - nothing breaks.
try:  # pragma: no cover
    from ui.viz.encyclopedia import get_dossier_knowledge
except Exception:  # noqa: BLE001
    def get_dossier_knowledge(device_type: str | None) -> dict:
        return {}

# Packet colour language (kept here so Python and JS agree on one source).
PACKET_COLORS: dict[str, str] = {
    "normal": "#22c55e",      # green  - normal traffic
    "dns": "#3b82f6",         # blue   - DNS
    "vpn": "#a855f7",         # purple - VPN tunnel
    "suspicious": "#f59e0b",  # orange - suspicious / attack in transit
    "blocked": "#ef4444",     # red    - blocked by a control
    "dropped": "#f97316",     # amber  - dropped (TTL / closed port)
    "malware": "#ec4899",     # pink   - malware
    "internal": "#e5e7eb",    # white  - internal east-west
}

_SECURITY = {"NGFW", "FIREWALL", "WAF", "PROXY", "VPN"}
_NETWORK = {"ROUTER", "SWITCH", "ISP", "INTERNET"}


# --------------------------------------------------------------- public API
def build_snapshot(
    topology,
    soc,
    *,
    result=None,
    attack_key: str | None = None,
    scenario: str = "Enterprise Baseline",
) -> dict[str, Any]:
    """Assemble the complete render snapshot. `result` is the last AttackResult
    (or None for an idle, healthy network)."""
    graph = topology.graph_data()
    return {
        "meta": {
            "name": getattr(CONFIG, "name", "SOCVerse"),
            "generated": now_iso(),
            "scenario": scenario,
            "attack": result.name if result is not None else None,
            "status": "under_attack" if result is not None else "healthy",
        },
        "colors": PACKET_COLORS,
        "nodes": _nodes(graph),
        "edges": _edges(graph),
        "devices": {hn: _dossier(topology.get(hn)) for hn in topology.hostnames},
        "attack": _attack(result, attack_key),
        "packets": _packets(result),
        "timeline": _timeline(result),
        "soc": _soc(soc),
    }


def snapshot_from_state(state, **kwargs) -> dict[str, Any]:
    """Convenience wrapper that reads everything off the AppState."""
    return build_snapshot(state.topology, state.soc, result=state.last_result, **kwargs)


# ------------------------------------------------------------- graph nodes
def _group(device_type: str | None) -> str:
    t = (device_type or "").upper()
    if t in _SECURITY:
        return "security"
    if t in _NETWORK:
        return "network"
    if t == "SERVER":
        return "server"
    if t == "WORKSTATION":
        return "endpoint"
    if t == "CLOUD":
        return "cloud"
    return "other"


def _nodes(graph: dict) -> list[dict]:
    out = []
    for n in graph.get("nodes", []):
        out.append({
            "id": n["id"],
            "label": n.get("label", n["id"]),
            "type": n.get("type"),
            "group": _group(n.get("type")),
            "layer": n.get("layer"),
            "vlan": n.get("vlan"),
            "ip": n.get("ip"),
            "status": n.get("status"),
        })
    return out


def _edges(graph: dict) -> list[dict]:
    out = []
    for e in graph.get("edges", []):
        src, dst = e.get("source"), e.get("target")
        out.append({"id": f"{src}__{dst}", "source": src, "target": dst, "kind": "normal"})
    return out


# ----------------------------------------------------------- device dossier
def _s(value) -> Any:
    """Stringify objects (ipaddress, enums) that are not natively JSON-safe."""
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _interfaces(device) -> list[dict]:
    out = []
    for iface in getattr(device, "interfaces", {}).values():
        out.append({
            "name": getattr(iface, "name", None),
            "ip": _s(getattr(iface, "ip", None)),
            "mac": _s(getattr(iface, "mac", None)),
            "subnet": _s(getattr(iface, "subnet", None)),
            "up": bool(getattr(iface, "is_up", True)),
        })
    return out


def _routes(device) -> list[dict]:
    rt = getattr(device, "routing_table", None)
    if rt is None:
        return []
    out = []
    for r in getattr(rt, "routes", []) or []:
        out.append({
            "destination": _s(getattr(r, "destination", "")),
            "next_hop": _s(getattr(r, "next_hop", None)),
            "interface": _s(getattr(r, "interface", None)),
            "metric": getattr(r, "metric", None),
        })
    return out


def _ports(device) -> list[int]:
    svc = getattr(device, "services", None)
    if isinstance(svc, dict):
        return sorted(int(k) for k in svc.keys())
    if isinstance(svc, (set, list, tuple)):
        return sorted(int(p) for p in svc)
    return []


def _osi(device) -> list[int]:
    layers = getattr(device, "OSI_LAYERS", ()) or ()
    out = []
    for layer in layers:
        try:
            out.append(int(layer))
        except (TypeError, ValueError):
            pass
    return out


def _dossier(device) -> dict:
    info = device.info()
    ifaces = _interfaces(device)
    return {
        "name": info.get("hostname"),
        "type": info.get("type"),
        "vendor": info.get("vendor"),
        "os": info.get("os"),
        "ip": info.get("ip"),
        "mac": ifaces[0]["mac"] if ifaces else None,
        "status": info.get("status"),
        "cpu": info.get("cpu"),
        "ram": info.get("ram"),
        "group": _group(info.get("type")),
        "purpose": getattr(device, "PURPOSE", "") or "",
        "osi_layers": _osi(device),
        "interfaces": ifaces,
        "connections": list(info.get("connections", [])),
        "routes": _routes(device),
        "open_ports": _ports(device),
        "kb": get_dossier_knowledge(info.get("type")),
    }


# ------------------------------------------------------------------- attack
def _attack(result, attack_key: str | None) -> dict | None:
    if result is None:
        return None
    paths = [list(getattr(t.packet, "path", []) or []) for t in getattr(result, "traversals", [])]
    path = max(paths, key=len) if paths else []
    sev = getattr(result, "severity", None)
    return {
        "key": attack_key,
        "name": getattr(result, "name", "Attack"),
        "tactic": getattr(result, "tactic", None),
        "severity": int(sev) if sev is not None else None,
        "source": getattr(result, "source", None),
        "target": getattr(result, "target", None),
        "techniques": list(getattr(result, "mitre_ids", []) or []),
        "path": path,
        "summary": result.summary() if hasattr(result, "summary") else "",
        "success": bool(getattr(result, "success", False)),
    }


# ------------------------------------------------------------------ packets
def _packet_class(pkt, is_attack: bool) -> str:
    status = getattr(pkt, "status", "")
    proto = getattr(pkt, "protocol", None)
    pname = getattr(proto, "name", str(proto)) if proto else ""
    if status == "blocked":
        return "blocked"
    if status == "dropped":
        return "dropped"
    if pname == "DNS":
        return "dns"
    if is_attack:
        return "suspicious"
    return "normal"


def _hops(pkt) -> list[dict]:
    out = []
    for h in getattr(pkt, "history", []) or []:
        out.append({
            "seq": getattr(h, "seq", None),
            "device": getattr(h, "device", None),
            "action": getattr(getattr(h, "action", None), "name", _s(getattr(h, "action", None))),
            "ttl": getattr(h, "ttl", None),
            "latency": getattr(h, "latency_ms", None),
            "reason": getattr(h, "reason", ""),
        })
    return out


def _packets(result, limit: int = 80) -> list[dict]:
    if result is None:
        return []
    is_attack = True
    out = []
    for t in getattr(result, "traversals", [])[:limit]:
        pkt = t.packet
        klass = _packet_class(pkt, is_attack)
        proto = getattr(pkt, "protocol", None)
        out.append({
            "id": getattr(pkt, "id", None),
            "klass": klass,
            "color": PACKET_COLORS.get(klass, "#9ca3af"),
            "status": getattr(pkt, "status", None),
            "protocol": getattr(proto, "name", _s(proto)) if proto else None,
            "dst_port": getattr(pkt, "dst_port", None),
            "path": list(getattr(pkt, "path", []) or []),
            "hops": _hops(pkt),
        })
    return out


# ----------------------------------------------------------------- timeline
def _clock(ts) -> str:
    if hasattr(ts, "strftime"):
        return ts.strftime("%H:%M:%S")
    s = str(ts)
    return s[11:19] if len(s) >= 19 else s


def _tl_entry(ev, is_alert: bool = False) -> dict:
    sev = getattr(ev, "severity", None)
    etype = getattr(ev, "event_type", None)
    return {
        "_ts": str(getattr(ev, "timestamp", "")),
        "time": _clock(getattr(ev, "timestamp", None)),
        "device": getattr(ev, "source", None),
        "label": getattr(ev, "message", ""),
        "severity": getattr(sev, "label", str(sev)) if sev is not None else "INFO",
        "kind": "alert" if is_alert else getattr(etype, "name", "LOG"),
        "mitre": getattr(ev, "mitre_id", None),
    }


def _timeline(result, limit: int = 40) -> list[dict]:
    if result is None:
        return []
    items = []
    for ev in getattr(result, "events", []) or []:
        sev = getattr(ev, "severity", None)
        if sev is not None and int(sev) < 1:   # drop INFO-level hop noise
            continue
        items.append(_tl_entry(ev))
    for al in getattr(result, "alerts", []) or []:
        items.append(_tl_entry(al, is_alert=True))
    items.sort(key=lambda x: x["_ts"])
    for it in items:
        it.pop("_ts", None)
    return items[:limit]


# --------------------------------------------------------------------- soc
def _soc(soc) -> dict:
    try:
        alerts = [a.to_dict() for a in soc.alerts()[:20]]
    except Exception:  # noqa: BLE001
        alerts = []
    return {"stats": soc.stats(), "alerts": alerts}
