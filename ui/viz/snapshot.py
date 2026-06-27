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


# --------------------------------------------------- role hint + metrics
# Both are DISPLAY-ONLY. They drive icon selection and the per-device meters
# in the browser. Seeded deterministically by hostname so a given device looks
# identical on every render (no flicker, no Python round-trips). Adding these
# fields is purely additive - existing keys and behaviour are untouched.

_ROLE_RULES = (
    ("INTERNET", ("INTERNET",)),
    ("ISP", ("ISP",)),
    ("ATTACKER", ("ATTACK", "ADVERSARY", "KALI", "C2")),
    ("NGFW", ("NGFW", "FIREWALL", "FW", "PALO", "FORTI")),
    ("WAF", ("WAF",)),
    ("PROXY", ("PROXY", "SQUID")),
    ("VPN", ("VPN",)),
    ("DNS", ("DNS",)),
    ("DC", ("AD-", "ADDC", "DC-", "-DC", "DOMAIN")),
    ("ROUTER", ("RTR", "ROUTER", "GW", "GATEWAY", "EDGE")),
    ("SWITCH", ("SWITCH", "-SW", "SW-", "CORE-SW", "ACCESS")),
    ("CLOUD", ("CLOUD", "VPC", "AWS", "AZURE", "GCP", "S3")),
    ("WORKSTATION", ("WS", "GUEST", "DESKTOP", "LAPTOP", "CLIENT", "HOST", "PC")),
    ("SERVER", ("SRV", "SERVER", "WEB", "APP", "DB", "MAIL", "FILE")),
)

_TYPE_ROLE = {
    "ROUTER": "ROUTER", "SWITCH": "SWITCH", "NGFW": "NGFW", "FIREWALL": "NGFW",
    "WAF": "WAF", "PROXY": "PROXY", "VPN": "VPN", "DNS": "DNS",
    "SERVER": "SERVER", "WORKSTATION": "WORKSTATION", "CLOUD": "CLOUD",
    "INTERNET": "INTERNET", "ISP": "ISP",
}


def _role(name: str | None, device_type: str | None) -> str:
    hn = (name or "").upper()
    for role, needles in _ROLE_RULES:
        for needle in needles:
            if needle in hn:
                return role
    return _TYPE_ROLE.get((device_type or "").upper(), "GENERIC")


def _fnv1a(text: str) -> int:
    """32-bit FNV-1a - the exact hash the JS fallback uses, so server-supplied
    metrics line up with the client's deterministic synthesis."""
    h = 0x811C9DC5
    for ch in text:
        h ^= ord(ch) & 0xFF
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


class _Rng:
    """Tiny LCG mirroring the JS PRNG (same constants) for stable per-seed runs."""

    def __init__(self, seed: int) -> None:
        self.s = seed & 0xFFFFFFFF or 0x9E3779B9

    def next(self) -> float:
        self.s = (self.s * 1664525 + 1013904223) & 0xFFFFFFFF
        return self.s / 0x100000000

    def between(self, lo: float, hi: float) -> float:
        return lo + (hi - lo) * self.next()


# Per-role load profiles: (cpu_lo, cpu_hi, mem_lo, mem_hi, util_lo, util_hi,
# traffic_lo_mbps, traffic_hi_mbps, latency_lo_ms, latency_hi_ms).
_LOAD_PROFILE = {
    "ROUTER":      (18, 62, 30, 70, 25, 80, 120, 940, 1, 9),
    "SWITCH":      (10, 45, 25, 60, 30, 88, 200, 980, 1, 6),
    "NGFW":        (28, 78, 40, 82, 35, 90, 90, 760, 2, 14),
    "WAF":         (24, 70, 38, 80, 22, 72, 40, 420, 3, 18),
    "PROXY":       (20, 66, 35, 78, 20, 70, 60, 520, 4, 22),
    "VPN":         (22, 68, 36, 78, 18, 64, 30, 360, 6, 28),
    "DNS":         (8, 38, 22, 58, 6, 40, 8, 180, 1, 12),
    "DC":          (26, 74, 45, 88, 14, 58, 20, 320, 2, 16),
    "SERVER":      (20, 82, 40, 90, 12, 66, 40, 600, 2, 20),
    "WORKSTATION": (5, 55, 20, 75, 4, 34, 4, 120, 4, 30),
    "CLOUD":       (16, 70, 35, 85, 20, 78, 80, 880, 8, 40),
    "INTERNET":    (4, 22, 10, 40, 40, 95, 300, 990, 5, 35),
    "ISP":         (12, 48, 20, 55, 45, 92, 260, 970, 3, 24),
    "ATTACKER":    (30, 95, 35, 85, 10, 60, 10, 240, 6, 60),
    "GENERIC":     (12, 60, 25, 75, 12, 60, 20, 400, 2, 24),
}


def _band(value: float, warn: float, hot: float) -> str:
    if value >= hot:
        return "hot"
    if value >= warn:
        return "warn"
    return "ok"


def _metrics(name: str | None, role: str, status: str | None) -> dict:
    """Deterministic, display-only utilisation snapshot for one device."""
    p = _LOAD_PROFILE.get(role, _LOAD_PROFILE["GENERIC"])
    rng = _Rng(_fnv1a(f"{name or role}|{role}"))
    cpu = round(rng.between(p[0], p[1]))
    mem = round(rng.between(p[2], p[3]))
    util = round(rng.between(p[4], p[5]))
    traffic = round(rng.between(p[6], p[7]))      # Mbps
    latency = round(rng.between(p[8], p[9]))      # ms

    st = (status or "").lower()
    if st in ("down", "offline", "compromised", "critical"):
        cpu = min(99, cpu + 18)
        util = max(0, util - 30) if st in ("down", "offline") else min(99, util + 12)

    health = max(0, 100 - round(cpu * 0.5 + util * 0.3 + max(0, latency - 10) * 0.6))
    return {
        "cpu": cpu,
        "mem": mem,
        "util": util,
        "traffic": traffic,        # Mbps, display-only
        "latency": latency,        # ms, display-only
        "health": health,          # 0-100, higher is better
        "cpu_band": _band(cpu, 60, 85),
        "mem_band": _band(mem, 65, 88),
        "util_band": _band(util, 65, 85),
    }


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
    name = info.get("hostname")
    dtype = info.get("type")
    status = info.get("status")
    role = _role(name, dtype)
    return {
        "name": name,
        "type": dtype,
        "role": role,                     # display-only icon/profile hint
        "vendor": info.get("vendor"),
        "os": info.get("os"),
        "ip": info.get("ip"),
        "mac": ifaces[0]["mac"] if ifaces else None,
        "status": status,
        "cpu": info.get("cpu"),
        "ram": info.get("ram"),
        "group": _group(dtype),
        "metrics": _metrics(name, role, status),   # display-only meters
        "purpose": getattr(device, "PURPOSE", "") or "",
        "osi_layers": _osi(device),
        "interfaces": ifaces,
        "connections": list(info.get("connections", [])),
        "routes": _routes(device),
        "open_ports": _ports(device),
        "kb": get_dossier_knowledge(dtype),
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
