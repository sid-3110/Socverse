"""
core/simulation/packet.py
The Packet domain object: a real, mutable object that records its own
journey hop-by-hop. No framework imports.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from config.settings import CONFIG
from core.enums import PacketAction, Protocol
from utils.helpers import clamp, now_iso, short_id


@dataclass
class PacketFlags:
    """TCP-style control flags plus a free-form custom set."""
    syn: bool = False
    ack: bool = False
    fin: bool = False
    rst: bool = False
    psh: bool = False
    urg: bool = False
    custom: set[str] = field(default_factory=set)

    def active(self) -> list[str]:
        named = [n.upper() for n in ("syn", "ack", "fin", "rst", "psh", "urg")
                 if getattr(self, n)]
        return named + sorted(self.custom)

    def __str__(self) -> str:
        return ",".join(self.active()) or "—"


@dataclass
class HopRecord:
    """One entry in a packet's travel history."""
    seq: int
    device: str
    action: PacketAction
    ttl: int
    latency_ms: float
    reason: str = ""
    timestamp: str = field(default_factory=now_iso)

    def __str__(self) -> str:
        r = f" ({self.reason})" if self.reason else ""
        return (f"#{self.seq} {self.device}: {self.action.value} "
                f"ttl={self.ttl} {self.latency_ms:.1f}ms{r}")


@dataclass
class Packet:
    """A network packet that travels the simulated topology."""
    source_ip: str
    dest_ip: str
    protocol: Protocol = Protocol.TCP
    src_port: int | None = None
    dst_port: int | None = None
    payload: str = ""
    ttl: int = CONFIG.default_ttl
    flags: PacketFlags = field(default_factory=PacketFlags)

    # Runtime / journey state
    id: str = field(default_factory=lambda: short_id("pkt"))
    hop_count: int = 0
    current_device: str | None = None
    history: list[HopRecord] = field(default_factory=list)
    total_latency_ms: float = 0.0

    # Terminal state
    delivered: bool = False
    dropped: bool = False
    blocked: bool = False
    drop_reason: str = ""

    created_at: str = field(default_factory=now_iso)
    metadata: dict[str, Any] = field(default_factory=dict)

    # ----------------------------------------------------------------- #
    # Lifecycle
    # ----------------------------------------------------------------- #
    @property
    def is_alive(self) -> bool:
        return not (self.delivered or self.dropped or self.blocked) and self.ttl > 0

    @property
    def status(self) -> str:
        if self.delivered:
            return "delivered"
        if self.blocked:
            return "blocked"
        if self.dropped:
            return "dropped"
        return "in-flight"

    def decrement_ttl(self, n: int = 1) -> int:
        self.ttl = clamp(self.ttl - n, 0, 255)
        return self.ttl

    def record_hop(self, device: str, action: PacketAction,
                   latency_ms: float, reason: str = "") -> HopRecord:
        self.hop_count += 1
        self.current_device = device
        self.total_latency_ms += latency_ms
        hop = HopRecord(self.hop_count, device, action, self.ttl, latency_ms, reason)
        self.history.append(hop)
        return hop

    # ----------------------------------------------------------------- #
    # Views
    # ----------------------------------------------------------------- #
    @property
    def path(self) -> list[str]:
        return [h.device for h in self.history]

    def summary(self) -> str:
        port = f":{self.dst_port}" if self.dst_port else ""
        return (f"{self.protocol.value} {self.source_ip} -> {self.dest_ip}{port} "
                f"[{self.flags}] {self.status} ({self.hop_count} hops, "
                f"{self.total_latency_ms:.1f}ms)")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "protocol": self.protocol.value,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "ttl": self.ttl,
            "flags": str(self.flags),
            "status": self.status,
            "hop_count": self.hop_count,
            "total_latency_ms": round(self.total_latency_ms, 2),
            "drop_reason": self.drop_reason,
            "path": self.path,
            "payload": self.payload,
        }

    # ----------------------------------------------------------------- #
    # Factory constructors — convenient, intent-revealing packet builders
    # ----------------------------------------------------------------- #
    @classmethod
    def tcp_syn(cls, src: str, dst: str, dst_port: int, **kw: Any) -> "Packet":
        return cls(src, dst, Protocol.TCP, dst_port=dst_port,
                   flags=PacketFlags(syn=True), **kw)

    @classmethod
    def icmp_echo(cls, src: str, dst: str, **kw: Any) -> "Packet":
        return cls(src, dst, Protocol.ICMP, payload="echo-request", **kw)

    @classmethod
    def udp(cls, src: str, dst: str, dst_port: int, **kw: Any) -> "Packet":
        return cls(src, dst, Protocol.UDP, dst_port=dst_port, **kw)