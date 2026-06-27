"""
core/simulation/engine.py
PacketEngine: drives a packet through the topology, hop by hop, using each
device's process_packet() decision. Topology-agnostic via an injected
device resolver (Dependency Inversion).
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable

from core.enums import DeviceType, EventType, PacketAction, Severity
from core.events import SimulationEvent
from core.simulation.packet import Packet
from utils.logger import get_logger

if TYPE_CHECKING:
    from core.devices.base import AbstractDevice

log = get_logger("packet-engine")

# A function that maps a hostname to a device (or None if unknown).
DeviceResolver = Callable[[str], "AbstractDevice | None"]

# Actions where the packet keeps travelling (and a router decrements TTL).
_TRANSIT_ACTIONS = {
    PacketAction.ROUTE, PacketAction.FORWARD,
    PacketAction.INSPECT, PacketAction.NAT,
}
# Actions that end the journey.
_TERMINAL_ACTIONS = {
    PacketAction.DELIVER, PacketAction.DROP, PacketAction.BLOCK,
}

# Baseline processing latency (ms) by device type.
_LATENCY_BY_TYPE: dict[DeviceType, float] = {
    DeviceType.INTERNET: 25.0,
    DeviceType.ISP: 12.0,
    DeviceType.ROUTER: 1.5,
    DeviceType.SWITCH: 0.4,
    DeviceType.FIREWALL: 2.5,
    DeviceType.NGFW: 5.0,
    DeviceType.WAF: 6.0,
    DeviceType.PROXY: 4.0,
    DeviceType.VPN: 8.0,
    DeviceType.SERVER: 1.0,
    DeviceType.WORKSTATION: 0.8,
    DeviceType.CLOUD: 10.0,
}


@dataclass
class TraversalResult:
    """Outcome of pushing one packet through the network."""
    packet: Packet
    events: list[SimulationEvent] = field(default_factory=list)

    @property
    def path(self) -> list[str]:
        return self.packet.path

    @property
    def status(self) -> str:
        return self.packet.status

    def summary(self) -> str:
        return self.packet.summary()


class PacketEngine:
    """Stateless-per-call engine that simulates packet traversal."""

    def __init__(
        self,
        resolver: DeviceResolver,
        *,
        max_hops: int = 30,
        link_latency_ms: float = 0.5,
        seed: int | None = None,
    ) -> None:
        self._resolver = resolver
        self.max_hops = max_hops
        self.link_latency_ms = link_latency_ms
        self._rng = random.Random(seed)

    # ----------------------------------------------------------------- #
    # Public API
    # ----------------------------------------------------------------- #
    def send(self, packet: Packet, start_hostname: str) -> TraversalResult:
        """Push `packet` into the network starting at `start_hostname`."""
        result = TraversalResult(packet=packet)
        device = self._resolver(start_hostname)
        if device is None:
            packet.dropped = True
            packet.drop_reason = f"unknown start node '{start_hostname}'"
            log.warning(packet.drop_reason)
            return result

        packet.current_device = device.hostname
        guard = 0
        while packet.is_alive and guard < self.max_hops:
            guard += 1
            decision = device.process_packet(packet)
            latency = self._latency(device)

            if decision.action in _TRANSIT_ACTIONS:
                packet.decrement_ttl()

            hop = packet.record_hop(
                device.hostname, decision.action, latency, decision.reason
            )
            result.events.append(self._hop_event(packet, decision, hop))

            # --- terminal outcomes ---
            if decision.action == PacketAction.DELIVER:
                packet.delivered = True
                break
            if decision.action == PacketAction.DROP:
                packet.dropped = True
                packet.drop_reason = decision.reason or "dropped"
                break
            if decision.action == PacketAction.BLOCK:
                packet.blocked = True
                packet.drop_reason = decision.reason or "blocked by policy"
                break

            # --- continue travelling ---
            if packet.ttl <= 0:
                packet.dropped = True
                packet.drop_reason = "TTL expired"
                result.events.append(self._note(packet, "TTL expired in transit",
                                                 Severity.LOW))
                break
            if not decision.next_hop:
                packet.dropped = True
                packet.drop_reason = "no next hop specified"
                break

            nxt = self._resolver(decision.next_hop)
            if nxt is None:
                packet.dropped = True
                packet.drop_reason = f"no route to '{decision.next_hop}'"
                result.events.append(self._note(packet, packet.drop_reason,
                                                 Severity.LOW))
                break
            device = nxt
            packet.current_device = device.hostname
        else:
            # loop exhausted without a terminal action
            if packet.is_alive:
                packet.dropped = True
                packet.drop_reason = "max hops exceeded (possible loop)"

        log.info("packet %s %s via %s", packet.id, packet.status, packet.path)
        return result

    # ----------------------------------------------------------------- #
    # Internals
    # ----------------------------------------------------------------- #
    def _latency(self, device: "AbstractDevice") -> float:
        base = getattr(device, "processing_latency_ms", None)
        if base is None:
            base = _LATENCY_BY_TYPE.get(device.device_type, 1.0)
        jitter = self._rng.uniform(0, base * 0.3)
        return round(base + jitter + self.link_latency_ms, 2)

    def _hop_event(self, packet: Packet, decision, hop) -> SimulationEvent:
        sev = Severity.HIGH if decision.action == PacketAction.BLOCK else Severity.INFO
        nxt = f" -> {decision.next_hop}" if decision.next_hop else ""
        return SimulationEvent(
            source=hop.device,
            message=f"{decision.action.value}{nxt} [{packet.protocol.value}]",
            event_type=EventType.HOP,
            severity=sev,
            metadata={
                "packet_id": packet.id,
                "ttl": packet.ttl,
                "latency_ms": hop.latency_ms,
                "reason": decision.reason,
                "dst": packet.dest_ip,
            },
        )

    def _note(self, packet: Packet, message: str, severity: Severity) -> SimulationEvent:
        return SimulationEvent(
            source=packet.current_device or "engine",
            message=message,
            event_type=EventType.PACKET,
            severity=severity,
            metadata={"packet_id": packet.id},
        )