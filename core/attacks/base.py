"""
core/attacks/base.py
AbstractAttack + AttackContext + AttackResult + MITRE technique catalog.
AttackContext is the shared toolkit every attack uses to interact with the
topology (send packets, emit timeline events, raise/collect alerts).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from core.enums import EventType, Severity
from core.events import AlertRecord, SimulationEvent
from utils.helpers import now_iso

if TYPE_CHECKING:
    from core.network.topology import Topology
    from core.simulation.engine import PacketEngine, TraversalResult
    from core.simulation.packet import Packet


# --------------------------------------------------------------------------- #
# MITRE ATT&CK catalog (grows as attacks are added)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class MitreTechnique:
    id: str
    name: str
    tactic: str


TECH: dict[str, MitreTechnique] = {
    "T1046": MitreTechnique("T1046", "Network Service Discovery", "Discovery"),
    "T1595": MitreTechnique("T1595", "Active Scanning", "Reconnaissance"),
    "T1190": MitreTechnique("T1190", "Exploit Public-Facing Application",
                            "Initial Access"),
    "T1110": MitreTechnique("T1110", "Brute Force", "Credential Access"),
}


# --------------------------------------------------------------------------- #
# Execution context
# --------------------------------------------------------------------------- #
class AttackContext:
    """Toolkit handed to each attack: send packets, emit events, raise alerts.

    Automatically harvests defender-side alerts (e.g. NGFW/WAF blocks) that
    fire on devices while the attack runs, via a before/after alert-id diff.
    """

    def __init__(self, topology: "Topology", engine: "PacketEngine",
                 source_host: str, target_host: str,
                 params: dict[str, Any]) -> None:
        self.topology = topology
        self.engine = engine
        self.source_host = source_host
        self.target_host = target_host
        self.params = params

        self.events: list[SimulationEvent] = []
        self.alerts: list[AlertRecord] = []
        self.traversals: list["TraversalResult"] = []

        self._seen_alert_ids: set[str] = set()
        for dev in topology.devices.values():
            self._seen_alert_ids.update(a.id for a in dev.alerts)

    # --- resolved addresses ---
    @property
    def src_ip(self) -> str:
        dev = self.topology.get(self.source_host)
        return (dev.primary_ip if dev and dev.primary_ip
                else self.params.get("source_ip", self.source_host))

    @property
    def target_ip(self) -> str:
        dev = self.topology.get(self.target_host)
        return (dev.primary_ip if dev and dev.primary_ip
                else self.params.get("target_ip", self.target_host))

    # --- primitives ---
    def event(self, message: str, severity: Severity = Severity.INFO,
              **meta: Any) -> SimulationEvent:
        ev = SimulationEvent(self.source_host, message, EventType.ATTACK,
                             severity, metadata=meta)
        self.events.append(ev)
        return ev

    def alert(self, message: str, severity: Severity = Severity.HIGH, *,
              mitre_id: str = "", recommendation: str = "",
              **meta: Any) -> AlertRecord:
        a = AlertRecord(self.source_host, message, severity=severity,
                        mitre_id=mitre_id, recommendation=recommendation,
                        metadata=meta)
        self.alerts.append(a)
        self.events.append(a)
        return a

    def send(self, packet: "Packet", start: str | None = None) -> "TraversalResult":
        result = self.engine.send(packet, start or self.source_host)
        self.traversals.append(result)
        self.events.extend(result.events)
        self._harvest_device_alerts()
        return result

    def _harvest_device_alerts(self) -> None:
        for dev in self.topology.devices.values():
            for a in dev.alerts:
                if a.id not in self._seen_alert_ids:
                    self._seen_alert_ids.add(a.id)
                    self.alerts.append(a)
                    self.events.append(a)


# --------------------------------------------------------------------------- #
# Result
# --------------------------------------------------------------------------- #
@dataclass
class AttackResult:
    name: str
    tactic: str
    source: str
    target: str
    severity: Severity
    techniques: list[MitreTechnique] = field(default_factory=list)
    events: list[SimulationEvent] = field(default_factory=list)
    alerts: list[AlertRecord] = field(default_factory=list)
    traversals: list["TraversalResult"] = field(default_factory=list)
    started: str = field(default_factory=now_iso)
    ended: str = field(default_factory=now_iso)

    @property
    def mitre_ids(self) -> list[str]:
        return [t.id for t in self.techniques]

    @property
    def packet_count(self) -> int:
        return len(self.traversals)

    @property
    def delivered_count(self) -> int:
        return sum(1 for r in self.traversals if r.packet.delivered)

    @property
    def blocked_count(self) -> int:
        return sum(1 for r in self.traversals
                   if r.packet.blocked or r.packet.dropped)

    @property
    def success(self) -> bool:
        return self.delivered_count > 0

    def summary(self) -> str:
        return (f"{self.name} [{self.tactic}] {self.source} -> {self.target}: "
                f"{self.packet_count} packets "
                f"({self.delivered_count} reached / {self.blocked_count} stopped), "
                f"{len(self.alerts)} alerts, MITRE {self.mitre_ids}")


# --------------------------------------------------------------------------- #
# Abstract attack
# --------------------------------------------------------------------------- #
class AbstractAttack(ABC):
    """Base class for every attack. Subclasses implement execute()."""
    NAME: str = "Attack"
    DESCRIPTION: str = ""
    TACTIC: str = ""
    TECHNIQUES: tuple[MitreTechnique, ...] = ()
    SEVERITY: Severity = Severity.MEDIUM

    def __init__(self, **params: Any) -> None:
        self.params = params

    @abstractmethod
    def execute(self, ctx: AttackContext) -> None:
        """Perform the attack using the context's primitives."""

    def run(self, ctx: AttackContext) -> AttackResult:
        started = now_iso()
        ctx.event(f"{self.NAME} started against {ctx.target_host}",
                  severity=self.SEVERITY, attack=self.NAME)
        self.execute(ctx)
        ctx.event(f"{self.NAME} completed", severity=Severity.INFO,
                  attack=self.NAME)
        return AttackResult(
            name=self.NAME, tactic=self.TACTIC, source=ctx.source_host,
            target=ctx.target_host, severity=self.SEVERITY,
            techniques=list(self.TECHNIQUES), events=ctx.events,
            alerts=ctx.alerts, traversals=ctx.traversals,
            started=started, ended=now_iso(),
        )