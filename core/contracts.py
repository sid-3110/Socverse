"""
core/contracts.py
Capability contracts as composable mixins + the packet-processing interface.
Follows Interface Segregation: tiny, focused, opt-in.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from core.enums import PacketAction, Severity
from core.events import AlertRecord, LogRecord

if TYPE_CHECKING:                       # avoids a circular import with Module 2
    from core.simulation.packet import Packet


class LoggableMixin:
    """Gives an object an in-memory log buffer."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._logs: list[LogRecord] = []

    def log(self, message: str, level: str = "INFO", **meta: Any) -> LogRecord:
        record = LogRecord(
            source=getattr(self, "hostname", self.__class__.__name__),
            message=message,
            level=level,
            metadata=meta,
        )
        self._logs.append(record)
        return record

    @property
    def logs(self) -> list[LogRecord]:
        return list(self._logs)


class AlertableMixin:
    """Gives an object the ability to raise security alerts."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._alerts: list[AlertRecord] = []

    def raise_alert(
        self,
        message: str,
        severity: Severity = Severity.MEDIUM,
        *,
        mitre_id: str = "",
        recommendation: str = "",
        **meta: Any,
    ) -> AlertRecord:
        alert = AlertRecord(
            source=getattr(self, "hostname", self.__class__.__name__),
            message=message,
            severity=severity,
            mitre_id=mitre_id,
            recommendation=recommendation,
            metadata=meta,
        )
        self._alerts.append(alert)
        return alert

    @property
    def alerts(self) -> list[AlertRecord]:
        return list(self._alerts)


@dataclass
class PacketDecision:
    """The outcome of a device processing a packet."""
    action: PacketAction
    reason: str = ""
    next_hop: str | None = None         # hostname of the next device, if any


class IPacketProcessor(ABC):
    """Contract: every device must decide what to do with a packet."""

    @abstractmethod
    def process_packet(self, packet: "Packet") -> PacketDecision:
        """Inspect `packet` and return a routing/forwarding decision."""
        raise NotImplementedError