"""
core/events.py
Unified simulation event model. Every observable thing (log, alert, hop)
is a SimulationEvent subtype, enabling a single timeline/event stream.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from core.enums import EventType, Severity
from utils.helpers import now_iso, short_id


@dataclass
class SimulationEvent:
    """Base class for anything that lands on the timeline."""
    source: str                       # originating device/component name
    message: str
    event_type: EventType = EventType.SYSTEM
    severity: Severity = Severity.INFO
    timestamp: str = field(default_factory=now_iso)
    id: str = field(default_factory=lambda: short_id("evt"))
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["event_type"] = self.event_type.value
        d["severity"] = self.severity.key
        return d


@dataclass
class LogRecord(SimulationEvent):
    """A device/system log line."""
    level: str = "INFO"

    def __post_init__(self) -> None:
        self.event_type = EventType.LOG


@dataclass
class AlertRecord(SimulationEvent):
    """A security alert. The SOC engine (Module 6) enriches these further."""
    mitre_id: str = ""
    recommendation: str = ""

    def __post_init__(self) -> None:
        self.event_type = EventType.ALERT