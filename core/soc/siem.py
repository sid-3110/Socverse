"""Lightweight SIEM query layer over the LogStore event stream."""
from __future__ import annotations

from dataclasses import dataclass

from core.enums import Severity
from core.events import SimulationEvent


@dataclass
class SiemQuery:
    """Declarative filter over the event stream (all conditions are ANDed)."""
    min_severity: Severity | None = None
    event_types: tuple[str, ...] = ()
    source_contains: str | None = None
    text_contains: str | None = None
    mitre_id: str | None = None

    def matches(self, event: SimulationEvent) -> bool:
        if self.min_severity is not None and int(event.severity) < int(self.min_severity):
            return False
        if self.event_types:
            etype = getattr(event.event_type, "name", str(event.event_type))
            if etype not in self.event_types:
                return False
        if self.source_contains and self.source_contains.lower() not in event.source.lower():
            return False
        if self.text_contains and self.text_contains.lower() not in event.message.lower():
            return False
        if self.mitre_id and getattr(event, "mitre_id", None) != self.mitre_id:
            return False
        return True


class SiemEngine:
    """Runs SiemQuery objects against a LogStore."""

    def __init__(self, store):
        self._store = store

    def search(self, query: SiemQuery, limit: int = 200) -> list[SimulationEvent]:
        hits = [e for e in self._store.events if query.matches(e)]
        return hits[-limit:]

    def errors(self, limit: int = 100) -> list[SimulationEvent]:
        return self.search(SiemQuery(min_severity=Severity.HIGH), limit)

    def by_technique(self, mitre_id: str, limit: int = 100) -> list[SimulationEvent]:
        return self.search(SiemQuery(mitre_id=mitre_id), limit)

    def by_source(self, source: str, limit: int = 100) -> list[SimulationEvent]:
        return self.search(SiemQuery(source_contains=source), limit)