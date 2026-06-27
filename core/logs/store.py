"""In-memory log store with optional SQLite persistence."""
from __future__ import annotations

from collections import deque
from datetime import datetime
from typing import Iterable

from core.events import SimulationEvent
from utils.logger import get_logger

_log = get_logger("logs.store")


def _iso(ts) -> str:
    if isinstance(ts, datetime):
        return ts.isoformat()
    return str(ts)


def _enum_name(value) -> str:
    return getattr(value, "name", str(value))


def event_to_row(event: SimulationEvent) -> dict:
    """Serialize any event into a flat, JSON-safe dict for persistence."""
    return {
        "id": event.id,
        "timestamp": _iso(event.timestamp),
        "source": event.source,
        "event_type": _enum_name(event.event_type),
        "severity": int(event.severity),
        "level": getattr(event, "level", None),
        "message": event.message,
        "mitre_id": getattr(event, "mitre_id", None),
        "metadata": getattr(event, "metadata", {}) or {},
    }


class LogStore:
    """Append-only ring buffer over the unified event stream.

    Keeps the most recent `capacity` events in memory for fast SIEM/UI
    access and optionally mirrors every event into a repository.
    """

    def __init__(self, repository=None, capacity: int = 5000):
        self._events: deque[SimulationEvent] = deque(maxlen=capacity)
        self._repository = repository

    def ingest(self, event: SimulationEvent) -> SimulationEvent:
        self._events.append(event)
        if self._repository is not None:
            try:
                self._repository.save_event(event_to_row(event))
            except Exception as exc:  # persistence must never break simulation
                _log.warning("Failed to persist event %s: %s", event.id, exc)
        return event

    def ingest_many(self, events: Iterable[SimulationEvent]) -> None:
        for ev in events:
            self.ingest(ev)

    @property
    def events(self) -> list[SimulationEvent]:
        return list(self._events)

    def tail(self, n: int = 50) -> list[SimulationEvent]:
        return list(self._events)[-n:]

    def clear(self) -> None:
        self._events.clear()

    def __len__(self) -> int:
        return len(self._events)