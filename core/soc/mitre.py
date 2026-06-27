"""MITRE ATT&CK rollups across enriched alerts."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass


@dataclass
class TechniqueStat:
    technique_id: str
    name: str
    tactic: str
    count: int


class MitreRollup:
    """Aggregates technique and tactic coverage from SocAlerts."""

    def __init__(self, alerts):
        self._alerts = list(alerts)

    def techniques(self) -> list[TechniqueStat]:
        counts: Counter = Counter()
        meta: dict[str, tuple[str, str]] = {}
        for a in self._alerts:
            tid = a.mitre_id or "UNKNOWN"
            counts[tid] += 1
            meta[tid] = (a.technique, a.tactic)
        return [
            TechniqueStat(tid, meta[tid][0], meta[tid][1], n)
            for tid, n in counts.most_common()
        ]

    def tactics(self) -> dict[str, int]:
        counts: Counter = Counter()
        for a in self._alerts:
            counts[a.tactic] += 1
        return dict(counts.most_common())

    def top(self, n: int = 5) -> list[TechniqueStat]:
        return self.techniques()[:n]