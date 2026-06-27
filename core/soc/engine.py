"""SOC engine: ingests the event stream, enriches alerts, exposes SIEM + metrics."""
from __future__ import annotations

from collections import Counter

from core.alerts.enrichment import AlertEnricher, SocAlert
from core.events import AlertRecord, SimulationEvent
from core.logs.store import LogStore
from core.soc.mitre import MitreRollup
from core.soc.siem import SiemEngine
from utils.logger import get_logger

_log = get_logger("soc.engine")


class SocEngine:
    """Central SOC brain wiring the log store, enrichment, SIEM, and MITRE rollups."""

    def __init__(self, repository=None, capacity: int = 5000):
        self.store = LogStore(repository=repository, capacity=capacity)
        self.enricher = AlertEnricher()
        self.siem = SiemEngine(self.store)
        self._repository = repository
        self._alerts: list[SocAlert] = []

    # ---- ingestion ----
    def ingest_event(self, event: SimulationEvent) -> None:
        self.store.ingest(event)

    def ingest_alert(self, alert: AlertRecord) -> SocAlert:
        self.store.ingest(alert)
        soc_alert = self.enricher.enrich(alert)
        self._alerts.append(soc_alert)
        if self._repository is not None:
            try:
                self._repository.save_alert(soc_alert.to_dict())
            except Exception as exc:
                _log.warning("Failed to persist alert %s: %s", soc_alert.id, exc)
        return soc_alert

    def ingest_attack(self, result) -> list[SocAlert]:
        """Feed a full AttackResult (events + alerts) into the SOC."""
        for event in result.events:
            if isinstance(event, AlertRecord):
                continue  # alerts are ingested separately below
            self.store.ingest(event)
        produced = [self.ingest_alert(a) for a in result.alerts]
        _log.info(
            "Ingested attack '%s': %d events, %d alerts",
            result.name, len(result.events), len(result.alerts),
        )
        return produced

    # ---- access ----
    def alerts(self, status: str | None = None) -> list[SocAlert]:
        if status is None:
            return list(self._alerts)
        return [a for a in self._alerts if a.status == status]

    def mitre(self) -> MitreRollup:
        return MitreRollup(self._alerts)

    def stats(self) -> dict:
        by_sev: Counter = Counter()
        for a in self._alerts:
            by_sev[a.severity_key] += 1
        return {
            "total_events": len(self.store),
            "total_alerts": len(self._alerts),
            "open_alerts": len(self.alerts("open")),
            "by_severity": dict(by_sev),
            "top_techniques": [
                {"id": t.technique_id, "name": t.name, "count": t.count}
                for t in self.mitre().top(5)
            ],
            "tactics": self.mitre().tactics(),
        }