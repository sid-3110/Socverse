"""Alert enrichment: turn a raw AlertRecord into an investigation-ready SOC alert."""
from __future__ import annotations

from dataclasses import dataclass, field

from core.alerts.playbooks import Playbook, get_playbook
from core.enums import Severity
from core.events import AlertRecord
from utils.helpers import now_iso, short_id


@dataclass
class IOC:
    """Indicator of compromise extracted from an alert."""
    type: str
    value: str
    context: str = ""

    def to_dict(self) -> dict:
        return {"type": self.type, "value": self.value, "context": self.context}


@dataclass
class SocAlert:
    """A fully enriched alert ready for analyst triage."""
    id: str
    timestamp: str
    title: str
    source: str
    severity: Severity
    mitre_id: str | None
    technique: str
    tactic: str
    summary: str
    recommendation: str
    business_impact: str
    iocs: list[IOC] = field(default_factory=list)
    containment: list[str] = field(default_factory=list)
    investigation: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    status: str = "open"
    raw_event_id: str | None = None
    metadata: dict = field(default_factory=dict)

    @property
    def severity_key(self) -> str:
        return getattr(self.severity, "key", str(int(self.severity)))

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "title": self.title,
            "source": self.source,
            "severity": int(self.severity),
            "status": self.status,
            "mitre_id": self.mitre_id,
            "technique": self.technique,
            "tactic": self.tactic,
            "summary": self.summary,
            "recommendation": self.recommendation,
            "business_impact": self.business_impact,
            "iocs": [i.to_dict() for i in self.iocs],
            "containment": list(self.containment),
            "investigation": list(self.investigation),
            "false_positives": list(self.false_positives),
            "metadata": dict(self.metadata),
        }


class AlertEnricher:
    """Maps raw AlertRecords to SocAlerts using the playbook knowledge base."""

    def enrich(self, alert: AlertRecord) -> SocAlert:
        pb: Playbook = get_playbook(getattr(alert, "mitre_id", None))
        severity = self._max_severity(
            getattr(alert, "severity", Severity.INFO), pb.default_severity
        )
        return SocAlert(
            id=short_id("soc"),
            timestamp=self._ts(alert),
            title=f"[{pb.name}] {alert.message}",
            source=alert.source,
            severity=severity,
            mitre_id=getattr(alert, "mitre_id", None) or pb.technique,
            technique=pb.name,
            tactic=pb.tactic,
            summary=alert.message,
            recommendation=getattr(alert, "recommendation", "") or "Triage per playbook.",
            business_impact=pb.business_impact,
            iocs=self._extract_iocs(alert),
            containment=list(pb.containment),
            investigation=list(pb.investigation),
            false_positives=list(pb.false_positives),
            raw_event_id=getattr(alert, "id", None),
            metadata=dict(getattr(alert, "metadata", {}) or {}),
        )

    @staticmethod
    def _max_severity(a: Severity, b: Severity) -> Severity:
        return a if int(a) >= int(b) else b

    @staticmethod
    def _ts(alert) -> str:
        ts = getattr(alert, "timestamp", None)
        if ts is None:
            return now_iso()
        return ts.isoformat() if hasattr(ts, "isoformat") else str(ts)

    @staticmethod
    def _extract_iocs(alert: AlertRecord) -> list[IOC]:
        iocs: list[IOC] = []
        meta = getattr(alert, "metadata", {}) or {}
        if alert.source:
            iocs.append(IOC("host", alert.source, "Device that raised the alert"))
        for key in ("src_ip", "source_ip", "attacker_ip"):
            if meta.get(key):
                iocs.append(IOC("ip", str(meta[key]), "Source address"))
        if meta.get("open_ports"):
            iocs.append(IOC("ports", str(meta["open_ports"]), "Discovered open ports"))
        if meta.get("port"):
            iocs.append(IOC("port", str(meta["port"]), "Targeted service port"))
        if meta.get("payload"):
            iocs.append(IOC("payload", str(meta["payload"])[:120], "Malicious payload"))
        return iocs