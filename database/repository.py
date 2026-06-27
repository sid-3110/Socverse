"""Persistence repository: maps SOCVerse events and alerts to SQLite rows."""
from __future__ import annotations

from typing import Any

from database.connection import Database
from utils.logger import get_logger

_log = get_logger("database.repository")


class SocRepository:
    """Stores and retrieves events and enriched alerts."""

    def __init__(self, database: Database | None = None):
        self.db = database or Database()

    # ---- events ----
    def save_event(self, event: dict[str, Any]) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO events "
            "(id, timestamp, source, event_type, severity, level, message, mitre_id, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event["id"],
                event["timestamp"],
                event["source"],
                event["event_type"],
                int(event["severity"]),
                event.get("level"),
                event["message"],
                event.get("mitre_id"),
                self.db.dumps(event.get("metadata") or {}),
            ),
        )

    def load_events(self, limit: int = 500) -> list[dict[str, Any]]:
        rows = self.db.query("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,))
        out = []
        for r in rows:
            d = dict(r)
            d["metadata"] = self.db.loads(d.get("metadata")) or {}
            out.append(d)
        return out

    # ---- alerts ----
    def save_alert(self, alert: dict[str, Any]) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO alerts "
            "(id, timestamp, title, source, severity, status, mitre_id, technique, tactic, "
            "summary, recommendation, business_impact, iocs, containment, investigation, "
            "false_positives, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                alert["id"],
                alert["timestamp"],
                alert["title"],
                alert["source"],
                int(alert["severity"]),
                alert["status"],
                alert.get("mitre_id"),
                alert.get("technique"),
                alert.get("tactic"),
                alert.get("summary"),
                alert.get("recommendation"),
                alert.get("business_impact"),
                self.db.dumps(alert.get("iocs") or []),
                self.db.dumps(alert.get("containment") or []),
                self.db.dumps(alert.get("investigation") or []),
                self.db.dumps(alert.get("false_positives") or []),
                self.db.dumps(alert.get("metadata") or {}),
            ),
        )

    def load_alerts(self, limit: int = 200) -> list[dict[str, Any]]:
        rows = self.db.query(
            "SELECT * FROM alerts ORDER BY severity DESC, timestamp DESC LIMIT ?", (limit,)
        )
        out = []
        for r in rows:
            d = dict(r)
            for key in ("iocs", "containment", "investigation", "false_positives", "metadata"):
                d[key] = self.db.loads(d.get(key))
            out.append(d)
        return out

    def counts(self) -> dict[str, int]:
        return {"events": self.db.count("events"), "alerts": self.db.count("alerts")}