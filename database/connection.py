"""SQLite connection wrapper and schema bootstrap for SOCVerse."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from config.settings import CONFIG
from utils.logger import get_logger

_log = get_logger("database.connection")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          TEXT PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    source      TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    severity    INTEGER NOT NULL,
    level       TEXT,
    message     TEXT NOT NULL,
    mitre_id    TEXT,
    metadata    TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id              TEXT PRIMARY KEY,
    timestamp       TEXT NOT NULL,
    title           TEXT NOT NULL,
    source          TEXT NOT NULL,
    severity        INTEGER NOT NULL,
    status          TEXT NOT NULL,
    mitre_id        TEXT,
    technique       TEXT,
    tactic          TEXT,
    summary         TEXT,
    recommendation  TEXT,
    business_impact TEXT,
    iocs            TEXT,
    containment     TEXT,
    investigation   TEXT,
    false_positives TEXT,
    metadata        TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
"""


class Database:
    """Thin wrapper around a SQLite connection with schema bootstrap."""

    def __init__(self, path: str | Path | None = None):
        self.path = str(path or CONFIG.db_path)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()
        _log.info("SQLite database ready at %s", self.path)

    def _init_schema(self) -> None:
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    @property
    def connection(self) -> sqlite3.Connection:
        return self._conn

    def execute(self, sql: str, params: Iterable[Any] = ()) -> None:
        self._conn.execute(sql, tuple(params))
        self._conn.commit()

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        return self._conn.execute(sql, tuple(params)).fetchall()

    def count(self, table: str) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS n FROM " + table).fetchone()
        return int(row["n"]) if row else 0

    def clear(self) -> None:
        self._conn.executescript("DELETE FROM events; DELETE FROM alerts;")
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    @staticmethod
    def dumps(value: Any) -> str:
        return json.dumps(value, default=str)

    @staticmethod
    def loads(value: str | None) -> Any:
        return json.loads(value) if value else None