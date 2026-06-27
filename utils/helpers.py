"""
utils/helpers.py
Small, pure utility functions shared across layers.
"""
from __future__ import annotations

import random
import uuid
from datetime import datetime, timezone


def now_utc() -> datetime:
    """Timezone-aware current time (UTC)."""
    return datetime.now(timezone.utc)


def now_iso() -> str:
    """ISO-8601 timestamp string."""
    return now_utc().isoformat(timespec="seconds")


def short_id(prefix: str = "") -> str:
    """Compact unique id, optionally prefixed (e.g. 'pkt-3f9a1c')."""
    token = uuid.uuid4().hex[:6]
    return f"{prefix}-{token}" if prefix else token


def random_mac(oui: str = "00:1A:2B") -> str:
    """Generate a MAC address with a fixed vendor OUI prefix."""
    tail = ":".join(f"{random.randint(0, 255):02X}" for _ in range(3))
    return f"{oui}:{tail}"


def clamp(value: int, low: int, high: int) -> int:
    """Constrain an integer to [low, high]."""
    return max(low, min(value, high))