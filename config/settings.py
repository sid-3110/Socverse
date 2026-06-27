"""
config/settings.py
Global application settings. Framework-agnostic, import-safe everywhere.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
BASE_DIR: Path = Path(__file__).resolve().parent.parent
DATABASE_DIR: Path = BASE_DIR / "database"
ASSETS_DIR: Path = BASE_DIR / "assets"
DB_PATH: Path = DATABASE_DIR / "socverse.db"

# Ensure runtime directories exist on import.
DATABASE_DIR.mkdir(parents=True, exist_ok=True)
ASSETS_DIR.mkdir(parents=True, exist_ok=True)


@dataclass(frozen=True)
class AppConfig:
    """Immutable application metadata and feature flags."""

    name: str = "SOCVerse"
    tagline: str = "Interactive Enterprise Network & SOC Attack Simulation Platform"
    version: str = "0.1.0"
    icon: str = "🛡️"
    layout: str = "wide"

    # Simulation defaults
    default_ttl: int = 64
    packet_animation_ms: int = 600
    max_timeline_events: int = 5000

    # Persistence
    db_path: Path = DB_PATH

    # UI panels (left sidebar order) — drives navigation rendering later.
    left_panels: tuple[str, ...] = field(
        default=(
            "Attack Simulation",
            "Network Controls",
            "Device Library",
            "Timeline",
            "Packet Inspector",
            "MITRE ATT&CK",
            "Logs",
            "Settings",
        )
    )


# Singleton-style accessor — import this everywhere.
CONFIG = AppConfig()