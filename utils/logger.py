"""
utils/logger.py
Console + rotating-file logger. Use get_logger(__name__) in any module.
"""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from config.settings import DATABASE_DIR

_LOG_FILE = DATABASE_DIR / "socverse.log"
_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_configured = False


def _configure_root() -> None:
    global _configured
    if _configured:
        return
    root = logging.getLogger("socverse")
    root.setLevel(logging.DEBUG)

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter(_FORMAT))

    file_handler = RotatingFileHandler(
        _LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(_FORMAT))

    root.addHandler(console)
    root.addHandler(file_handler)
    root.propagate = False
    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced child logger under the 'socverse' root."""
    _configure_root()
    return logging.getLogger(f"socverse.{name}")
