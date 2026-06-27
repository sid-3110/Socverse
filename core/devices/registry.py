"""
core/devices/registry.py
Decorator-based device registry. Importing a device module registers it,
which auto-populates the Device Library (Open/Closed principle).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.devices.base import AbstractDevice

DEVICE_REGISTRY: dict[str, type["AbstractDevice"]] = {}


def register_device(key: str, label: str = ""):
    def decorator(cls):
        cls.registry_key = key
        cls.registry_label = label or cls.__name__
        DEVICE_REGISTRY[key] = cls
        return cls
    return decorator


def get_device_class(key: str) -> type["AbstractDevice"]:
    try:
        return DEVICE_REGISTRY[key]
    except KeyError as exc:
        raise KeyError(f"Unknown device '{key}'. "
                       f"Registered: {sorted(DEVICE_REGISTRY)}") from exc