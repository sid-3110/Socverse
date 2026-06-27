"""
core/devices/factory.py
Device factory + catalog. Importing the device modules here registers every
class, so the Device Library is generated from code with no hard-coded lists.
"""
from __future__ import annotations

from typing import Any

# Import for side effect: registers all device classes.
from core.devices import endpoints, network_devices, security_devices  # noqa: F401
from core.devices.base import AbstractDevice
from core.devices.registry import DEVICE_REGISTRY, get_device_class


class DeviceFactory:
    """Creates devices by registry key and exposes the Device Library catalog."""

    @staticmethod
    def create(key: str, hostname: str, **kwargs: Any) -> AbstractDevice:
        cls = get_device_class(key)
        return cls(hostname, **kwargs)

    @staticmethod
    def keys() -> list[str]:
        return sorted(DEVICE_REGISTRY)

    @staticmethod
    def catalog() -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for key, cls in sorted(DEVICE_REGISTRY.items()):
            items.append({
                "key": key,
                "label": getattr(cls, "registry_label", cls.__name__),
                "type": cls.DEVICE_KIND.value,
                "purpose": cls.PURPOSE,
                "osi_layers": [layer.label for layer in cls.OSI_LAYERS],
                "vendors": list(cls.VENDORS),
            })
        return items