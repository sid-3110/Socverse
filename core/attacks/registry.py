"""
core/attacks/registry.py
Decorator-based attack registry (mirrors the device registry).
Importing an attack module registers it -> Attack Simulation panel auto-populates.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.attacks.base import AbstractAttack

ATTACK_REGISTRY: dict[str, type["AbstractAttack"]] = {}


def register_attack(key: str, label: str = ""):
    def decorator(cls):
        cls.registry_key = key
        cls.registry_label = label or cls.NAME
        ATTACK_REGISTRY[key] = cls
        return cls
    return decorator


def get_attack_class(key: str) -> type["AbstractAttack"]:
    try:
        return ATTACK_REGISTRY[key]
    except KeyError as exc:
        raise KeyError(f"Unknown attack '{key}'. "
                       f"Registered: {sorted(ATTACK_REGISTRY)}") from exc