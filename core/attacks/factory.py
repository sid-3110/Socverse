"""
core/attacks/factory.py
Attack factory + catalog. Importing the attack modules registers every class,
so the Attack Simulation panel is generated from code.
"""
from __future__ import annotations

from typing import Any

# Import for side effect: registers all attacks.
from core.attacks import bruteforce, recon, web  # noqa: F401
from core.attacks.base import AbstractAttack
from core.attacks.registry import ATTACK_REGISTRY, get_attack_class


class AttackFactory:
    @staticmethod
    def create(key: str, **params: Any) -> AbstractAttack:
        return get_attack_class(key)(**params)

    @staticmethod
    def keys() -> list[str]:
        return sorted(ATTACK_REGISTRY)

    @staticmethod
    def catalog() -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for key, cls in sorted(ATTACK_REGISTRY.items()):
            items.append({
                "key": key,
                "label": getattr(cls, "registry_label", cls.NAME),
                "name": cls.NAME,
                "description": cls.DESCRIPTION,
                "tactic": cls.TACTIC,
                "severity": cls.SEVERITY.label,
                "mitre": [t.id for t in cls.TECHNIQUES],
            })
        return items