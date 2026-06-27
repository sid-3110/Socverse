"""
core/attacks/simulator.py
AttackSimulator: ties a Topology + PacketEngine together and runs attacks
by key. This is the single entry point the UI will call.
"""
from __future__ import annotations

from typing import Any

from core.attacks.base import AttackContext, AttackResult
from core.attacks.factory import AttackFactory
from core.network.topology import Topology
from core.simulation.engine import PacketEngine


class AttackSimulator:
    def __init__(self, topology: Topology, *, seed: int | None = None) -> None:
        self.topology = topology
        self.engine = PacketEngine(resolver=topology.resolver(), seed=seed)

    def run(self, attack_key: str, *, source: str, target: str,
            **params: Any) -> AttackResult:
        attack = AttackFactory.create(attack_key, **params)
        ctx = AttackContext(self.topology, self.engine, source, target, params)
        return attack.run(ctx)

    @staticmethod
    def available() -> list[dict[str, Any]]:
        return AttackFactory.catalog()