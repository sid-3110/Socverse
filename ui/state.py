"""Application state: the single seam between the framework-free core and Streamlit.

Built once per session and cached in st.session_state so the topology and
engines persist across reruns. All core objects live here; the rest of the UI
layer only reads from and acts through this object.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import streamlit as st

from core.network.enterprise import EnterpriseNetworkBuilder
from core.network.topology import Topology
from core.attacks.simulator import AttackSimulator
from core.soc.engine import SocEngine
from utils.logger import get_logger

_log = get_logger("ui.state")

_STATE_KEY = "socverse_state"


@dataclass
class AppState:
    """Holds the live simulation: topology + attack simulator + SOC engine."""
    topology: Topology
    simulator: AttackSimulator
    soc: SocEngine
    selected_device: str | None = None
    last_result: object | None = None
    history: list = field(default_factory=list)

    @property
    def hostnames(self) -> list[str]:
        return sorted(self.topology.hostnames)

    @property
    def attack_catalog(self) -> list[dict]:
        return AttackSimulator.available()

    def run_attack(self, attack_key: str, source: str, target: str, **params):
        """Execute an attack and feed the result into the SOC. Returns the AttackResult."""
        result = self.simulator.run(attack_key, source=source, target=target, **params)
        produced = self.soc.ingest_attack(result)
        self.last_result = result
        self.history.append(result)
        _log.info("UI ran %s (%s -> %s): %d alert(s)", attack_key, source, target, len(produced))
        return result

    def select_device(self, hostname: str | None) -> None:
        self.selected_device = hostname

    def reset_soc(self) -> None:
        self.soc = SocEngine()
        self.history.clear()
        self.last_result = None


def _build_state() -> AppState:
    topology = EnterpriseNetworkBuilder().build()
    simulator = AttackSimulator(topology, seed=None)
    soc = SocEngine()
    _log.info("Built enterprise topology with %d devices", len(topology))
    return AppState(topology=topology, simulator=simulator, soc=soc)


def get_state() -> AppState:
    """Return the cached AppState, building it on first access this session."""
    if _STATE_KEY not in st.session_state:
        st.session_state[_STATE_KEY] = _build_state()
        _log.info("Initialized SOCVerse application state")
    return st.session_state[_STATE_KEY]