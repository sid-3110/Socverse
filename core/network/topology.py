"""
core/network/topology.py
Topology: a generic container for devices + a NetworkX graph. Provides the
device resolver the PacketEngine needs and graph data for the UI.
Knows nothing about any specific enterprise (built by EnterpriseNetworkBuilder).
"""
from __future__ import annotations

from typing import Any, Callable

import networkx as nx

from core.devices.base import AbstractDevice


class Topology:
    """Holds devices keyed by hostname and an undirected physical graph."""

    def __init__(self, name: str = "Enterprise") -> None:
        self.name = name
        self._devices: dict[str, AbstractDevice] = {}
        self.graph = nx.Graph()

    # ----------------------------------------------------------------- #
    # Construction
    # ----------------------------------------------------------------- #
    def add(self, device: AbstractDevice, *, layer: int = 0,
            vlan: str | None = None) -> AbstractDevice:
        self._devices[device.hostname] = device
        self.graph.add_node(
            device.hostname,
            type=device.device_type.value,
            layer=layer,
            vlan=vlan,
        )
        return device

    def link(self, a: str, b: str, **edge_attrs: Any) -> None:
        da, db = self._devices.get(a), self._devices.get(b)
        if da and db:
            da.connect(db)
        self.graph.add_edge(a, b, **edge_attrs)

    # ----------------------------------------------------------------- #
    # Access
    # ----------------------------------------------------------------- #
    def get(self, hostname: str) -> AbstractDevice | None:
        return self._devices.get(hostname)

    def resolver(self) -> Callable[[str], AbstractDevice | None]:
        """The callable the PacketEngine uses to map hostname -> device."""
        return self._devices.get

    @property
    def devices(self) -> dict[str, AbstractDevice]:
        return dict(self._devices)

    @property
    def hostnames(self) -> list[str]:
        return sorted(self._devices)

    def __len__(self) -> int:
        return len(self._devices)

    def __contains__(self, hostname: str) -> bool:
        return hostname in self._devices

    # ----------------------------------------------------------------- #
    # Queries / views
    # ----------------------------------------------------------------- #
    def expected_path(self, src: str, dst: str) -> list[str]:
        """Shortest *physical* path (for visualization), or [] if none."""
        try:
            return nx.shortest_path(self.graph, src, dst)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    def neighbors(self, hostname: str) -> list[str]:
        return list(self.graph.neighbors(hostname)) if hostname in self.graph else []

    def graph_data(self) -> dict[str, list[dict[str, Any]]]:
        """Nodes + edges with live device state — feeds the UI graph."""
        nodes: list[dict[str, Any]] = []
        for host, data in self.graph.nodes(data=True):
            dev = self._devices.get(host)
            nodes.append({
                "id": host,
                "label": host,
                "type": data.get("type"),
                "layer": data.get("layer", 0),
                "vlan": data.get("vlan"),
                "ip": dev.primary_ip if dev else None,
                "status": dev.status.value if dev else "unknown",
            })
        edges = [{"source": u, "target": v} for u, v in self.graph.edges()]
        return {"nodes": nodes, "edges": edges}