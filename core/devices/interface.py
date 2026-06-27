"""
core/devices/interface.py
Network interface and routing table primitives used by every device.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from utils.helpers import random_mac


@dataclass
class NetworkInterface:
    """A single L2/L3 interface on a device."""
    name: str                              # e.g. "eth0", "Gi0/1"
    ip: str | None = None
    mac: str = field(default_factory=random_mac)
    subnet: str | None = None              # CIDR, e.g. "10.10.130.0/24"
    is_up: bool = True
    connected_to: str | None = None        # remote device hostname

    def __str__(self) -> str:
        state = "up" if self.is_up else "down"
        return f"{self.name} {self.ip or '—'} [{self.mac}] ({state})"


@dataclass
class Route:
    """A single routing-table entry."""
    destination: str                       # CIDR; "0.0.0.0/0" = default route
    next_hop: str | None                   # next device hostname (None = local)
    interface: str
    metric: int = 10

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(self.destination, strict=False)


class RoutingTable:
    """Longest-prefix-match routing table."""

    def __init__(self) -> None:
        self._routes: list[Route] = []

    def add_route(
        self, destination: str, interface: str,
        next_hop: str | None = None, metric: int = 10,
    ) -> Route:
        route = Route(destination, next_hop, interface, metric)
        self._routes.append(route)
        return route

    def lookup(self, dest_ip: str) -> Route | None:
        """Return the most specific matching route, or None."""
        addr = ipaddress.ip_address(dest_ip)
        best: Route | None = None
        for route in self._routes:
            if addr in route.network:
                if best is None or route.network.prefixlen > best.network.prefixlen:
                    best = route
        return best

    @property
    def routes(self) -> list[Route]:
        return list(self._routes)