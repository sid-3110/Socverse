"""
core/devices/mixins.py
Reusable device behaviors. RoutingMixin centralizes L3 next-hop resolution
so no device duplicates routing logic.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from core.contracts import PacketDecision
from core.enums import PacketAction

if TYPE_CHECKING:
    from core.simulation.packet import Packet


class RoutingMixin:
    """Adds routing-table + default-uplink based next-hop resolution.

    Expects the consuming class to define `self.routing_table` (from
    AbstractDevice) and `self.uplink: str | None`.
    """
    uplink: str | None

    def _resolve_next_hop(self, packet: "Packet") -> str | None:
        route = self.routing_table.lookup(packet.dest_ip)  # type: ignore[attr-defined]
        if route and route.next_hop:
            return route.next_hop
        return self.uplink

    def route(self, packet: "Packet") -> PacketDecision:
        nh = self._resolve_next_hop(packet)
        if nh:
            return PacketDecision(PacketAction.ROUTE, "routed via table", nh)
        return PacketDecision(PacketAction.DROP, f"no route to {packet.dest_ip}")