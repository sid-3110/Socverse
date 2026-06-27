"""
core/devices/network_devices.py
Layer-2/3 infrastructure: Router (L3) and Switch (L2).
"""
from __future__ import annotations

from core.contracts import PacketDecision
from core.devices.base import AbstractDevice
from core.devices.mixins import RoutingMixin
from core.devices.registry import register_device
from core.enums import DeviceType, OSILayer, PacketAction
from core.simulation.packet import Packet


@register_device("router", "Router")
class Router(RoutingMixin, AbstractDevice):
    DEVICE_KIND = DeviceType.ROUTER
    OSI_LAYERS = (OSILayer.NETWORK,)
    PURPOSE = "Routes packets between subnets/VLANs using its routing table."
    VENDORS = ("Cisco", "Juniper", "MikroTik")

    def __init__(self, hostname: str, *, uplink: str | None = None,
                 vendor: str = "Cisco", os_name: str = "IOS-XE") -> None:
        super().__init__(hostname, self.DEVICE_KIND, vendor=vendor, os_name=os_name)
        self.uplink = uplink

    def process_packet(self, packet: Packet) -> PacketDecision:
        decision = self.route(packet)
        self.log(f"{decision.action.value} {packet.dest_ip} -> "
                 f"{decision.next_hop or '—'}")
        return decision


@register_device("switch", "Switch")
class Switch(AbstractDevice):
    DEVICE_KIND = DeviceType.SWITCH
    OSI_LAYERS = (OSILayer.DATA_LINK,)
    PURPOSE = "Forwards frames within a VLAN using its MAC/CAM table."
    VENDORS = ("Cisco", "Aruba", "Juniper")

    def __init__(self, hostname: str, *, uplink: str | None = None,
                 vendor: str = "Cisco", os_name: str = "IOS") -> None:
        super().__init__(hostname, self.DEVICE_KIND, vendor=vendor, os_name=os_name)
        self.uplink = uplink
        self.mac_table: dict[str, str] = {}   # dest IP -> local neighbor hostname

    def learn(self, ip: str, hostname: str) -> None:
        self.mac_table[ip] = hostname

    def process_packet(self, packet: Packet) -> PacketDecision:
        nh = self.mac_table.get(packet.dest_ip)
        if nh:
            return PacketDecision(PacketAction.FORWARD, f"L2 to {nh}", nh)
        if self.uplink:
            return PacketDecision(PacketAction.FORWARD,
                                  "unknown MAC -> uplink", self.uplink)
        return PacketDecision(PacketAction.DROP, "no L2 path")