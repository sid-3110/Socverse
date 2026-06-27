"""
core/devices/endpoints.py
Host endpoints: Server, Workstation, Cloud instance.
Endpoint base unifies deliver-vs-forward logic.
"""
from __future__ import annotations

from core.contracts import PacketDecision
from core.devices.base import AbstractDevice
from core.devices.registry import register_device
from core.enums import DeviceType, OSILayer, PacketAction
from core.simulation.packet import Packet


class Endpoint(AbstractDevice):
    """Common host behavior: deliver if addressed to me, else send to gateway."""
    OSI_LAYERS = (OSILayer.APPLICATION,)

    def __init__(self, hostname: str, device_type: DeviceType, *,
                 gateway: str | None = None, services: dict[int, str] | None = None,
                 vendor: str = "", os_name: str = "") -> None:
        super().__init__(hostname, device_type, vendor=vendor, os_name=os_name)
        self.gateway = gateway
        self.services: dict[int, str] = services or {}   # open port -> service

    def _owns(self, ip: str) -> bool:
        return any(i.ip == ip for i in self.interfaces.values())

    def process_packet(self, packet: Packet) -> PacketDecision:
        if self._owns(packet.dest_ip):
            if self.services and packet.dst_port and \
                    packet.dst_port not in self.services:
                self.log(f"connection to closed port {packet.dst_port}", "WARNING")
                return PacketDecision(PacketAction.DROP,
                                      f"port {packet.dst_port} closed")
            svc = self.services.get(packet.dst_port or -1, "host")
            return PacketDecision(PacketAction.DELIVER, f"delivered to {svc}")
        if self.gateway:
            return PacketDecision(PacketAction.FORWARD, "to default gateway",
                                  self.gateway)
        return PacketDecision(PacketAction.DROP, "no gateway")


_SERVER_SVCS = {22: "ssh", 53: "dns", 80: "http", 88: "kerberos",
                389: "ldap", 443: "https", 445: "smb", 3389: "rdp"}


@register_device("server", "Server")
class Server(Endpoint):
    DEVICE_KIND = DeviceType.SERVER
    PURPOSE = "Hosts services (AD, web, file, DB) for the enterprise."
    VENDORS = ("Microsoft", "Linux", "VMware")

    def __init__(self, hostname: str, *, gateway: str | None = None,
                 services: dict[int, str] | None = None,
                 vendor: str = "Microsoft", os_name: str = "Windows Server 2022"):
        super().__init__(hostname, self.DEVICE_KIND, gateway=gateway,
                         services=services or dict(_SERVER_SVCS),
                         vendor=vendor, os_name=os_name)


@register_device("workstation", "Workstation")
class Workstation(Endpoint):
    DEVICE_KIND = DeviceType.WORKSTATION
    PURPOSE = "End-user machine; common initial-access and phishing target."
    VENDORS = ("Microsoft", "Apple", "Linux")

    def __init__(self, hostname: str, *, gateway: str | None = None,
                 rdp_enabled: bool = False,
                 vendor: str = "Dell", os_name: str = "Windows 11"):
        services = {3389: "rdp"} if rdp_enabled else {}
        super().__init__(hostname, self.DEVICE_KIND, gateway=gateway,
                         services=services, vendor=vendor, os_name=os_name)


@register_device("cloud", "Cloud Instance")
class CloudInstance(Endpoint):
    DEVICE_KIND = DeviceType.CLOUD
    PURPOSE = "IaaS/PaaS workload reachable over the internet or VPC peering."
    VENDORS = ("AWS", "Azure", "GCP")

    def __init__(self, hostname: str, *, gateway: str | None = None,
                 services: dict[int, str] | None = None,
                 vendor: str = "AWS", os_name: str = "Amazon Linux"):
        super().__init__(hostname, self.DEVICE_KIND, gateway=gateway,
                         services=services or {22: "ssh", 80: "http", 443: "https"},
                         vendor=vendor, os_name=os_name)