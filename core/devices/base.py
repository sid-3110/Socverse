"""
core/devices/base.py
AbstractDevice: the common ancestor for every node in the network.
Composes logging, alerting, and packet-processing contracts.
"""
from __future__ import annotations

from abc import abstractmethod
from typing import TYPE_CHECKING, Any

from core.contracts import AlertableMixin, IPacketProcessor, LoggableMixin, PacketDecision
from core.devices.interface import NetworkInterface, RoutingTable
from core.enums import DeviceStatus, DeviceType, OSILayer
from utils.helpers import random_mac

if TYPE_CHECKING:
    from core.simulation.packet import Packet


class AbstractDevice(LoggableMixin, AlertableMixin, IPacketProcessor):
    """
    Base class for all devices.

    Subclasses (Module 3) MUST implement `process_packet` and SHOULD override
    the learning-page class attributes below for the device info pages.
    """

    # --- Learning-page metadata (overridden per device type) ---
    OSI_LAYERS: tuple[OSILayer, ...] = ()
    PURPOSE: str = ""
    VENDORS: tuple[str, ...] = ()

    def __init__(
        self,
        hostname: str,
        device_type: DeviceType,
        *,
        vendor: str = "",
        os_name: str = "",
        cpu: float = 5.0,
        ram: float = 20.0,
    ) -> None:
        # Identity
        self.hostname = hostname
        self.device_type = device_type
        self.vendor = vendor
        self.os_name = os_name
        self.status = DeviceStatus.ONLINE

        # Resources (percent utilization, 0–100)
        self.cpu = cpu
        self.ram = ram

        # Networking
        self.interfaces: dict[str, NetworkInterface] = {}
        self.routing_table = RoutingTable()
        self.connections: set[str] = set()   # neighbor hostnames

        super().__init__()                    # initializes mixin buffers

    # ----------------------------------------------------------------- #
    # Interface management
    # ----------------------------------------------------------------- #
    def add_interface(
        self, name: str, ip: str | None = None,
        subnet: str | None = None, mac: str | None = None, up: bool = True,
    ) -> NetworkInterface:
        iface = NetworkInterface(
            name=name, ip=ip, subnet=subnet,
            mac=mac or random_mac(), is_up=up,
        )
        self.interfaces[name] = iface
        return iface

    def get_interface(self, name: str) -> NetworkInterface | None:
        return self.interfaces.get(name)

    @property
    def primary_ip(self) -> str | None:
        for iface in self.interfaces.values():
            if iface.ip:
                return iface.ip
        return None

    # ----------------------------------------------------------------- #
    # Topology
    # ----------------------------------------------------------------- #
    def connect(self, other: "AbstractDevice", *, local_if: str | None = None,
                remote_if: str | None = None) -> None:
        """Record a bidirectional physical link with a neighbor."""
        self.connections.add(other.hostname)
        other.connections.add(self.hostname)
        if local_if and (iface := self.interfaces.get(local_if)):
            iface.connected_to = other.hostname
        if remote_if and (iface := other.interfaces.get(remote_if)):
            iface.connected_to = self.hostname

    # ----------------------------------------------------------------- #
    # State
    # ----------------------------------------------------------------- #
    def set_status(self, status: DeviceStatus, reason: str = "") -> None:
        previous, self.status = self.status, status
        self.log(f"status {previous.value} -> {status.value} {reason}".strip())

    @property
    def is_compromised(self) -> bool:
        return self.status in (DeviceStatus.COMPROMISED, DeviceStatus.QUARANTINED)

    # ----------------------------------------------------------------- #
    # Contract — must be implemented by concrete devices (Module 3)
    # ----------------------------------------------------------------- #
    @abstractmethod
    def process_packet(self, packet: "Packet") -> PacketDecision:
        ...

    # ----------------------------------------------------------------- #
    # Introspection
    # ----------------------------------------------------------------- #
    def info(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "type": self.device_type.value,
            "vendor": self.vendor,
            "os": self.os_name,
            "status": self.status.value,
            "ip": self.primary_ip,
            "cpu": self.cpu,
            "ram": self.ram,
            "interfaces": [str(i) for i in self.interfaces.values()],
            "connections": sorted(self.connections),
        }

    def __repr__(self) -> str:
        return (f"<{self.__class__.__name__} {self.hostname} "
                f"{self.device_type.value} {self.status.value}>")