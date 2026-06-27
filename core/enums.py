"""
core/enums.py
Controlled vocabularies for the whole simulation. No external dependencies.
"""
from __future__ import annotations

from enum import Enum, IntEnum


class OSILayer(IntEnum):
    """The 7 OSI layers. IntEnum so they compare/sort naturally."""
    PHYSICAL = 1
    DATA_LINK = 2
    NETWORK = 3
    TRANSPORT = 4
    SESSION = 5
    PRESENTATION = 6
    APPLICATION = 7

    @property
    def label(self) -> str:
        return f"L{self.value} {self.name.replace('_', ' ').title()}"


class Protocol(str, Enum):
    """Network protocols, with an approximate OSI layer mapping."""
    ARP = "ARP"
    ICMP = "ICMP"
    TCP = "TCP"
    UDP = "UDP"
    TLS = "TLS"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    DHCP = "DHCP"
    SSH = "SSH"
    RDP = "RDP"
    SMB = "SMB"
    LDAP = "LDAP"
    KERBEROS = "KERBEROS"

    @property
    def osi_layer(self) -> OSILayer:
        return _PROTO_LAYER.get(self, OSILayer.APPLICATION)


_PROTO_LAYER: dict[Protocol, OSILayer] = {
    Protocol.ARP: OSILayer.DATA_LINK,
    Protocol.ICMP: OSILayer.NETWORK,
    Protocol.TCP: OSILayer.TRANSPORT,
    Protocol.UDP: OSILayer.TRANSPORT,
    Protocol.TLS: OSILayer.PRESENTATION,
}


class DeviceType(str, Enum):
    """Kinds of nodes in the enterprise topology."""
    INTERNET = "Internet"
    ISP = "ISP"
    ROUTER = "Router"
    SWITCH = "Switch"
    FIREWALL = "Firewall"
    NGFW = "NGFW"
    WAF = "WAF"
    PROXY = "Proxy"
    VPN = "VPN Gateway"
    SERVER = "Server"
    WORKSTATION = "Workstation"
    CLOUD = "Cloud"


class DeviceStatus(str, Enum):
    """Operational state of a device."""
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    COMPROMISED = "compromised"
    QUARANTINED = "quarantined"


class Severity(IntEnum):
    """Alert/log severity. Ordered so HIGH > MEDIUM, etc."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.title()

    @property
    def key(self) -> str:
        """Lowercase key — matches theme.SEVERITY_COLORS."""
        return self.name.lower()


class PacketAction(str, Enum):
    """What a device decides to do with a packet it receives."""
    FORWARD = "forward"     # L2 switch forwarding
    ROUTE = "route"         # L3 routing to next hop
    DELIVER = "deliver"     # packet reached its destination host
    DROP = "drop"           # silently discarded (e.g. TTL=0)
    BLOCK = "block"         # explicitly denied by a security policy
    INSPECT = "inspect"     # deep inspection (NGFW/WAF/IDS)
    NAT = "nat"             # address translation applied


class EventType(str, Enum):
    """Discriminator for the unified simulation event stream."""
    SYSTEM = "system"
    LOG = "log"
    ALERT = "alert"
    PACKET = "packet"
    HOP = "hop"
    ATTACK = "attack"