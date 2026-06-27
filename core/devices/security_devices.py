"""
core/devices/security_devices.py
Security infrastructure: Firewall, NGFW, WAF, Proxy, VPN gateway.
All reuse RoutingMixin (next-hop) and the shared RuleEngine/scanner.
"""
from __future__ import annotations

from core.contracts import PacketDecision
from core.devices.base import AbstractDevice
from core.devices.mixins import RoutingMixin
from core.devices.registry import register_device
from core.devices.rules import RuleEngine, scan_payload
from core.enums import DeviceType, OSILayer, PacketAction, Protocol, Severity
from core.simulation.packet import Packet


@register_device("firewall", "Firewall")
class Firewall(RoutingMixin, AbstractDevice):
    DEVICE_KIND = DeviceType.FIREWALL
    OSI_LAYERS = (OSILayer.NETWORK, OSILayer.TRANSPORT)
    PURPOSE = "Stateful L3/L4 packet filtering via an ACL rule set."
    VENDORS = ("Cisco ASA", "Fortinet", "pfSense")

    def __init__(self, hostname: str, *, uplink: str | None = None,
                 rules: RuleEngine | None = None,
                 vendor: str = "Fortinet", os_name: str = "FortiOS") -> None:
        super().__init__(hostname, self.DEVICE_KIND, vendor=vendor, os_name=os_name)
        self.uplink = uplink
        self.rules = rules or RuleEngine()

    def process_packet(self, packet: Packet) -> PacketDecision:
        verdict = self.rules.evaluate(packet)
        if not verdict.allow:
            self.log(f"DENY {packet.summary()}", "WARNING")
            return PacketDecision(PacketAction.BLOCK, verdict.reason)
        self.log(f"ALLOW {packet.summary()}")
        return self.route(packet)


@register_device("ngfw", "Next-Gen Firewall")
class NGFW(Firewall):
    DEVICE_KIND = DeviceType.NGFW
    OSI_LAYERS = (OSILayer.NETWORK, OSILayer.TRANSPORT, OSILayer.APPLICATION)
    PURPOSE = "ACL filtering plus deep packet inspection and IPS signatures."
    VENDORS = ("Palo Alto", "Fortinet", "Check Point")

    def process_packet(self, packet: Packet) -> PacketDecision:
        verdict = self.rules.evaluate(packet)
        if not verdict.allow:
            self.log(f"DENY {packet.summary()}", "WARNING")
            return PacketDecision(PacketAction.BLOCK, verdict.reason)

        for sig in scan_payload(packet.payload):
            self.raise_alert(
                f"IPS signature hit: {sig['name']}", sig["severity"],
                mitre_id=sig["mitre"],
                recommendation="Block source IP; inspect target host.",
                packet_id=packet.id,
            )
            return PacketDecision(PacketAction.BLOCK, f"signature: {sig['name']}")

        nh = self._resolve_next_hop(packet)
        if not nh:
            return PacketDecision(PacketAction.DROP, "no route")
        self.log(f"INSPECT(clean) {packet.summary()}")
        return PacketDecision(PacketAction.INSPECT, "deep inspection clean", nh)


@register_device("waf", "Web App Firewall")
class WAF(RoutingMixin, AbstractDevice):
    DEVICE_KIND = DeviceType.WAF
    OSI_LAYERS = (OSILayer.APPLICATION,)
    PURPOSE = "Inspects HTTP(S) payloads for web attacks (SQLi, XSS, etc.)."
    VENDORS = ("F5", "Cloudflare", "Imperva", "AWS WAF")

    def __init__(self, hostname: str, *, uplink: str | None = None,
                 vendor: str = "F5", os_name: str = "BIG-IP") -> None:
        super().__init__(hostname, self.DEVICE_KIND, vendor=vendor, os_name=os_name)
        self.uplink = uplink

    def process_packet(self, packet: Packet) -> PacketDecision:
        is_web = packet.protocol in (Protocol.HTTP, Protocol.HTTPS) \
            or packet.dst_port in (80, 443, 8080)
        if is_web:
            for sig in scan_payload(packet.payload):
                self.raise_alert(
                    f"WAF blocked {sig['name']}", sig["severity"],
                    mitre_id=sig["mitre"],
                    recommendation="Block client; review WAF logs.",
                    packet_id=packet.id,
                )
                return PacketDecision(PacketAction.BLOCK, f"WAF: {sig['name']}")
        nh = self._resolve_next_hop(packet)
        if not nh:
            return PacketDecision(PacketAction.DROP, "no upstream")
        return PacketDecision(PacketAction.INSPECT, "WAF clean", nh)


@register_device("proxy", "Proxy")
class Proxy(RoutingMixin, AbstractDevice):
    DEVICE_KIND = DeviceType.PROXY
    OSI_LAYERS = (OSILayer.APPLICATION,)
    PURPOSE = "Forwards/caches web traffic and masks internal client IPs (NAT)."
    VENDORS = ("Squid", "Zscaler", "BlueCoat")

    def __init__(self, hostname: str, *, uplink: str | None = None,
                 vendor: str = "Squid", os_name: str = "Linux") -> None:
        super().__init__(hostname, self.DEVICE_KIND, vendor=vendor, os_name=os_name)
        self.uplink = uplink

    def process_packet(self, packet: Packet) -> PacketDecision:
        nh = self._resolve_next_hop(packet)
        if not nh:
            return PacketDecision(PacketAction.DROP, "no upstream")
        self.log(f"proxy {packet.source_ip} -> {packet.dest_ip}")
        return PacketDecision(PacketAction.NAT, "proxied (source masked)", nh)


@register_device("vpn", "VPN Gateway")
class VpnGateway(RoutingMixin, AbstractDevice):
    DEVICE_KIND = DeviceType.VPN
    OSI_LAYERS = (OSILayer.NETWORK, OSILayer.PRESENTATION)
    PURPOSE = "Terminates encrypted tunnels for remote users into the LAN."
    VENDORS = ("Cisco AnyConnect", "OpenVPN", "WireGuard")

    def __init__(self, hostname: str, *, uplink: str | None = None,
                 vendor: str = "Cisco", os_name: str = "AnyConnect") -> None:
        super().__init__(hostname, self.DEVICE_KIND, vendor=vendor, os_name=os_name)
        self.uplink = uplink

    def process_packet(self, packet: Packet) -> PacketDecision:
        nh = self._resolve_next_hop(packet)
        if not nh:
            return PacketDecision(PacketAction.DROP, "no inside route")
        self.log(f"VPN tunnel decapsulated for {packet.source_ip}")
        return PacketDecision(PacketAction.NAT, "VPN tunnel -> LAN", nh)