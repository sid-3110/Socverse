"""
core/network/enterprise.py
Builds the full SOCVerse enterprise topology:
Internet -> ISP -> Edge -> Perimeter NGFW -> {DMZ, Core NGFW} -> VLANs/Servers,
plus Cloud, VPN, Proxy and external attacker/remote-user nodes.
Subnets come from config.ip_plan (single source of truth).
"""
from __future__ import annotations

from config.ip_plan import VLANS
from core.devices.factory import DeviceFactory
from core.devices.rules import FirewallRule, RuleAction, RuleEngine
from core.network.topology import Topology

# Well-known IPs other modules (attacks/tests) reference.
EXTERNAL_DNS = "8.8.8.8"
ATTACKER_IP = "203.0.113.9"
REMOTE_USER_IP = "203.0.113.50"

# Endpoint inventory: (hostname, ip, vlan_key, access_switch, kind)
_ENDPOINTS = [
    ("WS-HR-01",   "10.10.110.50", "hr",      "ACCESS-HR",    "workstation"),
    ("WS-HR-02",   "10.10.110.51", "hr",      "ACCESS-HR",    "workstation"),
    ("WS-FIN-01",  "10.10.120.50", "finance", "ACCESS-FIN",   "workstation"),
    ("WS-IT-01",   "10.10.130.50", "it",      "ACCESS-IT",    "workstation"),
    ("WS-SOC-01",  "10.10.140.50", "soc",     "ACCESS-SOC",   "workstation"),
    ("SIEM-01",    "10.10.140.10", "soc",     "ACCESS-SOC",   "server"),
    ("GUEST-01",   "192.168.99.50","guest",   "ACCESS-GUEST", "workstation"),
    ("AD-DC-01",   "10.20.200.10", "servers", "ACCESS-SRV",   "server"),
    ("FILE-01",    "10.20.200.20", "servers", "ACCESS-SRV",   "server"),
    ("APP-01",     "10.20.200.30", "servers", "ACCESS-SRV",   "server"),
]
# Access switch -> VLAN key (drives SVI gateways + core routing)
_ACCESS_SWITCHES = {
    "ACCESS-HR": "hr", "ACCESS-FIN": "finance", "ACCESS-IT": "it",
    "ACCESS-SOC": "soc", "ACCESS-GUEST": "guest", "ACCESS-SRV": "servers",
}
_DMZ_SERVERS = [
    ("WEB-01",  "172.16.20.10", {80: "http", 443: "https"}),
    ("DNS-01",  "172.16.20.20", {53: "dns"}),
    ("MAIL-01", "172.16.20.30", {25: "smtp", 143: "imap"}),
]


class EnterpriseNetworkBuilder:
    """Constructs and fully wires the SOCVerse enterprise topology."""

    def build(self) -> Topology:
        t = Topology("SOCVerse Enterprise")
        F = DeviceFactory.create

        # ---------------- Internet & external hosts ----------------
        inet = F("router", "INTERNET"); inet.add_interface("eth0", ip="203.0.113.1")
        t.add(inet, layer=0)
        ext = F("server", "EXT-SVC", gateway="INTERNET",
                services={53: "dns", 80: "http", 443: "https"})
        ext.add_interface("eth0", ip=EXTERNAL_DNS); t.add(ext, layer=0)
        atk = F("workstation", "ATTACKER", gateway="INTERNET")
        atk.add_interface("eth0", ip=ATTACKER_IP); t.add(atk, layer=0)
        rem = F("workstation", "REMOTE-USER", gateway="INTERNET")
        rem.add_interface("eth0", ip=REMOTE_USER_IP); t.add(rem, layer=0)

        # ---------------- ISP / edge ----------------
        isp = F("router", "ISP-EDGE", uplink="INTERNET")
        isp.add_interface("eth0", ip="203.0.113.2"); t.add(isp, layer=1)
        edge = F("router", "EDGE-RTR", uplink="ISP-EDGE")
        edge.add_interface("eth0", ip="198.51.100.10"); t.add(edge, layer=2)

        # ---------------- Perimeter ----------------
        perim_rules = RuleEngine().add(FirewallRule(
            RuleAction.DENY, dst="10.0.0.0/8", port=3389,
            description="No inbound RDP to internal"))
        perim = F("ngfw", "PERIM-NGFW", uplink="EDGE-RTR", rules=perim_rules)
        perim.add_interface("eth0", ip="198.51.100.11"); t.add(perim, layer=3)
        proxy = F("proxy", "PROXY", uplink="PERIM-NGFW")
        proxy.add_interface("eth0", ip="10.0.0.3"); t.add(proxy, layer=3)
        vpn = F("vpn", "VPN-GW", uplink="CORE-NGFW")
        vpn.add_interface("eth0", ip="198.51.100.20"); t.add(vpn, layer=3)

        # ---------------- DMZ ----------------
        waf = F("waf", "DMZ-WAF", uplink="DMZ-SW")
        waf.add_interface("eth0", ip="172.16.20.2"); t.add(waf, layer=3, vlan="dmz")
        dmz_sw = F("switch", "DMZ-SW", uplink="PERIM-NGFW")
        dmz_sw.add_interface("eth0", ip="172.16.20.3"); t.add(dmz_sw, layer=4, vlan="dmz")
        for name, ip, svc in _DMZ_SERVERS:
            s = F("server", name, gateway="DMZ-SW", services=svc)
            s.add_interface("eth0", ip=ip, subnet=VLANS["dmz"].cidr)
            t.add(s, layer=5, vlan="dmz"); t.link("DMZ-SW", name); dmz_sw.learn(ip, name)

        # ---------------- Core (inter-VLAN L3 + east-west policy) ----------------
        core_rules = RuleEngine().add(FirewallRule(
            RuleAction.DENY, src=VLANS["guest"].cidr, dst=VLANS["servers"].cidr,
            description="Guest VLAN cannot reach servers"))
        core = F("ngfw", "CORE-NGFW", uplink="PERIM-NGFW", rules=core_rules)
        core.add_interface("eth0", ip="10.0.0.1"); t.add(core, layer=4)
        core_sw = F("switch", "CORE-SW", uplink="CORE-NGFW")
        core_sw.add_interface("eth0", ip="10.0.0.2"); t.add(core_sw, layer=5)

        # ---------------- Cloud ----------------
        cloud = F("cloud", "CLOUD-VPC", gateway="CORE-NGFW")
        cloud.add_interface("eth0", ip="10.50.0.10", subnet="10.50.0.0/16")
        t.add(cloud, layer=3, vlan="cloud")

        # ---------------- Access switches (SVIs) ----------------
        for sw_name, vlan_key in _ACCESS_SWITCHES.items():
            sw = F("switch", sw_name, uplink="CORE-SW")
            sw.add_interface("svi", ip=VLANS[vlan_key].gateway,
                             subnet=VLANS[vlan_key].cidr)
            t.add(sw, layer=6, vlan=vlan_key); t.link("CORE-SW", sw_name)

        # ---------------- Endpoints ----------------
        for name, ip, vlan_key, sw_name, kind in _ENDPOINTS:
            dev = F(kind, name, gateway=sw_name)
            dev.add_interface("eth0", ip=ip, subnet=VLANS[vlan_key].cidr)
            t.add(dev, layer=7, vlan=vlan_key); t.link(sw_name, name)
            t.get(sw_name).learn(ip, name)         # type: ignore[union-attr]

        # ---------------- Backbone links ----------------
        for a, b in [
            ("INTERNET", "ISP-EDGE"), ("ISP-EDGE", "EDGE-RTR"),
            ("EDGE-RTR", "PERIM-NGFW"), ("INTERNET", "ATTACKER"),
            ("INTERNET", "REMOTE-USER"), ("INTERNET", "EXT-SVC"),
            ("PERIM-NGFW", "DMZ-WAF"), ("DMZ-WAF", "DMZ-SW"),
            ("PERIM-NGFW", "CORE-NGFW"), ("PERIM-NGFW", "PROXY"),
            ("CORE-NGFW", "CORE-SW"), ("CORE-NGFW", "VPN-GW"),
            ("CORE-NGFW", "CLOUD-VPC"),
        ]:
            t.link(a, b)

        # ---------------- Routing tables ----------------
        def R(dev: str, cidr: str, nh: str) -> None:
            t.get(dev).routing_table.add_route(cidr, "eth0", nh)  # type: ignore[union-attr]

        # Internet: org ranges -> ISP; public DNS -> external service node
        R("INTERNET", "198.51.100.0/24", "ISP-EDGE")
        R("INTERNET", "172.16.20.0/24", "ISP-EDGE")
        R("INTERNET", "10.0.0.0/8", "ISP-EDGE")
        R("INTERNET", f"{EXTERNAL_DNS}/32", "EXT-SVC")
        # ISP -> Edge for org-bound traffic
        for c in ("198.51.100.0/24", "172.16.20.0/24", "10.0.0.0/8"):
            R("ISP-EDGE", c, "EDGE-RTR")
        # Edge -> Perimeter
        R("EDGE-RTR", "172.16.20.0/24", "PERIM-NGFW")
        R("EDGE-RTR", "10.0.0.0/8", "PERIM-NGFW")
        # Perimeter: DMZ via WAF, internal via Core NGFW
        R("PERIM-NGFW", "172.16.20.0/24", "DMZ-WAF")
        R("PERIM-NGFW", "10.0.0.0/8", "CORE-NGFW")
        # Core NGFW: each VLAN -> its access switch; cloud -> VPC
        for sw_name, vlan_key in _ACCESS_SWITCHES.items():
            R("CORE-NGFW", VLANS[vlan_key].cidr, sw_name)
        R("CORE-NGFW", "10.50.0.0/16", "CLOUD-VPC")

        return t