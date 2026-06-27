"""Reconnaissance attacks - network and port scanning."""
from __future__ import annotations

from core.attacks.base import AbstractAttack, AttackContext, TECH
from core.attacks.registry import register_attack
from core.enums import Severity
from core.simulation.packet import Packet


@register_attack("nmap", "Nmap Port Scan")
class NmapScan(AbstractAttack):
    NAME = "Nmap Port Scan"
    DESCRIPTION = "TCP SYN sweep across common service ports to map the target's exposed surface."
    TACTIC = "Reconnaissance"
    TECHNIQUES = (TECH["T1046"], TECH["T1595"])
    SEVERITY = Severity.MEDIUM

    DEFAULT_PORTS = (21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 3389)

    def __init__(self, ports=None, **params):
        super().__init__(**params)
        self.ports = tuple(ports) if ports else self.DEFAULT_PORTS

    def execute(self, ctx: AttackContext) -> None:
        ctx.event(
            f"Starting TCP SYN scan of {ctx.target_host} ({ctx.target_ip}) on {len(self.ports)} ports",
            Severity.INFO,
            ports=list(self.ports),
        )

        open_ports: list[int] = []
        filtered: list[int] = []
        closed: list[int] = []

        for port in self.ports:
            pkt = Packet.tcp_syn(ctx.src_ip, ctx.target_ip, port)
            result = ctx.send(pkt, ctx.source_host)
            p = result.packet
            if p.delivered:
                open_ports.append(port)
                ctx.event(f"Port {port}/tcp open", Severity.LOW, port=port, state="open")
            elif p.blocked:
                filtered.append(port)
            else:
                closed.append(port)

        ctx.event(
            f"Scan complete: open={open_ports} filtered={len(filtered)} closed={len(closed)}",
            Severity.INFO,
            open_ports=open_ports,
            filtered=len(filtered),
            closed=len(closed),
        )

        ctx.alert(
            f"Port scan from {ctx.src_ip} against {ctx.target_host}: {len(open_ports)} open port(s)",
            Severity.MEDIUM,
            mitre_id="T1046",
            recommendation="Enable scan detection and verify only required ports are exposed.",
            open_ports=open_ports,
        )