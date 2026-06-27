"""Web application attacks - SQL injection."""
from __future__ import annotations

from core.attacks.base import AbstractAttack, AttackContext, TECH
from core.attacks.registry import register_attack
from core.enums import Protocol, Severity
from core.simulation.packet import Packet


@register_attack("sqli", "SQL Injection")
class SqlInjection(AbstractAttack):
    NAME = "SQL Injection"
    DESCRIPTION = "Sends crafted SQL payloads to a web endpoint to manipulate backend queries."
    TACTIC = "Initial Access"
    TECHNIQUES = (TECH["T1190"],)
    SEVERITY = Severity.HIGH

    PAYLOADS = (
        "' OR '1'='1",
        "admin'--",
        "1; DROP TABLE users;--",
        "' UNION SELECT username, password FROM users--",
    )

    def __init__(self, payloads=None, port=80, **params):
        super().__init__(**params)
        self.payloads = tuple(payloads) if payloads else self.PAYLOADS
        self.port = port

    def execute(self, ctx: AttackContext) -> None:
        ctx.event(
            f"Launching SQL injection against {ctx.target_host} ({ctx.target_ip}:{self.port})",
            Severity.INFO,
            attempts=len(self.payloads),
        )

        reached = 0
        for payload in self.payloads:
            pkt = Packet.tcp_syn(ctx.src_ip, ctx.target_ip, self.port)
            pkt.protocol = Protocol.HTTP
            pkt.payload = f"GET /login?q={payload} HTTP/1.1"
            result = ctx.send(pkt, ctx.source_host)
            p = result.packet
            if p.blocked:
                where = p.path[-1] if p.path else "perimeter"
                ctx.event(f"Payload blocked at {where}: {payload!r}", Severity.LOW, payload=payload)
            elif p.delivered:
                reached += 1
                ctx.event(f"Payload reached application: {payload!r}", Severity.HIGH, payload=payload)

        if reached:
            ctx.alert(
                f"SQL injection reached {ctx.target_host}: possible database compromise",
                Severity.CRITICAL,
                mitre_id="T1190",
                recommendation="Deploy WAF signatures, use parameterized queries, validate all input.",
                reached=reached,
            )
        else:
            ctx.event(
                f"All {len(self.payloads)} SQLi payloads blocked before reaching {ctx.target_host}",
                Severity.INFO,
            )