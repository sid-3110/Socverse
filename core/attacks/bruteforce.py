"""
core/attacks/bruteforce.py
Credential-access brute force attacks. RDP/SSH share one implementation.
"""
from __future__ import annotations

from core.attacks.base import TECH, AbstractAttack, AttackContext
from core.attacks.registry import register_attack
from core.enums import Severity
from core.simulation.packet import Packet


class _BruteForce(AbstractAttack):
    """Shared brute-force logic; subclasses set PORT + SERVICE."""
    PORT: int = 0
    SERVICE: str = ""
    TACTIC = "Credential Access"
    TECHNIQUES = (TECH["T1110"],)
    SEVERITY = Severity.HIGH

    def execute(self, ctx: AttackContext) -> None:
        attempts = int(self.params.get("attempts", 5))
        reached = 0
        for i in range(1, attempts + 1):
            r = ctx.send(Packet.tcp_syn(
                ctx.src_ip, ctx.target_ip, self.PORT, ttl=64,
                payload=f"{self.SERVICE}-login user=administrator "
                        f"pass=Winter2025!{i}"))
            ctx.event(f"{self.SERVICE} attempt {i}/{attempts} -> {r.packet.status}",
                      severity=Severity.LOW, attempt=i, status=r.packet.status)
            reached += int(r.packet.delivered)

        note = "service reachable" if reached else "blocked by perimeter"
        sev = Severity.CRITICAL if reached else Severity.HIGH
        ctx.alert(
            f"{self.SERVICE} brute force: {attempts} attempts to "
            f"{ctx.target_host} ({note})",
            sev, mitre_id="T1110",
            recommendation="Enforce account lockout + MFA; restrict source IPs.",
            attempts=attempts, reached=reached,
        )


@register_attack("rdp_brute", "RDP Brute Force")
class RdpBruteForce(_BruteForce):
    NAME = "RDP Brute Force"
    DESCRIPTION = "Repeated RDP (3389) login attempts to guess credentials."
    PORT = 3389
    SERVICE = "RDP"


@register_attack("ssh_brute", "SSH Brute Force")
class SshBruteForce(_BruteForce):
    NAME = "SSH Brute Force"
    DESCRIPTION = "Repeated SSH (22) login attempts to guess credentials."
    PORT = 22
    SERVICE = "SSH"