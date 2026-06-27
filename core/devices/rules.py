"""
core/devices/rules.py
Firewall ACL engine + payload signature scanner. Shared by Firewall/NGFW/WAF.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from core.enums import Protocol, Severity

if TYPE_CHECKING:
    from core.simulation.packet import Packet


class RuleAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


def _ip_in(ip: str, cidr: str | None) -> bool:
    if cidr in (None, "any", "0.0.0.0/0"):
        return True
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


@dataclass
class FirewallRule:
    """A single ACL entry. None fields act as wildcards."""
    action: RuleAction
    protocol: Protocol | None = None
    src: str | None = None
    dst: str | None = None
    port: int | None = None
    description: str = ""

    def matches(self, packet: "Packet") -> bool:
        return (
            (self.protocol is None or self.protocol == packet.protocol)
            and _ip_in(packet.source_ip, self.src)
            and _ip_in(packet.dest_ip, self.dst)
            and (self.port is None or self.port == packet.dst_port)
        )


@dataclass
class Verdict:
    allow: bool
    reason: str
    rule: FirewallRule | None = None


class RuleEngine:
    """First-match ACL evaluator with a configurable default action."""

    def __init__(self, default: RuleAction = RuleAction.ALLOW) -> None:
        self.default = default
        self._rules: list[FirewallRule] = []

    def add(self, rule: FirewallRule) -> "RuleEngine":
        self._rules.append(rule)
        return self

    @property
    def rules(self) -> list[FirewallRule]:
        return list(self._rules)

    def evaluate(self, packet: "Packet") -> Verdict:
        for rule in self._rules:
            if rule.matches(packet):
                allow = rule.action == RuleAction.ALLOW
                return Verdict(allow, rule.description or rule.action.value, rule)
        return Verdict(self.default == RuleAction.ALLOW,
                       f"default {self.default.value}")


# --------------------------------------------------------------------------- #
# L7 attack signatures (case-insensitive substring match).
# --------------------------------------------------------------------------- #
@dataclass
class Signature:
    name: str
    patterns: tuple[str, ...]
    mitre: str
    severity: Severity = Severity.HIGH


SIGNATURES: tuple[Signature, ...] = (
    Signature("SQL Injection",
              ("' or '1'='1", "union select", "'--", " or 1=1", "sleep("),
              "T1190", Severity.HIGH),
    Signature("Cross-Site Scripting",
              ("<script", "onerror=", "javascript:", "<img src=x"),
              "T1059", Severity.HIGH),
    Signature("Command Injection",
              ("; cat ", "&& whoami", "| nc ", "$(", "; rm -rf"),
              "T1059", Severity.HIGH),
    Signature("Path Traversal",
              ("../../", "..\\", "/etc/passwd"),
              "T1083", Severity.MEDIUM),
)


def scan_payload(payload: str) -> list[dict]:
    """Return all signatures whose patterns appear in `payload`."""
    text = (payload or "").lower()
    hits: list[dict] = []
    for sig in SIGNATURES:
        if any(p in text for p in sig.patterns):
            hits.append({"name": sig.name, "mitre": sig.mitre,
                         "severity": sig.severity})
    return hits