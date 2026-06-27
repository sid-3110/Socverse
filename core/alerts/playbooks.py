"""SOC analyst knowledge base: response playbooks keyed by MITRE technique."""
from __future__ import annotations

from dataclasses import dataclass

from core.enums import Severity


@dataclass(frozen=True)
class Playbook:
    technique: str
    name: str
    tactic: str
    default_severity: Severity
    containment: tuple[str, ...] = ()
    investigation: tuple[str, ...] = ()
    false_positives: tuple[str, ...] = ()
    business_impact: str = ""
    data_sources: tuple[str, ...] = ()


PLAYBOOKS: dict[str, Playbook] = {
    "T1046": Playbook(
        technique="T1046",
        name="Network Service Discovery",
        tactic="Discovery",
        default_severity=Severity.MEDIUM,
        containment=(
            "Block the scanning source IP at the perimeter firewall.",
            "Enable port-scan rate limiting on the affected segment.",
        ),
        investigation=(
            "Identify the source IP and confirm it is not an authorized scanner.",
            "Review which ports responded and whether any expose sensitive services.",
            "Correlate with follow-on connection attempts to the discovered ports.",
        ),
        false_positives=(
            "Authorized vulnerability scans on a known schedule.",
            "Internal asset-inventory tooling.",
        ),
        business_impact="Reconnaissance precedes targeted attacks; exposed services may be exploited next.",
        data_sources=("Firewall logs", "NetFlow", "IDS"),
    ),
    "T1595": Playbook(
        technique="T1595",
        name="Active Scanning",
        tactic="Reconnaissance",
        default_severity=Severity.LOW,
        containment=(
            "Drop traffic from the source at the edge.",
            "Add the source to a watchlist for follow-on activity.",
        ),
        investigation=(
            "Determine scan breadth (single host vs subnet sweep).",
            "Check whether the source has prior history against your range.",
        ),
        false_positives=("Search-engine crawlers.", "Uptime and monitoring probes."),
        business_impact="Early-stage external interest in your perimeter.",
        data_sources=("Edge firewall", "WAF"),
    ),
    "T1190": Playbook(
        technique="T1190",
        name="Exploit Public-Facing Application",
        tactic="Initial Access",
        default_severity=Severity.HIGH,
        containment=(
            "Block the source IP and the targeted URI at the WAF.",
            "Take the affected app into maintenance if exploitation is confirmed.",
            "Rotate any credentials or tokens the app can access.",
        ),
        investigation=(
            "Inspect the payload and identify the injection class (SQLi, XSS, RCE).",
            "Check app and database logs for successful query manipulation.",
            "Verify whether the request returned data indicating success.",
            "Confirm whether the WAF/NGFW blocked or passed the request.",
        ),
        false_positives=(
            "Authorized red-team security testing.",
            "Legitimate input that resembles an injection string.",
        ),
        business_impact="Successful exploitation can lead to data theft, defacement, or server compromise.",
        data_sources=("WAF", "Web server logs", "Database audit logs"),
    ),
    "T1110": Playbook(
        technique="T1110",
        name="Brute Force",
        tactic="Credential Access",
        default_severity=Severity.HIGH,
        containment=(
            "Lock the targeted accounts and force a password reset.",
            "Block the source IP and enforce MFA on the exposed service.",
            "Disable external exposure of the service if not required.",
        ),
        investigation=(
            "Count authentication attempts and identify targeted usernames.",
            "Determine whether any attempt succeeded.",
            "Check for the same source against other hosts or services.",
        ),
        false_positives=(
            "A user repeatedly mistyping a password.",
            "A misconfigured service retrying stale credentials.",
        ),
        business_impact="Account compromise grants an attacker an authenticated foothold.",
        data_sources=("Authentication logs", "Windows Security events", "VPN logs"),
    ),
    "T1059": Playbook(
        technique="T1059",
        name="Command and Scripting Interpreter",
        tactic="Execution",
        default_severity=Severity.HIGH,
        containment=(
            "Isolate the affected host from the network.",
            "Block the source and kill suspicious processes.",
        ),
        investigation=(
            "Identify the command or script content in the payload.",
            "Determine whether execution succeeded on the target.",
            "Hunt for persistence created by the executed code.",
        ),
        false_positives=("Admin automation scripts.", "Legitimate deployment tooling."),
        business_impact="Arbitrary code execution can lead to full host compromise.",
        data_sources=("EDR", "Process logs", "WAF"),
    ),
    "T1083": Playbook(
        technique="T1083",
        name="File and Directory Discovery",
        tactic="Discovery",
        default_severity=Severity.MEDIUM,
        containment=(
            "Block the source and review exposed file paths.",
            "Restrict directory traversal at the web/app tier.",
        ),
        investigation=(
            "Identify which paths were requested.",
            "Confirm whether sensitive files were returned.",
        ),
        false_positives=("Legitimate file browsing.", "Crawler path enumeration."),
        business_impact="Path discovery often precedes data exfiltration.",
        data_sources=("Web server logs", "WAF"),
    ),
}

_GENERIC = Playbook(
    technique="UNKNOWN",
    name="Uncategorized Activity",
    tactic="Unknown",
    default_severity=Severity.MEDIUM,
    containment=("Investigate the source and scope before acting.",),
    investigation=("Review the raw event stream around this alert.",),
    false_positives=("Benign automated activity.",),
    business_impact="Impact unknown until triaged.",
    data_sources=("SIEM",),
)


def get_playbook(technique_id: str | None) -> Playbook:
    if not technique_id:
        return _GENERIC
    return PLAYBOOKS.get(technique_id.upper(), _GENERIC)