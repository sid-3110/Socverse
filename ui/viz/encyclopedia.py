"""Device knowledge base: the educational brain behind the asset console.

`get_dossier_knowledge(device_type)` returns a JSON-safe dict of SOC-grade
teaching fields for a given device type: role, common attacks (with MITRE
technique ids), detection sources, investigation steps, hardening guidance,
CLI examples, and the RFCs that define the technology.

This module is pure data plus one lookup. It imports no Streamlit and no
renderer code, so it can be unit-tested in isolation and reused anywhere.
`snapshot.build_snapshot()` merges the returned dict into each device dossier
under the `kb` key; the browser renderer reads it to populate the side panel.
"""
from __future__ import annotations
from typing import Any

# Every entry is normalized through `_fields()` so the renderer can rely on a
# stable shape: missing keys fall back to the generic defaults below.
_GENERIC: dict[str, Any] = {
    "role": "Network-connected asset participating in enterprise traffic.",
    "common_attacks": [
        {"name": "Reconnaissance / port scanning", "mitre": "T1046",
         "note": "Adversary maps reachable services before exploitation."},
    ],
    "detection": [
        "Baseline traffic volume and flag statistical anomalies.",
        "Correlate authentication and connection logs in the SIEM.",
    ],
    "investigation": [
        "Identify the asset owner and business function.",
        "Pull recent logs for the source and destination IPs.",
        "Check whether the activity matches a known maintenance window.",
    ],
    "hardening": [
        "Apply least-privilege access and disable unused services.",
        "Keep firmware and software patched to the current release.",
        "Forward logs to the central SIEM for retention and correlation.",
    ],
    "cli_examples": [
        {"label": "List active connections", "cmd": "netstat -ant"},
    ],
    "rfcs": [
        {"id": "RFC 1122", "title": "Requirements for Internet Hosts"},
    ],
}

_KB: dict[str, dict[str, Any]] = {
    "ROUTER": {
        "role": "Layer-3 device forwarding packets between subnets using a "
                "routing table; the enterprise's path-selection brain.",
        "common_attacks": [
            {"name": "Route/ARP poisoning", "mitre": "T1557",
             "note": "Forged routes or ARP replies redirect traffic for MITM."},
            {"name": "Management-plane brute force", "mitre": "T1110",
             "note": "SSH/Telnet credential guessing against the router."},
            {"name": "Denial of service", "mitre": "T1498",
             "note": "Control-plane flooding starves the forwarding engine."},
        ],
        "detection": [
            "Alert on routing-table or BGP/OSPF neighbor changes.",
            "Monitor management-plane logins from unexpected sources.",
            "Watch for asymmetric routes and unexpected next-hops.",
        ],
        "investigation": [
            "Diff the running config against the last known-good baseline.",
            "Review who authenticated to the device and from where.",
            "Confirm routing neighbors are all authorized peers.",
        ],
        "hardening": [
            "Restrict management to an out-of-band network with ACLs.",
            "Use SSHv2 only, disable Telnet, enforce AAA/TACACS+.",
            "Authenticate routing protocols (OSPF/BGP MD5 or keychains).",
        ],
        "cli_examples": [
            {"label": "Show routing table", "cmd": "show ip route"},
            {"label": "Show neighbors", "cmd": "show ip ospf neighbor"},
        ],
        "rfcs": [
            {"id": "RFC 791", "title": "Internet Protocol (IPv4)"},
            {"id": "RFC 2328", "title": "OSPF Version 2"},
            {"id": "RFC 4271", "title": "Border Gateway Protocol 4 (BGP-4)"},
        ],
    },
    "SWITCH": {
        "role": "Layer-2 device forwarding frames within a broadcast domain "
                "using a MAC address table; segments LANs into VLANs.",
        "common_attacks": [
            {"name": "MAC flooding / CAM overflow", "mitre": "T1557",
             "note": "Overflows the MAC table to force hub-like flooding."},
            {"name": "VLAN hopping", "mitre": "T1599",
             "note": "Double-tagging or DTP abuse crosses VLAN boundaries."},
            {"name": "ARP spoofing", "mitre": "T1557.002",
             "note": "Poisoned ARP cache enables on-path interception."},
        ],
        "detection": [
            "Alert on port security violations and MAC moves.",
            "Watch for unexpected trunk negotiation (DTP) events.",
            "Monitor DHCP snooping and dynamic ARP inspection drops.",
        ],
        "investigation": [
            "Map the offending MAC to a physical port and asset.",
            "Check for unauthorized trunk ports or VLAN changes.",
            "Review switchport logs around the event window.",
        ],
        "hardening": [
            "Enable port security with sticky MAC limits.",
            "Disable DTP; set access ports to 'switchport mode access'.",
            "Enable DHCP snooping and dynamic ARP inspection.",
        ],
        "cli_examples": [
            {"label": "Show MAC table", "cmd": "show mac address-table"},
            {"label": "Show port security", "cmd": "show port-security"},
        ],
        "rfcs": [
            {"id": "IEEE 802.1Q", "title": "VLAN Tagging"},
            {"id": "IEEE 802.1X", "title": "Port-Based Network Access Control"},
        ],
    },
    "NGFW": {
        "role": "Next-generation firewall enforcing policy with deep packet "
                "inspection, app-ID, IPS, and TLS inspection at the perimeter.",
        "common_attacks": [
            {"name": "Policy/evasion bypass", "mitre": "T1599",
             "note": "Fragmentation or tunneling to slip past inspection."},
            {"name": "Exploitation of public-facing rule", "mitre": "T1190",
             "note": "Abuse of an over-permissive inbound rule."},
            {"name": "Credential brute force on mgmt", "mitre": "T1110",
             "note": "Login guessing against the firewall admin portal."},
        ],
        "detection": [
            "Alert on IPS/threat signatures and blocked sessions.",
            "Monitor rule-base changes and policy commits.",
            "Watch for denied-then-allowed sequences (rule tampering).",
        ],
        "investigation": [
            "Trace the session through the policy that matched it.",
            "Confirm the threat signature and affected destination.",
            "Check whether TLS inspection saw the payload or was bypassed.",
        ],
        "hardening": [
            "Default-deny inbound; least-privilege rule base with logging.",
            "Keep threat/IPS signatures and app-ID current.",
            "Separate and MFA-protect the management plane.",
        ],
        "cli_examples": [
            {"label": "Show traffic log", "cmd": "show log traffic recent"},
            {"label": "Show threat log", "cmd": "show log threat recent"},
        ],
        "rfcs": [
            {"id": "RFC 4949", "title": "Internet Security Glossary"},
            {"id": "RFC 8404", "title": "Effects of Pervasive Encryption"},
        ],
    },
    "WAF": {
        "role": "Web application firewall inspecting HTTP/S to block app-layer "
                "attacks (injection, XSS) before they reach the web server.",
        "common_attacks": [
            {"name": "SQL injection", "mitre": "T1190",
             "note": "Malicious SQL in parameters to reach the database."},
            {"name": "Cross-site scripting", "mitre": "T1059.007",
             "note": "Injected script executes in a victim's browser."},
            {"name": "WAF evasion", "mitre": "T1027",
             "note": "Encoding/obfuscation to bypass signatures."},
        ],
        "detection": [
            "Alert on OWASP CRS rule hits and anomaly scores.",
            "Watch for spikes in 4xx/5xx and blocked request bursts.",
            "Correlate payload signatures with the SIEM.",
        ],
        "investigation": [
            "Pull the full request: URI, headers, and body payload.",
            "Determine whether the request was blocked or passed through.",
            "Check the backend app logs for matching activity.",
        ],
        "hardening": [
            "Run OWASP Core Rule Set in blocking mode, tuned for the app.",
            "Enforce strict input validation at the application as well.",
            "Rate-limit and geo-fence sensitive endpoints.",
        ],
        "cli_examples": [
            {"label": "Tail audit log", "cmd": "tail -f modsec_audit.log"},
        ],
        "rfcs": [
            {"id": "RFC 9110", "title": "HTTP Semantics"},
            {"id": "RFC 6749", "title": "OAuth 2.0 Authorization Framework"},
        ],
    },
    "PROXY": {
        "role": "Forward/reverse proxy mediating client requests; enforces "
                "egress policy, caching, and URL/content filtering.",
        "common_attacks": [
            {"name": "C2 over web proxy", "mitre": "T1071.001",
             "note": "Beaconing disguised as normal web browsing."},
            {"name": "Data exfiltration", "mitre": "T1048",
             "note": "Staged data pushed out through allowed channels."},
            {"name": "Open-proxy abuse", "mitre": "T1090",
             "note": "Misconfigured proxy relays attacker traffic."},
        ],
        "detection": [
            "Baseline per-host destinations; flag rare/new domains.",
            "Alert on long-lived, fixed-interval beacon patterns.",
            "Monitor large outbound transfers to uncategorized sites.",
        ],
        "investigation": [
            "Pull the proxy access log for the client and destination.",
            "Check domain reputation and category of the destination.",
            "Correlate request timing for beaconing regularity.",
        ],
        "hardening": [
            "Default-deny egress; allow-list required categories only.",
            "Enable TLS inspection where policy and law permit.",
            "Authenticate users so logs attribute traffic to identities.",
        ],
        "cli_examples": [
            {"label": "Tail access log", "cmd": "tail -f /var/log/squid/access.log"},
        ],
        "rfcs": [
            {"id": "RFC 9110", "title": "HTTP Semantics"},
            {"id": "RFC 3040", "title": "Internet Web Replication and Caching"},
        ],
    },
    "VPN": {
        "role": "VPN gateway terminating encrypted tunnels for remote access "
                "or site-to-site connectivity into the enterprise.",
        "common_attacks": [
            {"name": "Credential stuffing / brute force", "mitre": "T1110",
             "note": "Reused or guessed creds against the VPN portal."},
            {"name": "Exploit of VPN appliance CVE", "mitre": "T1190",
             "note": "Unpatched gateway used for initial access."},
            {"name": "MFA fatigue / push bombing", "mitre": "T1621",
             "note": "Repeated prompts to coerce approval."},
        ],
        "detection": [
            "Alert on impossible-travel and new-geo logins.",
            "Watch for many failed logins followed by a success.",
            "Monitor concurrent sessions from one identity.",
        ],
        "investigation": [
            "Confirm the user, source IP, and device posture.",
            "Check MFA method and whether a push was approved.",
            "Review what internal resources the session reached.",
        ],
        "hardening": [
            "Enforce phishing-resistant MFA and device certificates.",
            "Patch the appliance promptly; subscribe to vendor advisories.",
            "Restrict split-tunneling and post-auth lateral access.",
        ],
        "cli_examples": [
            {"label": "Show active tunnels", "cmd": "show vpn-sessiondb"},
        ],
        "rfcs": [
            {"id": "RFC 7296", "title": "Internet Key Exchange v2 (IKEv2)"},
            {"id": "RFC 4301", "title": "Security Architecture for IP (IPsec)"},
        ],
    },
    "DNS": {
        "role": "Resolves hostnames to IP addresses; a high-value target "
                "because nearly all activity begins with a DNS lookup.",
        "common_attacks": [
            {"name": "DNS tunneling", "mitre": "T1071.004",
             "note": "Data smuggled inside DNS queries/responses."},
            {"name": "Cache poisoning", "mitre": "T1584.002",
             "note": "Forged records redirect victims to attacker hosts."},
            {"name": "Domain generation algorithm C2", "mitre": "T1568.002",
             "note": "Malware resolves algorithmically generated domains."},
        ],
        "detection": [
            "Alert on high-entropy or unusually long query names.",
            "Flag spikes in TXT/NULL record queries (tunneling).",
            "Watch NXDOMAIN bursts indicative of DGA beaconing.",
        ],
        "investigation": [
            "Pull resolver logs for the querying host and domain.",
            "Score the domain: age, reputation, and entropy.",
            "Correlate with proxy/firewall logs for the same host.",
        ],
        "hardening": [
            "Restrict recursion to internal clients; use DNS filtering.",
            "Enable DNSSEC validation and query logging.",
            "Force clients through approved resolvers only.",
        ],
        "cli_examples": [
            {"label": "Resolve a name", "cmd": "dig example.com any"},
        ],
        "rfcs": [
            {"id": "RFC 1035", "title": "Domain Names - Implementation"},
            {"id": "RFC 4033", "title": "DNS Security Introduction (DNSSEC)"},
        ],
    },
    "DC": {
        "role": "Active Directory domain controller; authenticates users and "
                "machines and is the crown jewel for identity attacks.",
        "common_attacks": [
            {"name": "Kerberoasting", "mitre": "T1558.003",
             "note": "Crack service-account tickets offline for creds."},
            {"name": "DCSync", "mitre": "T1003.006",
             "note": "Replicate directory data to steal password hashes."},
            {"name": "Pass-the-hash / ticket", "mitre": "T1550",
             "note": "Reuse stolen hashes or tickets to move laterally."},
        ],
        "detection": [
            "Alert on 4769 ticket requests with weak (RC4) encryption.",
            "Monitor 4662 replication access from non-DC accounts (DCSync).",
            "Watch for anomalous 4624/4768 logon and TGT patterns.",
        ],
        "investigation": [
            "Identify the account and host issuing the requests.",
            "Check for recent privilege grants or group changes.",
            "Map lateral movement from the compromised identity.",
        ],
        "hardening": [
            "Tier admin accounts; ban domain admins on workstations.",
            "Use gMSAs and long, random service-account passwords.",
            "Enable AES Kerberos and audit replication permissions.",
        ],
        "cli_examples": [
            {"label": "List SPNs", "cmd": "setspn -Q */*"},
            {"label": "Recent logons", "cmd": "Get-EventLog Security -Newest 50"},
        ],
        "rfcs": [
            {"id": "RFC 4120", "title": "The Kerberos Network Auth Service v5"},
            {"id": "RFC 4511", "title": "LDAP: The Protocol"},
        ],
    },
    "SERVER": {
        "role": "Application or infrastructure server hosting business "
                "services; a common pivot and persistence target.",
        "common_attacks": [
            {"name": "Exploit public-facing service", "mitre": "T1190",
             "note": "Vulnerable service yields code execution."},
            {"name": "Web shell / persistence", "mitre": "T1505.003",
             "note": "Backdoor planted in a web-accessible directory."},
            {"name": "Privilege escalation", "mitre": "T1068",
             "note": "Local exploit to gain root/SYSTEM."},
        ],
        "detection": [
            "Alert on new listening ports and unexpected processes.",
            "Monitor file integrity in web roots and system dirs.",
            "Watch for outbound connections from server processes.",
        ],
        "investigation": [
            "Enumerate running processes and their parent chain.",
            "Check for new/modified files and scheduled tasks.",
            "Review auth logs for the initial access vector.",
        ],
        "hardening": [
            "Patch promptly; remove unused services and packages.",
            "Run services as least-privilege, non-root accounts.",
            "Deploy EDR and ship logs to the SIEM.",
        ],
        "cli_examples": [
            {"label": "Listening sockets", "cmd": "ss -tlnp"},
            {"label": "Recent auth", "cmd": "journalctl -u sshd --since '-1h'"},
        ],
        "rfcs": [
            {"id": "RFC 9110", "title": "HTTP Semantics"},
            {"id": "RFC 5321", "title": "Simple Mail Transfer Protocol"},
        ],
    },
    "ENDPOINT": {
        "role": "User workstation/laptop; the most common point of initial "
                "compromise via phishing and malicious documents.",
        "common_attacks": [
            {"name": "Phishing attachment", "mitre": "T1566.001",
             "note": "Malicious document executes on open."},
            {"name": "Malicious script execution", "mitre": "T1059",
             "note": "PowerShell/cmd used to download and run payloads."},
            {"name": "Credential theft", "mitre": "T1555",
             "note": "Harvest browser/OS-stored credentials."},
        ],
        "detection": [
            "Alert on office apps spawning script interpreters.",
            "Monitor for LSASS access and credential-dump tools.",
            "Watch for new autoruns and scheduled tasks.",
        ],
        "investigation": [
            "Pull the process tree around the suspicious execution.",
            "Identify the delivery vector (email, USB, download).",
            "Check for outbound C2 and lateral movement attempts.",
        ],
        "hardening": [
            "Block macros from the internet; enable ASR rules.",
            "Enforce application allow-listing and EDR.",
            "Least-privilege users; no local admin by default.",
        ],
        "cli_examples": [
            {"label": "Process tree", "cmd": "Get-CimInstance Win32_Process"},
        ],
        "rfcs": [
            {"id": "RFC 5321", "title": "Simple Mail Transfer Protocol"},
            {"id": "RFC 8446", "title": "TLS 1.3"},
        ],
    },
    "CLOUD": {
        "role": "Cloud-hosted workload or service; governed by IAM and API "
                "control planes rather than physical network edges.",
        "common_attacks": [
            {"name": "Cloud credential abuse", "mitre": "T1078.004",
             "note": "Stolen access keys used against the control plane."},
            {"name": "Public storage exposure", "mitre": "T1530",
             "note": "Misconfigured bucket exposes sensitive data."},
            {"name": "IAM privilege escalation", "mitre": "T1098",
             "note": "Policy abuse to widen permissions."},
        ],
        "detection": [
            "Alert on API calls from new regions or IPs (CloudTrail).",
            "Monitor IAM policy and role changes.",
            "Watch for public-access changes on storage resources.",
        ],
        "investigation": [
            "Trace the principal and access key in the audit log.",
            "Review the sequence of API calls in the session.",
            "Check for new IAM users, roles, or persistence.",
        ],
        "hardening": [
            "Enforce MFA, short-lived creds, and least-privilege IAM.",
            "Block public access by default; encrypt at rest.",
            "Enable full control-plane logging and anomaly detection.",
        ],
        "cli_examples": [
            {"label": "Recent API events", "cmd": "aws cloudtrail lookup-events"},
        ],
        "rfcs": [
            {"id": "RFC 6749", "title": "OAuth 2.0 Authorization Framework"},
            {"id": "RFC 7519", "title": "JSON Web Token (JWT)"},
        ],
    },
    "INTERNET": {
        "role": "The untrusted public network; origin of inbound threats and "
                "destination for command-and-control and exfiltration.",
        "common_attacks": [
            {"name": "External scanning", "mitre": "T1595",
             "note": "Internet-wide probing for exposed services."},
            {"name": "Command and control", "mitre": "T1071",
             "note": "Compromised hosts beacon to external servers."},
        ],
        "detection": [
            "Match inbound/outbound IPs against threat intel feeds.",
            "Alert on connections to known-bad or newly registered domains.",
        ],
        "investigation": [
            "Enrich the external IP with WHOIS and reputation data.",
            "Determine which internal asset initiated or received traffic.",
        ],
        "hardening": [
            "Minimize the public attack surface; default-deny inbound.",
            "Egress-filter to approved destinations only.",
        ],
        "cli_examples": [
            {"label": "WHOIS lookup", "cmd": "whois 203.0.113.10"},
        ],
        "rfcs": [
            {"id": "RFC 791", "title": "Internet Protocol (IPv4)"},
            {"id": "RFC 1918", "title": "Private Address Allocation"},
        ],
    },
    "ATTACKER": {
        "role": "Adversary-controlled host (red-team origin) used to launch "
                "reconnaissance, exploitation, and post-exploitation activity.",
        "common_attacks": [
            {"name": "Reconnaissance", "mitre": "T1595",
             "note": "Active scanning to map the target environment."},
            {"name": "Exploitation", "mitre": "T1190",
             "note": "Weaponized exploit against a discovered service."},
        ],
        "detection": [
            "Treat as the canonical source for attack-path analysis.",
            "Correlate every alert back to this origin in the SIEM.",
        ],
        "investigation": [
            "Reconstruct the full kill chain from this node outward.",
            "Catalog the techniques used at each hop.",
        ],
        "hardening": [
            "N/A - this node models the threat, not a defended asset.",
        ],
        "cli_examples": [
            {"label": "Example scan", "cmd": "nmap -sS -p- target"},
        ],
        "rfcs": [
            {"id": "RFC 4949", "title": "Internet Security Glossary"},
        ],
    },
}

# Map the many type strings the topology may emit onto canonical KB keys.
_ALIASES: dict[str, str] = {
    "GATEWAY": "ROUTER", "EDGE-RTR": "ROUTER", "EDGE": "ROUTER",
    "CORE-RTR": "ROUTER", "L3": "ROUTER", "ISP": "ROUTER", "ISP-EDGE": "ROUTER",
    "L2": "SWITCH", "ACCESS": "SWITCH", "ACCESS-SWITCH": "SWITCH",
    "FIREWALL": "NGFW", "FW": "NGFW", "PERIM-NGFW": "NGFW", "CORE-NGFW": "NGFW",
    "WEB-WAF": "WAF",
    "FORWARD-PROXY": "PROXY", "REVERSE-PROXY": "PROXY",
    "VPN-GW": "VPN", "VPN-GATEWAY": "VPN",
    "DNS-SERVER": "DNS", "RESOLVER": "DNS",
    "DOMAIN-CONTROLLER": "DC", "AD": "DC", "ACTIVE-DIRECTORY": "DC",
    "WEB": "SERVER", "WEB-SERVER": "SERVER", "APP": "SERVER", "APP-SERVER": "SERVER",
    "DB": "SERVER", "DATABASE": "SERVER", "SQL": "SERVER", "MAIL": "SERVER",
    "FILE": "SERVER", "FILE-SERVER": "SERVER", "SIEM": "SERVER", "SOC": "SERVER",
    "WORKSTATION": "ENDPOINT", "WS": "ENDPOINT", "PC": "ENDPOINT",
    "LAPTOP": "ENDPOINT", "CLIENT": "ENDPOINT", "HOST": "ENDPOINT",
    "CLOUD-VM": "CLOUD", "SAAS": "CLOUD", "IAAS": "CLOUD",
    "WAN": "INTERNET", "PUBLIC": "INTERNET",
    "ADVERSARY": "ATTACKER", "RED-TEAM": "ATTACKER", "C2": "ATTACKER",
}


def _canon(device_type: Any) -> str:
    """Normalize an arbitrary device-type string to a canonical KB key."""
    if not device_type:
        return ""
    key = str(device_type).strip().upper().replace(" ", "-")
    if key in _KB:
        return key
    if key in _ALIASES:
        return _ALIASES[key]
    # Substring fallback: e.g. "EDGE-ROUTER-01" -> ROUTER.
    for canon in _KB:
        if canon in key:
            return canon
    for alias, canon in _ALIASES.items():
        if alias in key:
            return canon
    return ""


def get_dossier_knowledge(device_type: Any) -> dict[str, Any]:
    """Return the educational knowledge dict for a device type.

    Always returns a complete, JSON-safe shape: any field absent from the
    specific entry inherits the generic default, so the renderer never has to
    null-check. Unknown types fall back to the generic profile.
    """
    entry = _KB.get(_canon(device_type), {})
    merged: dict[str, Any] = {}
    for field, default in _GENERIC.items():
        merged[field] = entry.get(field, default)
    merged["matched_type"] = _canon(device_type) or "GENERIC"
    return merged


def known_types() -> list[str]:
    """Canonical device types covered by the knowledge base (for tests/UI)."""
    return sorted(_KB.keys())
