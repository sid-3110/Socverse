"""
config/ip_plan.py
Enterprise IP addressing and VLAN plan (RFC1918).
Single source of truth for subnets, gateways, and segmentation.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VlanPlan:
    """A Layer-2/3 segment definition."""

    vlan_id: int
    name: str
    cidr: str          # e.g. "10.10.10.0/24"
    gateway: str       # first usable address
    description: str
    color: str = "#3b82f6"


# --------------------------------------------------------------------------- #
# Public / edge addressing
# --------------------------------------------------------------------------- #
PUBLIC_RANGES: dict[str, str] = {
    "internet":    "0.0.0.0/0",
    "isp_uplink":  "203.0.113.0/30",   # TEST-NET-3 (safe documentation range)
    "edge_public": "198.51.100.10/29", # NGFW public side
}

# --------------------------------------------------------------------------- #
# Internal VLAN segmentation
# --------------------------------------------------------------------------- #
VLANS: dict[str, VlanPlan] = {
    "dmz":     VlanPlan(20,  "DMZ",       "172.16.20.0/24", "172.16.20.1",
                        "Public-facing servers (web, mail, DNS)", "#f59e0b"),
    "hr":      VlanPlan(110, "HR",        "10.10.110.0/24", "10.10.110.1",
                        "Human Resources workstations", "#22c55e"),
    "finance": VlanPlan(120, "Finance",   "10.10.120.0/24", "10.10.120.1",
                        "Finance workstations (high value)", "#ef4444"),
    "it":      VlanPlan(130, "IT",        "10.10.130.0/24", "10.10.130.1",
                        "IT administration", "#3b82f6"),
    "soc":     VlanPlan(140, "SOC",       "10.10.140.0/24", "10.10.140.1",
                        "Security Operations Center / SIEM", "#22d3ee"),
    "guest":   VlanPlan(199, "Guest",     "192.168.99.0/24", "192.168.99.1",
                        "Untrusted guest Wi-Fi", "#8b98a9"),
    "servers": VlanPlan(200, "Servers",   "10.20.200.0/24", "10.20.200.1",
                        "Internal server farm (AD, file, app)", "#a855f7"),
}

# --------------------------------------------------------------------------- #
# Remote access
# --------------------------------------------------------------------------- #
VPN_POOL: str = "10.99.0.0/24"          # VPN client pool
CLOUD_VPC: str = "10.50.0.0/16"         # Cloud VPC supernet


def get_vlan(name: str) -> VlanPlan:
    """Lookup helper with a clear error for typos."""
    try:
        return VLANS[name]
    except KeyError as exc:
        raise KeyError(f"Unknown VLAN '{name}'. Valid: {list(VLANS)}") from exc