"""Active-scan policy: which targets may receive active probes.

Restricted / fragile VLANs (for example a medical or OT segment) must never be
actively probed — passive observation only. Both the nmap pipeline and the
device discovery service funnel their target validation through this module so
that the rule lives in exactly one place instead of being re-implemented per
caller.

Only ``app.core.config`` (pydantic-settings) is imported, so this module stays
importable in the minimal CI test environment.
"""
from __future__ import annotations

import ipaddress
from typing import Iterable, List, Set, Union

from app.core.config import settings

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

# Characters that would let a target string escape its single argv slot.
_SHELL_METACHARACTERS = (";", "|", "&", "`", "$", "\n", "\r")


def restricted_vlan_cidrs() -> Set[str]:
    """Configured restricted CIDRs.

    Merges the current ``restricted_vlan_cidrs`` setting with the legacy
    ``medical_iot_vlan_cidrs`` name so existing deployments keep working.
    """
    cidrs: Set[str] = {c for c in (settings.restricted_vlan_cidrs or []) if c}
    cidrs.update(c for c in (settings.medical_iot_vlan_cidrs or []) if c)
    return cidrs


def parse_target_address(target: str) -> IPAddress | None:
    """Parse the host part of a target (``10.0.0.0/24`` → ``10.0.0.0``).

    Returns None for hostnames and anything unparseable — callers decide how
    to treat a target they cannot classify statically.
    """
    if not target:
        return None
    try:
        return ipaddress.ip_address(target.strip().split("/")[0])
    except ValueError:
        return None


def is_restricted_target(target: str) -> bool:
    """True when *target* sits inside a restricted/fragile CIDR.

    Hostnames cannot be classified statically and therefore return False;
    operators must keep restricted segments unreachable by name at the network
    layer.
    """
    address = parse_target_address(target)
    if address is None:
        return False

    for cidr in restricted_vlan_cidrs():
        try:
            if address in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            # A malformed CIDR in configuration must not block all scanning.
            continue
    return False


def validate_target(target: str) -> bool:
    """Basic safety check for a user-supplied target.

    Accepts an IP, a CIDR, or a hostname. Rejects empty input, whitespace,
    leading-dash (flag smuggling) and shell metacharacters. nmap receives the
    target as its own argv entry, so this is defence in depth rather than the
    only guard.
    """
    target = (target or "").strip()
    if not target or len(target) > 255:
        return False
    if any(ch.isspace() for ch in target):
        return False
    if target.startswith("-"):
        return False
    return not any(bad in target for bad in _SHELL_METACHARACTERS)


def subnets_to_sweep(
    candidates: Iterable[str],
    *,
    max_prefix_length: int = 20,
) -> List[str]:
    """Filter attached subnets down to ones small enough to sweep actively.

    A /20 (4094 hosts) is the widest a background discovery sweep may go, and
    restricted ranges are dropped here too so no caller can forget the check.
    """
    usable: List[str] = []
    for candidate in candidates:
        try:
            network = ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            continue
        if network.prefixlen < max_prefix_length:
            continue
        if is_restricted_target(str(network)):
            continue
        usable.append(str(network))
    return usable
