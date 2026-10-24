"""Identify the network this host is currently attached to.

Why this exists
---------------
Home networks reuse the same addressing: several houses all run
``192.168.1.0/24`` with the router at ``192.168.1.1``. Keying the device
inventory by IP alone therefore fuses those networks together — the second
house's ``192.168.1.10`` overwrites the first one's row, and its MAC/hostname
land on a device that never had them.

The fingerprint below adds the gateway's hardware address, which differs per
router, so each network becomes its own row that the operator can name and
switch between. Devices are scoped to that row.

Detection is best-effort by design: without root or an ARP table the gateway
MAC is unavailable, and the subnet is then used alone. Two networks that share
*and* hide their gateway MAC look identical — nothing on the host can tell
them apart — which is why the name is editable rather than automatic.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select

from app.models.network import Network
from app.services.oui import lookup_vendor, normalize_mac

logger = logging.getLogger("netpulse.network")

# Re-detection cost is one ``ip neigh``/``arp`` call, but discovery sweeps run
# often; a minute of caching keeps that off the hot path without hiding a move
# to another network for long.
CACHE_TTL_SECONDS = 60.0

_MAC_PATTERN = re.compile(
    r"([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})"
)
_IPV4_PATTERN = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")


@dataclass(frozen=True)
class NetworkProfile:
    """What the host can observe about the network it sits on."""

    cidr: str
    gateway_ip: Optional[str]
    gateway_mac: Optional[str]
    interface: Optional[str]

    @property
    def key(self) -> str:
        mac = (self.gateway_mac or "-").upper()
        return f"{self.cidr or '-'}|{mac}"

    @property
    def default_name(self) -> str:
        label = self.cidr or self.gateway_ip or "Unknown network"
        vendor = lookup_vendor(self.gateway_mac) if self.gateway_mac else None
        return f"{vendor} · {label}" if vendor else label


def format_mac(mac: Optional[str]) -> Optional[str]:
    """Render a stored compact MAC (``AABBCCDDEEFF``) as ``aa:bb:cc:dd:ee:ff``."""
    if not mac:
        return None
    compact = re.sub(r"[^0-9a-fA-F]", "", mac).upper()
    if len(compact) != 12:
        return mac
    return ":".join(compact[i : i + 2] for i in range(0, 12, 2)).lower()


def _run(command: list[str]) -> str:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return completed.stdout or ""
    except Exception:
        return ""


def detect_gateway_ip() -> Optional[str]:
    """Default gateway address, without the ``192.168.1.1`` guess config uses."""
    try:
        with open("/proc/net/route", "r") as handle:
            for line in handle.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == "00000000":
                    value = int(parts[2], 16)
                    return ".".join(str((value >> shift) & 0xFF) for shift in (0, 8, 16, 24))
    except Exception:
        pass

    match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", _run(["ip", "route", "show", "default"]))
    if match:
        return match.group(1)

    if sys.platform.startswith("win"):
        match = re.search(
            r"Default Gateway[ .]*:\s*(\d+\.\d+\.\d+\.\d+)",
            _run(["ipconfig"]),
        )
        if match:
            return match.group(1)
        # Numeric table as a fallback: ipconfig's labels are localised.
        for line in _run(["route", "print", "0.0.0.0"]).splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                if _IPV4_PATTERN.fullmatch(parts[2]):
                    return parts[2]

    if sys.platform == "darwin":
        match = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", _run(["route", "-n", "get", "default"]))
        if match:
            return match.group(1)

    return None


def _neighbour_mac(ip: str) -> Optional[str]:
    if sys.platform.startswith("linux"):
        output = _run(["ip", "neigh", "show", ip])
    elif sys.platform.startswith("win"):
        output = _run(["arp", "-a", ip])
    else:
        output = _run(["arp", "-n", ip])

    match = _MAC_PATTERN.search(output)
    return normalize_mac(match.group(1)) if match else None


def _poke_arp(ip: str) -> None:
    """Make the kernel resolve ``ip`` so the neighbour table has its MAC."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.5)
            sock.connect((ip, 53))
            sock.send(b"\x00")
    except Exception:
        pass


def _attached_subnets() -> tuple[list[str], Optional[str]]:
    try:
        # Imported lazily: it pulls scapy, which is only needed down here.
        from app.services.device_discovery import local_subnets

        return local_subnets(None)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("Subnet detection unavailable: %s", exc)
        return [], None


def detect_profile() -> Optional[NetworkProfile]:
    """Read the current network off the host. Returns ``None`` when unknowable."""
    subnets, interface = _attached_subnets()
    gateway_ip = detect_gateway_ip()

    cidr = subnets[0] if subnets else ""
    if gateway_ip and subnets:
        try:
            gateway = ipaddress.ip_address(gateway_ip)
            for candidate in subnets:
                if gateway in ipaddress.ip_network(candidate, strict=False):
                    cidr = candidate
                    break
        except ValueError:
            pass

    gateway_mac = _neighbour_mac(gateway_ip) if gateway_ip else None
    if gateway_ip and not gateway_mac:
        _poke_arp(gateway_ip)
        time.sleep(0.2)
        gateway_mac = _neighbour_mac(gateway_ip)

    if not cidr and not gateway_ip:
        return None

    return NetworkProfile(
        cidr=cidr,
        gateway_ip=gateway_ip,
        gateway_mac=gateway_mac,
        interface=interface,
    )


_cached: Optional[tuple[float, Optional[NetworkProfile]]] = None
_id_cache: Optional[tuple[float, Optional[int]]] = None


def current_profile(*, refresh: bool = False) -> Optional[NetworkProfile]:
    global _cached
    now = time.monotonic()
    if not refresh and _cached is not None and now - _cached[0] < CACHE_TTL_SECONDS:
        return _cached[1]
    profile = detect_profile()
    _cached = (now, profile)
    return profile


def invalidate_cache() -> None:
    """Forget the detected profile (used by the API and by tests)."""
    global _cached, _id_cache
    _cached = None
    _id_cache = None


def _is_stale(value: Optional[datetime], seconds: float) -> bool:
    if value is None:
        return True
    try:
        return (datetime.now(timezone.utc) - value).total_seconds() > seconds
    except TypeError:
        # Timestamps written as naive by an older row: rewrite them as aware.
        return True


async def resolve_current_network(db: Any, *, refresh: bool = False) -> Optional[Network]:
    """Return the ``Network`` row for the network this host is on, creating it once."""
    profile = await asyncio.to_thread(current_profile, refresh=refresh)
    if profile is None:
        return None

    result = await db.execute(select(Network).where(Network.key == profile.key))
    network = result.scalar_one_or_none()
    now = datetime.now(timezone.utc)

    if network is None:
        network = Network(
            key=profile.key,
            name=profile.default_name,
            cidr=profile.cidr,
            gateway_ip=profile.gateway_ip,
            gateway_mac=profile.gateway_mac,
            interface=profile.interface,
            first_seen=now,
            last_seen=now,
        )
        db.add(network)
        await db.commit()
        await db.refresh(network)
        logger.info(
            "New network recorded as #%s '%s' (%s, gateway %s%s)",
            network.id,
            network.name,
            profile.cidr or "unknown subnet",
            profile.gateway_ip or "unknown",
            f" / {format_mac(profile.gateway_mac)}" if profile.gateway_mac else "",
        )
        return network

    # Refresh what the host observes, but never overwrite the operator's name.
    changed = False
    for attribute, value in (
        ("cidr", profile.cidr),
        ("gateway_ip", profile.gateway_ip),
        ("gateway_mac", profile.gateway_mac),
        ("interface", profile.interface),
    ):
        if value and getattr(network, attribute) != value:
            setattr(network, attribute, value)
            changed = True

    # ``last_seen`` is a heartbeat, not a fact worth a write on every call: the
    # NetFlow collector resolves the network for each record.
    if _is_stale(network.last_seen, CACHE_TTL_SECONDS):
        network.last_seen = now
        changed = True

    if changed:
        await db.commit()
    return network


async def current_network_id(db: Any) -> Optional[int]:
    """The id of the current network, tagged onto devices as they are recorded.

    Cached like the profile: discovery, NetFlow and passive sweeps all ask for
    it, and only the fingerprint has to be re-read every minute.
    """
    global _id_cache
    now = time.monotonic()
    if _id_cache is not None and now - _id_cache[0] < CACHE_TTL_SECONDS:
        return _id_cache[1]

    network = await resolve_current_network(db)
    _id_cache = (now, network.id if network is not None else None)
    return _id_cache[1]
