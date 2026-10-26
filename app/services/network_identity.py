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

from sqlalchemy import func, select

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
        """Stable identity for this network.

        The gateway's MAC is the only value that survives a re-detect: subnet
        detection fails whenever scapy cannot enumerate interfaces (packet
        capture driver stopped, no privileges), and the old ``cidr|mac`` key
        then produced a *second* row for the same router — the duplicate
        "192.168.1.1 / unknown subnet" entry next to the real one.
        """
        if self.gateway_mac:
            return f"mac:{self.gateway_mac.upper()}"
        if self.cidr:
            return f"cidr:{self.cidr}"
        return f"gw:{self.gateway_ip}"

    @property
    def legacy_keys(self) -> list[str]:
        """Keys rows may still carry from before the identity change."""
        keys = [f"{self.cidr or '-'}|{(self.gateway_mac or '-').upper()}"]
        if self.gateway_ip and self.gateway_mac:
            keys.append(f"{self.gateway_ip}|{self.gateway_mac.upper()}")
        return keys

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


async def _find_network(db: Any, profile: NetworkProfile) -> Optional[Network]:
    """Locate the row for *profile*, tolerating keys from older versions."""
    network = (
        await db.execute(select(Network).where(Network.key == profile.key))
    ).scalar_one_or_none()
    if network is not None:
        return network

    # Rows written before the key changed. Adopting them in place is what keeps
    # the inventory attached to one row per network instead of growing a new
    # one every time the key formula moves.
    for legacy in profile.legacy_keys:
        legacy_row = (
            await db.execute(select(Network).where(Network.key == legacy))
        ).scalar_one_or_none()
        if legacy_row is not None:
            return legacy_row

    # The gateway's hardware address identifies the router even when the subnet
    # could not be read, which is exactly how duplicates were created.
    if profile.gateway_mac:
        return (
            await db.execute(
                select(Network)
                .where(func.upper(Network.gateway_mac) == profile.gateway_mac.upper())
                .order_by(Network.first_seen)
            )
        ).scalars().first()

    return None


async def fold_network_devices(db: Any, keep_id: int, dup_id: int) -> int:
    """Move *dup_id*'s devices onto *keep_id*, merging rows that share an IP.

    A plain ``UPDATE ... SET network_id`` is not enough: two rows for the same
    network can each hold a device at the same address, and ``devices`` is
    unique on ``(network_id, ip_address)`` — the update then fails with a
    UniqueViolation. Same address on the same network is one machine, so the
    two rows are folded: blanks are filled from whichever row has the value,
    verification and ``last_seen`` are combined, and one row is deleted.

    Returns the number of device rows that were merged away.
    """
    from sqlalchemy import delete as sa_delete
    from sqlalchemy import select
    from sqlalchemy import update as sa_update

    from app.models.device import Device
    from app.models.script_job import ScriptJob

    keep_rows = {
        row.ip_address: row
        for row in (
            await db.execute(select(Device).where(Device.network_id == keep_id))
        ).scalars().all()
    }
    dup_rows = list(
        (await db.execute(select(Device).where(Device.network_id == dup_id)))
        .scalars()
        .all()
    )

    merged = 0
    for row in dup_rows:
        twin = keep_rows.get(row.ip_address)
        if twin is None:
            row.network_id = keep_id
            continue

        await _absorb_device(db, twin, row)
        merged += 1

    return merged


async def _absorb_device(db: Any, keep: Any, drop: Any) -> None:
    """Merge *drop* into *keep* and delete it. Both are rows for one address."""
    from sqlalchemy import delete as sa_delete
    from sqlalchemy import update as sa_update

    from app.models.device import Device
    from app.models.script_job import ScriptJob

    merge_device_details(keep, drop)

    # script_jobs holds an FK without ON DELETE CASCADE.
    await db.execute(sa_update(ScriptJob).where(ScriptJob.device_id == drop.id).values(device_id=keep.id))
    await db.execute(sa_delete(Device).where(Device.id == drop.id))


def merge_device_details(keep: Any, drop: Any) -> None:
    """Fold *drop*'s known facts into *keep* in place (no I/O).

    Two rows for one address means one machine seen twice: whichever row holds
    the fact wins, and nothing that was verified or seen more recently is lost
    when the redundant row goes away.
    """
    for attribute in ("hostname", "mac_address", "vendor", "device_type", "os", "zone"):
        if not getattr(keep, attribute) and getattr(drop, attribute):
            setattr(keep, attribute, getattr(drop, attribute))
    if drop.verified and not keep.verified:
        keep.verified = True
        keep.verified_at = drop.verified_at
        keep.verified_source = drop.verified_source
    if drop.last_seen and (keep.last_seen is None or drop.last_seen > keep.last_seen):
        keep.last_seen = drop.last_seen
    keep.is_gateway = bool(keep.is_gateway or drop.is_gateway)


async def adopt_orphan_devices(db: Any, network: Network) -> int:
    """Attach devices recorded before networks existed to *network*.

    ``UPDATE devices SET network_id = ...`` is what a plain adoption wants, but
    it fails whenever an orphan shares an address with a row already on this
    network: ``uq_devices_network_ip`` then rejects the whole statement, and
    the boot logged a UniqueViolation instead of adopting anything. Orphans
    without a twin are repointed; orphans with one are folded into it.

    Returns the number of rows that now live on *network* as a result.
    """
    from sqlalchemy import select

    from app.models.device import Device

    orphans = list(
        (await db.execute(select(Device).where(Device.network_id.is_(None)))).scalars().all()
    )
    if not orphans:
        return 0

    existing = {
        row.ip_address: row
        for row in (
            await db.execute(select(Device).where(Device.network_id == network.id))
        ).scalars().all()
    }

    adopted = 0
    for row in orphans:
        twin = existing.get(row.ip_address)
        if twin is None:
            row.network_id = network.id
            existing[row.ip_address] = row
            adopted += 1
            continue
        logger.info(
            "Folding pre-network device row #%s %s into #%s.",
            row.id,
            row.ip_address,
            twin.id,
        )
        await _absorb_device(db, twin, row)

    await db.commit()
    return adopted


async def _merge_duplicates(db: Any, keep: Network, profile: NetworkProfile) -> None:
    """Fold other rows describing this same router into *keep*.

    Same gateway MAC means the same network no matter what the subnet read as
    on the sweep that created the row. Duplicates carry devices, so they are
    repointed rather than dropped.
    """
    if not profile.gateway_mac:
        return

    from sqlalchemy import delete as sa_delete

    duplicates = list(
        (
            await db.execute(
                select(Network).where(
                    func.upper(Network.gateway_mac) == profile.gateway_mac.upper(),
                    Network.id != keep.id,
                )
            )
        ).scalars().all()
    )
    if not duplicates:
        return

    for dup in duplicates:
        merged = await fold_network_devices(db, keep.id, dup.id)
        if merged:
            logger.info(
                "Folded %d duplicate device row(s) from network #%s into #%s.",
                merged,
                dup.id,
                keep.id,
            )
        if dup.first_seen and (keep.first_seen is None or dup.first_seen < keep.first_seen):
            keep.first_seen = dup.first_seen
        logger.info(
            "Merging duplicate network #%s '%s' (cidr=%r) into #%s '%s' — same gateway %s.",
            dup.id,
            dup.name,
            dup.cidr,
            keep.id,
            keep.name,
            format_mac(profile.gateway_mac),
        )
        await db.execute(sa_delete(Network).where(Network.id == dup.id))


async def resolve_current_network(db: Any, *, refresh: bool = False) -> Optional[Network]:
    """Return the ``Network`` row for the network this host is on, creating it once."""
    profile = await asyncio.to_thread(current_profile, refresh=refresh)
    if profile is None:
        return None

    network = await _find_network(db, profile)
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
    if network.key != profile.key:
        # Old or transient key (see NetworkProfile.key): adopt the stable one.
        network.key = profile.key
        changed = True
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

    await _merge_duplicates(db, network, profile)
    if changed or network.id is not None:
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
