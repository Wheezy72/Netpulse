"""Finding and removing the device rows a proxy-ARP router invented.

A hotspot or a router doing proxy ARP answers for addresses it does not own, so
one sweep reports a whole /24 as "hosts" that all share its MAC address.
Discovery now collapses that fan-out (``collapse_proxy_arp`` in
``app/services/device_discovery.py``), but rows written before it existed stay
in the inventory: the console shows 255 nodes, the topology map has one dot in
the middle, and every count is wrong.

This module is the single implementation behind both the maintenance script
and the System tab: it decides which rows are phantom and deletes them, keeping
the lowest address of each shared MAC — the router's own address in the layout
that produces this. The threshold matches discovery, so only rows the scanner
would refuse to write today are touched. A machine with several NICs has a
different MAC per address and a NAT router with a handful of extra addresses
stays under the limit, so neither is affected.
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.device import Device
from app.models.device_port import DevicePort
from app.models.metric import Metric
from app.models.script_job import ScriptJob
from app.models.vulnerability import Vulnerability

# Same threshold as PROXY_ARP_ADDRESS_LIMIT in app/services/device_discovery.py.
DEFAULT_LIMIT = 8


@dataclass(frozen=True)
class Clump:
    """One MAC answering for too many addresses on one network."""

    network_id: int | None
    mac: str
    keep_id: int
    keep_ip: str
    keep_hostname: str | None
    keep_is_gateway: bool
    delete_ids: tuple[int, ...]
    first_dropped: str | None
    last_dropped: str | None

    @property
    def rows(self) -> int:
        """How many rows the clump holds, counting the one that stays."""
        return len(self.delete_ids) + 1


def _ip_key(address: str) -> tuple:
    """Order addresses numerically, falling back to text for odd input."""
    try:
        return (0, int(ipaddress.ip_address(address)))
    except ValueError:
        return (1, address)


def _normalise(mac: str | None) -> str | None:
    """MACs are written in several cases by different sources."""
    if not mac:
        return None
    cleaned = mac.strip().upper().replace("-", ":")
    return cleaned or None


def plan_purge(
    rows: Iterable[Sequence[Any]],
    limit: int = DEFAULT_LIMIT,
) -> list[Clump]:
    """Group device rows by MAC and return the ones over *limit*.

    *rows* are ``(id, network_id, mac_address, ip_address, hostname,
    is_gateway)`` sequences. Grouping is per network: five homes can all run
    192.168.1.10, and a MAC seen in two of them is two separate questions.
    """
    if limit < 1:
        raise ValueError("limit must be at least 1")

    grouped: dict[tuple[int | None, str], list[tuple]] = defaultdict(list)
    for device_id, network_id, mac, ip_address, hostname, is_gateway in rows:
        normalised = _normalise(mac)
        if normalised is None:
            continue
        grouped[(network_id, normalised)].append(
            (device_id, ip_address, hostname, bool(is_gateway))
        )

    clumps: list[Clump] = []
    for (network_id, mac), members in grouped.items():
        if len(members) <= limit:
            continue
        ordered = sorted(members, key=lambda member: (_ip_key(member[1]), member[0]))
        keep_id, keep_ip, keep_hostname, keep_is_gateway = ordered[0]
        dropped = ordered[1:]
        addresses = [member[1] for member in dropped]
        clumps.append(
            Clump(
                network_id=network_id,
                mac=mac,
                keep_id=keep_id,
                keep_ip=keep_ip,
                keep_hostname=keep_hostname,
                keep_is_gateway=keep_is_gateway,
                delete_ids=tuple(member[0] for member in dropped),
                first_dropped=min(addresses, key=_ip_key) if addresses else None,
                last_dropped=max(addresses, key=_ip_key) if addresses else None,
            )
        )

    clumps.sort(key=lambda clump: (clump.network_id is None, clump.network_id or 0, clump.mac))
    return clumps


async def scan(
    session: AsyncSession,
    *,
    limit: int = DEFAULT_LIMIT,
    network_id: int | None = None,
) -> tuple[list[Clump], int]:
    """Read the inventory and return ``(clumps, rows_inspected)``.

    Read-only: safe to call from a preview that only reports what it found.
    """
    query = select(
        Device.id,
        Device.network_id,
        Device.mac_address,
        Device.ip_address,
        Device.hostname,
        Device.is_gateway,
    ).order_by(Device.id)
    if network_id is not None:
        query = query.where(Device.network_id == network_id)

    rows = (await session.execute(query)).all()
    return plan_purge(rows, limit), len(rows)


async def apply(session: AsyncSession, clumps: Sequence[Clump]) -> int:
    """Delete every row in *clumps* except the one each clump keeps.

    Children go first. Metrics and vulnerabilities point at the device with no
    ``ON DELETE`` action, so the database would refuse the parent delete until
    they are gone; ports cascade but are removed explicitly for the same
    reason, and script jobs are kept while losing their device link, because a
    run that happened is history and an address that never existed is not worth
    keeping a pointer to.
    """
    doomed = [device_id for clump in clumps for device_id in clump.delete_ids]
    if not doomed:
        return 0

    await session.execute(delete(Metric).where(Metric.device_id.in_(doomed)))
    await session.execute(delete(Vulnerability).where(Vulnerability.device_id.in_(doomed)))
    await session.execute(delete(DevicePort).where(DevicePort.device_id.in_(doomed)))
    await session.execute(
        update(ScriptJob).where(ScriptJob.device_id.in_(doomed)).values(device_id=None)
    )
    result = await session.execute(delete(Device).where(Device.id.in_(doomed)))
    await session.commit()

    if result.rowcount is not None and result.rowcount >= 0:
        return int(result.rowcount)
    return len(doomed)
