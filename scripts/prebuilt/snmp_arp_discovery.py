from __future__ import annotations

"""
snmp_arp_discovery.py

Prebuilt script: pull ARP tables from one or more routers/switches via SNMP
and populate the Device table. Designed for personal / lab use to quickly
build an inventory for a given "zone" or segment.

Parameters (ctx.params):

{
  "targets": ["192.168.124.1"],
  "community": "public",
  "zone": "home-router-1"
}

This script assumes SNMPv2c and that the backend environment has access to
the routers/switches and the appropriate community string. It reads the table
through the in-repo SNMPv2c client (app.services.snmp_client), the same one
router discovery uses, so no extra package has to be installed.

Devices are inserted/updated by IP address; MAC, vendor and zone are
populated where possible.
"""

from typing import Any, Iterable, List, Optional, Tuple

from sqlalchemy import select

from app.db.session import async_session_factory
from app.services import snmp_client
from app.models.device import Device


def _walk_arp_table(
    target_ip: str,
    community: str,
    timeout: int = 2,
    retries: int = 1,
) -> List[Tuple[str, str]]:
    """
    Walk the ARP table via SNMP and return a list of (ip, mac) tuples.

    Uses ipNetToMediaPhysAddress / ipNetToMediaNetAddress OIDs read through
    app.services.snmp_client. This previously went through pysnmp, which is
    not a dependency of this project, so the script raised ImportError before
    it ever queried a router.
    """
    # ipNetToMediaPhysAddress: 1.3.6.1.2.1.4.22.1.2
    # ipNetToMediaNetAddress: 1.3.6.1.2.1.4.22.1.3
    phys_oid = "1.3.6.1.2.1.4.22.1.2"
    net_oid = "1.3.6.1.2.1.4.22.1.3"
    kwargs = {"community": community, "timeout": timeout, "retries": retries}

    # Raise SnmpError when the agent cannot be reached at all: run() reports
    # that per target, which is better than claiming an empty ARP table.
    phys = snmp_client.walk(target_ip, phys_oid, **kwargs)
    net = snmp_client.walk(target_ip, net_oid, **kwargs)

    def _suffix(oid: str, root: str) -> Optional[str]:
        prefix = f"{root}."
        return oid[len(prefix) :] if oid.startswith(prefix) else None

    # Join the two columns on their shared table index. Matching on the walked
    # root, not on ".1.2." appearing anywhere in the OID, keeps the join
    # correct: the base OID itself contains it, and so does 10.0.2.15.
    macs: dict[str, str] = {}
    for oid, value in phys:
        key = _suffix(oid, phys_oid)
        mac = snmp_client.mac_to_str(value)
        if key is not None and mac:
            macs[key] = mac

    results: List[Tuple[str, str]] = []
    for oid, value in net:
        key = _suffix(oid, net_oid)
        ip = snmp_client.to_ip(value)
        if key is None or not ip:
            continue
        mac = macs.get(key)
        if mac:
            results.append((ip, mac))

    return results


async def _upsert_devices(
    entries: Iterable[Tuple[str, str]],
    zone: Optional[str],
    router_ip: str,
    logger,
) -> int:
    """
    Insert or update Device rows from ARP entries.
    """
    count = 0
    async with async_session_factory() as session:
        for ip, mac in entries:
            # Skip the router itself; it will typically be added separately.
            if ip == router_ip:
                continue

            result = await session.execute(select(Device).where(Device.ip_address == ip))
            device = result.scalar_one_or_none()
            if device is None:
                device = Device(ip_address=ip)
                session.add(device)

            device.mac_address = mac
            if zone:
                device.zone = zone
            count += 1

        await session.commit()
    return count


def run(ctx: Any) -> dict:
    """
    Entry point for the NetPulse script engine.

    ctx.params should contain:
      - targets: list of router/switch IPs
      - community: SNMP community string (default 'public')
      - zone: optional string label for these devices (e.g. 'home-router-1')
    """
    params = getattr(ctx, "params", {}) or {}
    targets = params.get("targets") or []
    if isinstance(targets, str):
        targets = [targets]
    community = params.get("community", "public")
    zone = params.get("zone")

    if not targets:
        raise ValueError("snmp_arp_discovery: 'targets' (router IPs) are required")

    total_devices = 0
    results: list[dict] = []

    for router_ip in targets:
        ctx.logger(f"snmp_arp_discovery: querying ARP table from {router_ip} ...")
        try:
            entries = _walk_arp_table(router_ip, community)
            ctx.logger(f"snmp_arp_discovery: {len(entries)} ARP entries from {router_ip}")
            count = ctx.loop.run_until_complete(_upsert_devices(entries, zone, router_ip, ctx.logger))  # type: ignore[attr-defined]
            total_devices += count
            results.append({"router": router_ip, "entries": len(entries), "upserts": count})
        except Exception as exc:
            ctx.logger(f"snmp_arp_discovery: error talking to {router_ip}: {exc}")
            results.append({"router": router_ip, "error": str(exc)})

    return {"status": "completed", "devices_updated": total_devices, "results": results}