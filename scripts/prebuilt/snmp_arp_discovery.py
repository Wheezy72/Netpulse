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
the routers/switches and the appropriate community string. It uses pysnmp,
which must be installed in the Python environment used by the worker:

  pip install pysnmp

Devices are inserted/updated by IP address; MAC, vendor and zone are
populated where possible.
"""

from typing import Any, Iterable, List, Optional, Tuple

from pysnmp.hlapi import (  # type: ignore[import-untyped]
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    bulkCmd,
)
from sqlalchemy import select

from app.db.session import async_session_factory
from app.models.device import Device


def _walk_arp_table(
    target_ip: str,
    community: str,
    timeout: int = 2,
    retries: int = 1,
) -> List[Tuple[str, str]]:
    """
    Walk the ARP table via SNMP and return a list of (ip, mac) tuples.

    Uses ipNetToMediaPhysAddress / ipNetToMediaNetAddress OIDs.
    """
    engine = SnmpEngine()
    community_data = CommunityData(community)
    transport = UdpTransportTarget((target_ip, 161), timeout=timeout, retries=retries)
    context = ContextData()

    # ipNetToMediaPhysAddress: 1.3.6.1.2.1.4.22.1.2
    # ipNetToMediaNetAddress: 1.3.6.1.2.1.4.22.1.3
    phys_oid = ObjectIdentity("1.3.6.1.2.1.4.22.1.2")
    net_oid = ObjectIdentity("1.3.6.1.2.1.4.22.1.3")

    # We'll walk both and correlate by index suffix
    phys_table: dict[str, str] = {}
    net_table: dict[str, str] = {}

    # Walk phys
    for errorIndication, errorStatus, errorIndex, varBinds in bulkCmd(
        engine,
        community_data,
        transport,
        context,
        0,
        25,
        ObjectType(phys_oid),
        lexicographicMode=False,
    ):
        if errorIndication or errorStatus:
            break
        for varBind in varBinds:
            oid_str = str(varBind[0])
            value = varBind[1]
            suffix = oid_str.split(".1.2.", 1)[-1]
            mac = ":".join(f"{b:02x}" for b in bytes(value))
            phys_table[suffix] = mac

    # Walk net
    for errorIndication, errorStatus, errorIndex, varBinds in bulkCmd(
        engine,
        community_data,
        transport,
        context,
        0,
        25,
        ObjectType(net_oid),
        lexicographicMode=False,
    ):
        if errorIndication or errorStatus:
            break
        for varBind in varBinds:
            oid_str = str(varBind[0])
            value = varBind[1]
            suffix = oid_str.split(".1.3.", 1)[-1]
            ip = str(value)
            net_table[suffix] = ip

    results: List[Tuple[str, str]] = []
    for suffix, mac in phys_table.items():
        ip = net_table.get(suffix)
        if ip and mac:
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