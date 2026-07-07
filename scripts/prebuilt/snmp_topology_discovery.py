from __future__ import annotations

"""
snmp_topology_discovery.py

Prebuilt script: queries switches and routers via SNMP to discover neighbor
connections using CDP (Cisco Discovery Protocol) and LLDP (Link Layer Discovery
Protocol). Discovered connections are stored as time-series metrics to construct
the network map.

Parameters (ctx.params):
{
  "targets": ["192.168.124.1", "192.168.124.2"],
  "community": "public"
}
"""

import socket
from datetime import datetime
from typing import Any, Dict, List, Set, Tuple

try:
    from pysnmp.hlapi import (  # type: ignore[import-untyped]
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        bulkCmd,
    )
except ImportError as exc:
    raise RuntimeError(
        "pysnmp is required to run snmp_topology_discovery.py. "
        "Install it in the worker image (e.g. pip install pysnmp)."
    ) from exc

from sqlalchemy import select
from app.db.session import async_session_factory
from app.models.device import Device
from app.models.metric import Metric


def _snmp_walk(
    target_ip: str,
    community: str,
    oid_str: str,
    timeout: int = 2,
    retries: int = 1,
) -> List[Tuple[str, Any]]:
    """Perform a bulk SNMP walk on a given target IP and return (oid, value) tuples."""
    results = []
    try:
        engine = SnmpEngine()
        community_data = CommunityData(community)
        transport = UdpTransportTarget((target_ip, 161), timeout=timeout, retries=retries)
        context = ContextData()
        oid = ObjectIdentity(oid_str)

        for errorIndication, errorStatus, errorIndex, varBinds in bulkCmd(
            engine,
            community_data,
            transport,
            context,
            0,
            25,
            ObjectType(oid),
            lexicographicMode=False,
        ):
            if errorIndication or errorStatus:
                break
            for varBind in varBinds:
                results.append((str(varBind[0]), varBind[1]))
    except Exception:
        pass
    return results


def _ip_bytes_to_str(val: Any) -> str | None:
    """Parse raw bytes representing an IP address from SNMP response."""
    try:
        if isinstance(val, bytes) and len(val) == 4:
            return ".".join(str(b) for b in val)
        # Sometimes SNMP returns as a string with raw hex or integers
        val_str = str(val)
        if len(val_str.split(".")) == 4:
            return val_str
    except Exception:
        pass
    return None


async def _save_links(links: Set[Tuple[str, str, str]]) -> int:
    """Save topology links into the database as metrics."""
    async with async_session_factory() as session:
        # First, delete old topology_link metrics to avoid duplicates and stale paths
        try:
            from sqlalchemy import text
            await session.execute(text("DELETE FROM metrics WHERE metric_type = 'topology_link'"))
        except Exception:
            pass

        count = 0
        for src_ip, tgt_ip, kind in links:
            # Get device IDs if possible for association
            src_result = await session.execute(select(Device.id).where(Device.ip_address == src_ip))
            src_id = src_result.scalar_one_or_none()

            metric = Metric(
                device_id=src_id,
                timestamp=datetime.utcnow(),
                metric_type="topology_link",
                value=1.0,
                tags={
                    "source_ip": src_ip,
                    "target_ip": tgt_ip,
                    "kind": kind,
                    "discovered_at": datetime.utcnow().isoformat()
                }
            )
            session.add(metric)
            count += 1
        
        await session.commit()
        return count


def run(ctx: Any) -> dict:
    params = getattr(ctx, "params", {}) or {}
    targets = params.get("targets") or []
    if isinstance(targets, str):
        targets = [targets]
    community = params.get("community", "public")

    if not targets:
        # Fallback to querying all devices of type switch or router from DB
        ctx.logger("snmp_topology_discovery: no targets specified, loading switches/routers from database...")
        async def _load_switch_ips():
            async with async_session_factory() as session:
                res = await session.execute(
                    select(Device.ip_address).where(
                        Device.device_type.in_(["switch", "router"])
                    )
                )
                return [r[0] for r in res.fetchall()]
        targets = ctx.loop.run_until_complete(_load_switch_ips())

    if not targets:
        ctx.logger("snmp_topology_discovery: no target switches/routers found. Skipping.")
        return {"status": "completed", "links_found": 0, "msg": "No targets to query"}

    discovered_links: Set[Tuple[str, str, str]] = set()

    for switch_ip in targets:
        ctx.logger(f"snmp_topology_discovery: walking CDP cache for legacy Cisco switch {switch_ip}...")
        # 1. Cisco CDP Cache MIB: 1.3.6.1.4.1.9.9.23.1.2.1.1
        # cdpCacheAddress: 1.3.6.1.4.1.9.9.23.1.2.1.1.4
        cdp_entries = _snmp_walk(switch_ip, community, "1.3.6.1.4.1.9.9.23.1.2.1.1.4")
        cdp_count = 0
        for oid, val in cdp_entries:
            neighbor_ip = _ip_bytes_to_str(val)
            if neighbor_ip and neighbor_ip != "0.0.0.0":
                # We save undirected link pairings (lexicographically ordered) to represent link
                pair = tuple(sorted([switch_ip, neighbor_ip]))
                discovered_links.add((pair[0], pair[1], "cdp"))
                cdp_count += 1
        ctx.logger(f"snmp_topology_discovery: found {cdp_count} CDP links on {switch_ip}")

        ctx.logger(f"snmp_topology_discovery: walking LLDP remote table for modern devices on {switch_ip}...")
        # 2. IEEE LLDP Remote Table MIB: 1.0.8802.1.1.2.1.4.1.1
        # lldpRemManAddrEntry: 1.0.8802.1.1.2.1.4.1.1.12
        # However, sometimes lldpRemManAddrEntry is complex to parse.
        # Fallback to walking lldpRemSysName (1.0.8802.1.1.2.1.4.1.1.9) or lldpRemPortId (1.0.8802.1.1.2.1.4.1.1.7)
        # to find indices, then trying to resolve management IPs or resolving via DNS/ARP.
        # As a robust fallback, we walk lldpRemPortId:
        lldp_entries = _snmp_walk(switch_ip, community, "1.0.8802.1.1.2.1.4.1.1.9")
        lldp_count = 0
        for oid, val in lldp_entries:
            # val is the remote system name (e.g. hostname or IP)
            neighbor_label = str(val).strip()
            if neighbor_label:
                # Try to resolve neighbor label to an IP address
                try:
                    neighbor_ip = socket.gethostbyname(neighbor_label)
                    if neighbor_ip and neighbor_ip != "127.0.0.1" and neighbor_ip != "0.0.0.0":
                        pair = tuple(sorted([switch_ip, neighbor_ip]))
                        discovered_links.add((pair[0], pair[1], "lldp"))
                        lldp_count += 1
                except Exception:
                    pass
        ctx.logger(f"snmp_topology_discovery: found {lldp_count} LLDP links on {switch_ip}")

    # Save to database
    total_saved = ctx.loop.run_until_complete(_save_links(discovered_links))
    ctx.logger(f"snmp_topology_discovery: successfully updated {total_saved} connections in database")

    return {
        "status": "completed",
        "links_discovered": len(discovered_links),
        "links_saved": total_saved
    }
