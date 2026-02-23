from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple

from celery.utils.log import get_task_logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.device import Device
from app.models.metric import Metric
from app.models.router import Router, RouterInterfaceCounter

logger = get_task_logger(__name__)

IFDESCR_OID = "1.3.6.1.2.1.2.2.1.2"
IFINOCTETS_OID = "1.3.6.1.2.1.2.2.1.10"
IFOUTOCTETS_OID = "1.3.6.1.2.1.2.2.1.16"

COUNTER32_MOD = 2**32


@dataclass
class InterfaceSnapshot:
    if_index: int
    if_descr: Optional[str]
    in_octets: int
    out_octets: int


def _counter32_delta(prev: int, cur: int) -> int:
    if cur >= prev:
        return cur - prev
    return (COUNTER32_MOD - prev) + cur


def _snmp_auth(snmp_version: str, community: Optional[str]):
    from pysnmp.hlapi import CommunityData  # type: ignore[import-untyped]

    version = (snmp_version or "").lower().strip()
    if version == "2c":
        if not community:
            raise ValueError("Missing SNMP community")
        return CommunityData(community, mpModel=1)
    if version in {"1", "v1"}:
        if not community:
            raise ValueError("Missing SNMP community")
        return CommunityData(community, mpModel=0)

    raise ValueError(f"Unsupported SNMP version: {snmp_version}")


def _snmp_get_sync(
    host: str,
    port: int,
    snmp_version: str,
    community: Optional[str],
    oids: Iterable[str],
    timeout_seconds: float,
) -> Dict[str, str]:
    from pysnmp.hlapi import (  # type: ignore[import-untyped]
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        getCmd,
    )

    auth = _snmp_auth(snmp_version, community)

    engine = SnmpEngine()
    transport = UdpTransportTarget((host, port), timeout=timeout_seconds, retries=0)
    ctx = ContextData()

    var_binds = [ObjectType(ObjectIdentity(oid)) for oid in oids]

    for (error_indication, error_status, error_index, binds) in getCmd(
        engine,
        auth,
        transport,
        ctx,
        *var_binds,
    ):
        if error_indication:
            raise TimeoutError(str(error_indication))
        if error_status:
            idx = int(error_index) - 1 if error_index else None
            which = oids[idx] if idx is not None and idx < len(list(oids)) else "(unknown)"
            raise RuntimeError(f"SNMP error for {which}: {error_status.prettyPrint()}")

        out: Dict[str, str] = {}
        for name, val in binds:
            out[str(name)] = val.prettyPrint()
        return out

    raise RuntimeError("SNMP getCmd returned no results")


def _snmp_walk_ifdescr_sync(
    host: str,
    port: int,
    snmp_version: str,
    community: Optional[str],
    timeout_seconds: float,
) -> Dict[int, str]:
    from pysnmp.hlapi import (  # type: ignore[import-untyped]
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        nextCmd,
    )

    auth = _snmp_auth(snmp_version, community)

    engine = SnmpEngine()
    transport = UdpTransportTarget((host, port), timeout=timeout_seconds, retries=0)
    ctx = ContextData()

    results: Dict[int, str] = {}
    for (error_indication, error_status, error_index, var_binds) in nextCmd(
        engine,
        auth,
        transport,
        ctx,
        ObjectType(ObjectIdentity(IFDESCR_OID)),
        lexicographicMode=False,
    ):
        if error_indication:
            raise TimeoutError(str(error_indication))
        if error_status:
            raise RuntimeError(error_status.prettyPrint())

        for name, val in var_binds:
            # name ends with .<ifIndex>
            parts = str(name).split(".")
            if not parts:
                continue
            try:
                if_index = int(parts[-1])
            except ValueError:
                continue
            results[if_index] = val.prettyPrint()

    return results


async def _fetch_router_snapshots(router: Router) -> Tuple[List[InterfaceSnapshot], Dict[int, str]]:
    timeout_seconds = 2.0

    if_descrs: Dict[int, str] = {}
    if_indexes = list(router.if_indexes or [])

    # Auto-discover interfaces if none selected.
    if not if_indexes:
        if_descrs = await asyncio.to_thread(
            _snmp_walk_ifdescr_sync,
            router.host,
            router.port,
            router.snmp_version,
            router.community,
            timeout_seconds,
        )
        if_indexes = sorted(if_descrs.keys())

    snapshots: List[InterfaceSnapshot] = []

    for if_index in if_indexes:
        oids = [
            f"{IFINOCTETS_OID}.{if_index}",
            f"{IFOUTOCTETS_OID}.{if_index}",
        ]
        if if_index not in if_descrs:
            oids.append(f"{IFDESCR_OID}.{if_index}")

        try:
            values = await asyncio.to_thread(
                _snmp_get_sync,
                router.host,
                router.port,
                router.snmp_version,
                router.community,
                oids,
                timeout_seconds,
            )
        except Exception as exc:
            logger.warning("SNMP get failed for %s ifIndex=%s: %s", router.host, if_index, exc)
            continue

        def _get_int(oid_prefix: str) -> Optional[int]:
            raw = values.get(f"{oid_prefix}.{if_index}")
            if raw is None:
                return None
            try:
                return int(raw)
            except ValueError:
                return None

        in_octets = _get_int(IFINOCTETS_OID)
        out_octets = _get_int(IFOUTOCTETS_OID)

        if in_octets is None or out_octets is None:
            continue

        if_descr = if_descrs.get(if_index) or values.get(f"{IFDESCR_OID}.{if_index}")

        snapshots.append(
            InterfaceSnapshot(
                if_index=if_index,
                if_descr=if_descr,
                in_octets=in_octets,
                out_octets=out_octets,
            )
        )

    return snapshots, if_descrs


async def poll_network_metrics(db: AsyncSession) -> None:
    """Poll configured routers over SNMP and store interface bandwidth metrics.

    Metrics written:
      - metric_type="if_in_bps"  (bits/sec)
      - metric_type="if_out_bps" (bits/sec)

    Metric tags:
      - router_id
      - ifIndex
      - ifDescr (when available)
    """

    now = datetime.utcnow()

    result = await db.execute(select(Router).where(Router.is_active == True))
    routers = list(result.scalars().all())
    if not routers:
        return

    for router in routers:
        try:
            snapshots, _ = await _fetch_router_snapshots(router)
        except Exception as exc:
            logger.warning("SNMP poll failed for %s: %s", router.host, exc)
            continue

        if not snapshots:
            continue

        counters_result = await db.execute(
            select(RouterInterfaceCounter).where(RouterInterfaceCounter.router_id == router.id)
        )
        existing = {c.if_index: c for c in counters_result.scalars().all()}

        metrics: List[Metric] = []

        for snap in snapshots:
            prev = existing.get(snap.if_index)

            if prev is not None:
                dt = (now - prev.last_polled_at).total_seconds()
                if dt > 0.5:
                    in_delta = _counter32_delta(int(prev.in_octets), int(snap.in_octets))
                    out_delta = _counter32_delta(int(prev.out_octets), int(snap.out_octets))

                    in_bps = (in_delta * 8.0) / dt
                    out_bps = (out_delta * 8.0) / dt

                    tags = {
                        "router_id": router.id,
                        "ifIndex": snap.if_index,
                    }
                    if snap.if_descr:
                        tags["ifDescr"] = snap.if_descr

                    metrics.append(
                        Metric(
                            device_id=router.device_id,
                            timestamp=now,
                            metric_type="if_in_bps",
                            value=float(in_bps),
                            tags=tags,
                        )
                    )
                    metrics.append(
                        Metric(
                            device_id=router.device_id,
                            timestamp=now,
                            metric_type="if_out_bps",
                            value=float(out_bps),
                            tags=tags,
                        )
                    )

                prev.in_octets = int(snap.in_octets)
                prev.out_octets = int(snap.out_octets)
                prev.if_descr = snap.if_descr
                prev.last_polled_at = now

            else:
                db.add(
                    RouterInterfaceCounter(
                        router_id=router.id,
                        if_index=snap.if_index,
                        if_descr=snap.if_descr,
                        in_octets=int(snap.in_octets),
                        out_octets=int(snap.out_octets),
                        last_polled_at=now,
                    )
                )

        if metrics:
            db.add_all(metrics)

        device = await db.get(Device, router.device_id)
        if device is not None:
            device.last_seen = now

    await db.commit()
