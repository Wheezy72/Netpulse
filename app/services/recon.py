from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from collections import deque
from typing import Any, Iterable, List

import nmap  # type: ignore[import-untyped]
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.vulnerability import Vulnerability, VulnerabilitySeverity
from app.services.device_discovery import (
    DEFAULT_ARP_TIMEOUT,
    enrich_hosts,
    hosts_from_arp_pairs,
    local_subnets,
    upsert_discovered_hosts,
)
logger = logging.getLogger("netpulse.recon")


@dataclass
class DetectedService:
    port: int
    protocol: str
    service: str


probe_telemetry: deque[dict[str, Any]] = deque(maxlen=1024)


async def record_probe_telemetry(payload: dict[str, Any], source: str = "recon") -> None:
    entry = {
        "source": source,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **payload,
    }
    probe_telemetry.append(entry)


async def run_nmap_scan(db: AsyncSession, target: str) -> List[DetectedService]:
    """Run a basic Nmap scan against a target and return discovered services.

    This is intentionally conservative: it focuses on service discovery rather
    than aggressive exploitation. You can extend this with custom arguments,
    script sets, and OS detection flags.
    """
    # python-nmap is sync; offload to a thread to avoid blocking the event loop.
    def _scan() -> List[DetectedService]:
        nm = nmap.PortScanner()
        # Service/version detection; no default scripts here for safety.
        nm.scan(target, arguments="-sV")

        services: list[DetectedService] = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in sorted(lport):
                    svc = nm[host][proto][port]
                    name = svc.get("name") or "unknown"
                    services.append(
                        DetectedService(
                            port=int(port),
                            protocol=str(proto),
                            service=str(name),
                        )
                    )
        return services

    services = await asyncio.to_thread(_scan)
    await record_probe_telemetry(
        {
            "event_type": "nmap.scan",
            "target": target,
            "service_count": len(services),
            "services": [service.__dict__ for service in services],
        }
    )

    # Optionally, we could upsert the Device and create basic Vulnerability stubs
    # here based on service fingerprints. For now, this function focuses on
    # returning structured service data to the API.
    return services


def _sniff_and_sweep(iface: str | None, duration: int) -> list[tuple[str, str]]:
    """Passively sniff ARP for *duration* seconds, then actively sweep the
    attached subnets so devices that never speak first are still found.

    ``iface=None`` means "whatever carries the default route", which on Linux
    is where a USB Wi-Fi adapter (``wlan0``/``wlx…``) usually sits.

    Returns de-duplicated (ip, mac) pairs.
    """
    from scapy.all import ARP, sniff

    from app.services.device_discovery import arp_sweep, default_interface

    iface = iface or default_interface()

    observed: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def _remember(ip: str, mac: str) -> None:
        pair = (ip, mac)
        if pair not in seen:
            seen.add(pair)
            observed.append(pair)

    def _handler(packet) -> None:
        if not packet.haslayer(ARP):
            return
        arp_layer = packet[ARP]
        if arp_layer.psrc and arp_layer.hwsrc:
            _remember(str(arp_layer.psrc), str(arp_layer.hwsrc))

    try:
        sniff(iface=iface, prn=_handler, filter="arp", store=False, timeout=duration)
    except Exception as exc:
        logger.debug("Passive ARP sniff unavailable: %s", exc)

    # Active sweep of directly attached subnets. The width cap (/20) and the
    # restricted-VLAN skip are both enforced by scan_policy.
    subnets, resolved_iface = local_subnets(iface)
    for subnet in subnets:
        try:
            for ip, mac in arp_sweep(subnet, resolved_iface, DEFAULT_ARP_TIMEOUT):
                _remember(ip, mac)
        except Exception as exc:
            logger.debug("Active ARP sweep of %s skipped: %s", subnet, exc)

    return observed


async def passive_arp_discovery(
    db: AsyncSession, iface: str | None = None, duration: int = 10
) -> None:
    """Passive ARP sniff plus an active sweep of the attached subnets.

    Enrichment, classification and persistence are shared with the on-demand
    discovery endpoint (app/services/device_discovery.py), so a host found by
    the scheduled beat task and one found by the on-demand scan button produce
    identical device rows instead of drifting apart.
    """
    pairs = await asyncio.to_thread(_sniff_and_sweep, iface, duration)

    await record_probe_telemetry(
        {
            "event_type": "passive.arp.discovery",
            "iface": iface,
            "observed_pairs": len(pairs),
            "severity": "info",
        },
        source="passive_arp",
    )

    if not pairs:
        return

    hosts = await enrich_hosts(hosts_from_arp_pairs(pairs))
    await upsert_discovered_hosts(db, hosts)
