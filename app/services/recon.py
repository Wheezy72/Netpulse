from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
from collections import deque
from typing import Any, Iterable, List

import nmap  # type: ignore[import-untyped]
from scapy.all import ARP, Ether, sniff  # type: ignore[import-untyped]
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.device import Device
from app.models.vulnerability import Vulnerability, VulnerabilitySeverity
from app.services.splunk_service import get_splunk_service


@dataclass
class DetectedService:
    port: int
    protocol: str
    service: str


probe_telemetry: deque[dict[str, Any]] = deque(maxlen=1024)


async def record_probe_telemetry(payload: dict[str, Any], source: str = "recon") -> None:
    entry = {
        "source": source,
        "timestamp": datetime.utcnow().isoformat(),
        **payload,
    }
    probe_telemetry.append(entry)
    await get_splunk_service().emit(
        {
            "type": "probe.telemetry",
            "severity": payload.get("severity", "info"),
            "event": entry,
        }
    )


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


async def passive_arp_discovery(db: AsyncSession, iface: str = "eth0", duration: int = 10) -> None:
    """Perform passive ARP-based discovery on the given interface.

    Listens for ARP traffic for a limited duration (seconds) and upserts
    Device entries with IP/MAC/last_seen. This function is meant to be
    invoked periodically by a Celery task, not as a permanent daemon.
    """

    def _capture() -> list[tuple[str, str]]:
        observed: list[tuple[str, str]] = []

        def _handler(pkt) -> None:
            if pkt.haslayer(ARP):
                arp_layer = pkt[ARP]
                if arp_layer.psrc and arp_layer.hwsrc:
                    observed.append((arp_layer.psrc, arp_layer.hwsrc))

        sniff(
            iface=iface,
            prn=_handler,
            filter="arp",
            store=False,
            timeout=duration,
        )
        return observed

    pairs = await asyncio.to_thread(_capture)
    now = datetime.utcnow()

    await record_probe_telemetry(
        {
            "event_type": "passive.arp.discovery",
            "iface": iface,
            "observed_pairs": len(pairs),
            "severity": "info",
        },
        source="passive_arp",
    )

    for ip, mac in pairs:
        # Upsert behaviour: try to find an existing device by IP, else create new.
        result = await db.execute(select(Device).where(Device.ip_address == ip))
        device = result.scalar_one_or_none()

        if device is None:
            device = Device(ip_address=ip, mac_address=mac, last_seen=now)
            db.add(device)
        else:
            device.mac_address = device.mac_address or mac
            device.last_seen = now

    await db.commit()
