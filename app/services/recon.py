from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from collections import deque
from typing import Any, Iterable, List

import nmap  # type: ignore[import-untyped]
from scapy.all import ARP, Ether, sniff, conf  # type: ignore[import-untyped]
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.device import Device
from app.models.vulnerability import Vulnerability, VulnerabilitySeverity
from app.services.splunk_service import get_splunk_service
from app.core.config import settings


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
    """Perform passive ARP-based discovery on the given interface, combined with
    an active background ARP sweep on local subnets to ensure high-accuracy device detection.
    """

    def _capture() -> list[tuple[str, str]]:
        observed: list[tuple[str, str]] = []

        # 1. Passive sniff
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

        # 2. Active ARP sweep on local subnets to automatically detect all devices
        try:
            from scapy.all import srp
            from scapy.utils import ltoa
            
            # Identify the default physical interface (or fall back to the given interface)
            default_iface = None
            try:
                default_iface = conf.route.route("0.0.0.0")[0]
            except Exception:
                pass
            iface_to_scan = default_iface or iface or conf.iface

            # Find all directly attached subnets
            subnets = []
            for net, msk, gw, route_iface, addr, metric in conf.route.routes:
                if route_iface == iface_to_scan and gw == '0.0.0.0' and msk != 0 and msk != 0xffffffff:
                    net_str = ltoa(net)
                    if not (net_str.startswith("127.") or net_str.startswith("224.") or net_str.startswith("240.") or net_str.startswith("255.")):
                        prefix = bin(msk & 0xffffffff).count('1')
                        # Only scan subnets that are /20 or smaller to prevent massive scan loops
                        if prefix >= 20:
                            subnets.append(f"{net_str}/{prefix}")

            # Send active unicast-reply-eliciting ARP requests across the subnets
            for subnet in subnets:
                try:
                    ans, unans = srp(
                        Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet),
                        iface=iface_to_scan,
                        timeout=2.0,
                        retry=0,
                        verbose=False
                    )
                    for snd, rcv in ans:
                        if rcv.haslayer(ARP) and rcv[ARP].psrc and rcv[ARP].hwsrc:
                            observed.append((rcv[ARP].psrc, rcv[ARP].hwsrc))
                except Exception:
                    pass
        except Exception:
            pass

        return list(set(observed))

    pairs = await asyncio.to_thread(_capture)
    now = datetime.now(timezone.utc)

    await record_probe_telemetry(
        {
            "event_type": "passive.arp.discovery",
            "iface": iface,
            "observed_pairs": len(pairs),
            "severity": "info",
        },
        source="passive_arp",
    )

    # Intelligent Gateway Detection
    # Attempt to read the live system routing table for the default gateway.
    # If it fails or is None, fallback to the manual setup override from config.py.
    try:
        live_gateway_ip = conf.route.route("0.0.0.0")[2]
    except Exception:
        live_gateway_ip = None
        
    manual_gateway_override = settings.pulse_gateway_ip

    for ip, mac in pairs:
        # Determine if this IP matches the detected gateway or the manual override
        is_gw = (ip == live_gateway_ip) or (ip == manual_gateway_override)

        # Upsert behaviour: try to find an existing device by IP, else create new.
        result = await db.execute(select(Device).where(Device.ip_address == ip))
        device = result.scalar_one_or_none()

        if device is None:
            device = Device(ip_address=ip, mac_address=mac, last_seen=now, is_gateway=is_gw)
            db.add(device)
        else:
            device.mac_address = device.mac_address or mac
            device.last_seen = now
            if is_gw:
                device.is_gateway = True

    await db.commit()
