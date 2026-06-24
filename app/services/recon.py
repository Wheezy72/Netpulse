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
    Enriches discovered hosts with hostname reverse resolution, OUI vendor matching, and OS/device type guessing.
    """

    def _capture() -> list[dict[str, Any]]:
        observed_pairs = []
        observed_set = set()

        # 1. Passive sniff
        def _handler(pkt) -> None:
            if pkt.haslayer(ARP):
                arp_layer = pkt[ARP]
                if arp_layer.psrc and arp_layer.hwsrc:
                    pair = (arp_layer.psrc, arp_layer.hwsrc)
                    if pair not in observed_set:
                        observed_set.add(pair)
                        observed_pairs.append(pair)

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
                            pair = (rcv[ARP].psrc, rcv[ARP].hwsrc)
                            if pair not in observed_set:
                                observed_set.add(pair)
                                observed_pairs.append(pair)
                except Exception:
                    pass
        except Exception:
            pass

        # 3. Enrich the discovered devices (hostname, vendor, device type, OS)
        enriched = []
        import socket
        
        # A list of common OUIs
        ouis = {
            "000569": "VMware", "000c29": "VMware", "001c14": "VMware", "005056": "VMware",
            "000393": "Apple", "000a27": "Apple", "000d93": "Apple", "0010fa": "Apple",
            "001451": "Apple", "0016cb": "Apple", "0017f2": "Apple", "0019e3": "Apple",
            "00000c": "Cisco", "0001c7": "Cisco", "0002fc": "Cisco", "0003e3": "Cisco",
            "001302": "Intel", "0018de": "Intel", "001b21": "Intel", "001cbf": "Intel",
            "f875a4": "Intel", "3413e8": "Intel", "4c1d96": "Intel", "7c5cf8": "Intel",
            "0007ab": "Samsung", "001247": "Samsung", "001c7b": "Samsung", "0021d2": "Samsung",
            "0003ff": "Microsoft", "000d3a": "Microsoft", "00155d": "Microsoft",
            "0001e6": "HP", "000854": "HP", "000f20": "HP",
            "00065b": "Dell", "000874": "Dell", "000f1f": "Dell",
            "b827eb": "Raspberry Pi", "3a8024": "Raspberry Pi", "d83add": "Raspberry Pi"
        }

        for ip, mac in observed_pairs:
            hostname = None
            vendor = None
            device_type = None
            os_val = None
            
            # Resolve hostname with a tight timeout to prevent workers hanging on DNS
            try:
                socket.setdefaulttimeout(0.15)
                res = socket.gethostbyaddr(ip)
                hostname = res[0]
            except Exception:
                pass
                
            # Resolve vendor from OUI
            if mac:
                clean_mac = mac.replace(":", "").replace("-", "").lower()[:6]
                vendor = ouis.get(clean_mac)
                
            # Classify device and OS
            h = (hostname or "").lower()
            v = (vendor or "").lower()
            
            if any(k in h for k in ["router", "gateway", "pfsense", "opnsense"]):
                device_type = "Router"
                os_val = "Linux/Embedded"
            elif any(k in h for k in ["switch", "cisco", "catalyst"]):
                device_type = "Switch (Cisco)"
                os_val = "Cisco IOS"
            elif "printer" in h or v in ["hp", "epson", "canon", "brother"]:
                device_type = "Printer"
                os_val = "Embedded"
            elif any(k in h for k in ["nas", "storage", "synology", "qnap"]):
                device_type = "NAS"
                os_val = "Linux/Embedded"
            elif any(k in h for k in ["tv", "roku", "chromecast", "firetv", "appletv"]):
                device_type = "Smart TV"
                os_val = "Android/tvOS"
            elif any(k in h for k in ["iphone", "ipad"]) or (v == "apple" and any(k in h for k in ["phone", "pad"])):
                device_type = "Phone/Tablet (Apple)"
                os_val = "iOS"
            elif any(k in h for k in ["android", "pixel", "galaxy"]) or (v == "samsung" and any(k in h for k in ["phone", "galaxy"])):
                device_type = "Phone/Tablet (Android)"
                os_val = "Android"
            elif any(k in h for k in ["desktop", "laptop", "pc", "win-", "windows"]):
                device_type = "Windows Workstation"
                os_val = "Windows"
            elif v in ["intel", "microsoft", "dell", "hp"]:
                device_type = "Windows Workstation"
                os_val = "Windows"
            else:
                device_type = "Linux Workstation"
                os_val = "Linux"

            enriched.append({
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "vendor": vendor,
                "device_type": device_type,
                "os": os_val
            })
            
        return enriched

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
    try:
        live_gateway_ip = conf.route.route("0.0.0.0")[2]
    except Exception:
        live_gateway_ip = None
        
    manual_gateway_override = settings.pulse_gateway_ip

    for item in pairs:
        ip = item["ip"]
        mac = item["mac"]
        hostname = item["hostname"]
        vendor = item["vendor"]
        device_type = item["device_type"]
        os_val = item["os"]
        
        is_gw = (ip == live_gateway_ip) or (ip == manual_gateway_override)
        if is_gw:
            device_type = "Router"
            os_val = "Linux/Embedded"

        # Upsert: load existing device or create new
        result = await db.execute(select(Device).where(Device.ip_address == ip))
        device = result.scalar_one_or_none()

        if device is None:
            device = Device(
                ip_address=ip,
                mac_address=mac,
                hostname=hostname,
                vendor=vendor,
                device_type=device_type,
                os=os_val,
                last_seen=now,
                is_gateway=is_gw
            )
            db.add(device)
        else:
            device.mac_address = device.mac_address or mac
            device.last_seen = now
            if hostname:
                device.hostname = device.hostname or hostname
            if vendor:
                device.vendor = device.vendor or vendor
            if device_type:
                device.device_type = device.device_type or device_type
            if os_val:
                device.os = device.os or os_val
            if is_gw:
                device.is_gateway = True

    await db.commit()
