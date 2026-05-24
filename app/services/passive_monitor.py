from __future__ import annotations

import asyncio
import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from scapy.all import ARP, BOOTP, DHCP, Ether, Packet, sniff  # type: ignore[import-untyped]

from app.core.config import settings
from app.services.recon import record_probe_telemetry
from app.services.splunk_service import get_splunk_service

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class DiscoveryEvent:
    signature: str
    event_type: str
    source_mac: str | None = None
    source_ip: str | None = None
    trusted: bool = False
    payload: dict[str, Any] = field(default_factory=dict)


_seen_signatures: set[str] = set()
_event_buffer: deque[DiscoveryEvent] = deque(maxlen=1024)


def _signature_for_packet(packet: Packet) -> DiscoveryEvent | None:
    if packet.haslayer(ARP):
        arp = packet[ARP]
        if int(getattr(arp, "op", 0)) != 2:
            return None
        signature = f"arp:{arp.hwsrc}:{arp.psrc}"
        return DiscoveryEvent(
            signature=signature,
            event_type="arp.reply",
            source_mac=str(arp.hwsrc or ""),
            source_ip=str(arp.psrc or ""),
            payload={
                "hwsrc": str(arp.hwsrc or ""),
                "psrc": str(arp.psrc or ""),
                "pdst": str(arp.pdst or ""),
            },
        )

    if packet.haslayer(DHCP) and packet.haslayer(BOOTP):
        bootp = packet[BOOTP]
        for option in packet[DHCP].options:
            if isinstance(option, tuple) and option[0] == "message-type" and option[1] == 1:
                chaddr = ":".join(f"{b:02x}" for b in bytes(bootp.chaddr[:6]))
                signature = f"dhcp.discover:{chaddr}"
                return DiscoveryEvent(
                    signature=signature,
                    event_type="dhcp.discover",
                    source_mac=chaddr,
                    payload={
                        "xid": int(getattr(bootp, "xid", 0)),
                        "flags": int(getattr(bootp, "flags", 0)),
                        "giaddr": str(getattr(bootp, "giaddr", "")),
                    },
                )

    return None


async def evaluate_signature(event: DiscoveryEvent) -> DiscoveryEvent:
    event.trusted = event.signature in _seen_signatures
    _seen_signatures.add(event.signature)
    _event_buffer.append(event)

    telemetry = {
        "signature": event.signature,
        "event_type": event.event_type,
        "source_mac": event.source_mac,
        "source_ip": event.source_ip,
        "trusted": event.trusted,
        "payload": event.payload,
    }
    await record_probe_telemetry(telemetry, source="passive_monitor")

    if not event.trusted:
        await get_splunk_service().emit(
            {
                "type": "passive.discovery.anomaly",
                "severity": "high",
                "signature": event.signature,
                "source_mac": event.source_mac,
                "source_ip": event.source_ip,
                "payload": event.payload,
            }
        )

    return event


async def on_packet(packet: Packet, anomaly_callback: Callable[[DiscoveryEvent], Awaitable[None]] | None = None) -> None:
    event = _signature_for_packet(packet)
    if event is None:
        return

    evaluated = await evaluate_signature(event)
    if not evaluated.trusted and anomaly_callback is not None:
        await anomaly_callback(evaluated)


async def run_passive_monitor(
    iface: str | None = None,
    stop_event: asyncio.Event | None = None,
    anomaly_callback: Callable[[DiscoveryEvent], Awaitable[None]] | None = None,
) -> None:
    interface = iface or settings.passive_monitor_iface

    def _sniff() -> list[Packet]:
        packets: list[Packet] = []

        def _capture(pkt: Packet) -> None:
            packets.append(pkt)

        sniff(
            iface=interface,
            filter="arp or (udp and (port 67 or port 68))",
            prn=_capture,
            store=False,
            timeout=5,
        )
        return packets

    while stop_event is None or not stop_event.is_set():
        packets = await asyncio.to_thread(_sniff)
        for packet in packets:
            await on_packet(packet, anomaly_callback=anomaly_callback)


def recent_events() -> list[DiscoveryEvent]:
    return list(_event_buffer)
