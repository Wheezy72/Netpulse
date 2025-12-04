from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional

from scapy.all import IP, TCP, UDP, Packet, sniff, wrpcap  # type: ignore[import-untyped]
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.packet_capture import PacketCapture, PacketHeader


async def capture_to_pcap(
    db: AsyncSession,
    duration_seconds: int = 300,
    iface: str = "eth0",
    bpf_filter: Optional[str] = None,
    max_packets: int = 5000,
) -> int:
    """Capture packets for a limited duration and persist headers + PCAP.

    This is a Wireshark-style feature focused on:
    - BPF filters (e.g. "tcp port 443")
    - Header summaries stored in the database
    - A downloadable PCAP file for deeper offline analysis
    """

    capture = PacketCapture(
        iface=iface,
        bpf_filter=bpf_filter,
        created_at=datetime.utcnow(),
    )
    db.add(capture)
    await db.commit()
    await db.refresh(capture)

    output_dir = Path("/data/pcap")
    output_dir.mkdir(parents=True, exist_ok=True)
    pcap_path = output_dir / f"capture_{capture.id}.pcap"

    def _run_capture() -> list[Packet]:
        return sniff(
            iface=iface,
            filter=bpf_filter or "",
            timeout=duration_seconds,
            count=max_packets,
            store=True,
        )

    packets = await asyncio.to_thread(_run_capture)
    headers: list[PacketHeader] = []
    now = datetime.utcnow()

    for pkt in packets:
        ts = datetime.fromtimestamp(float(pkt.time)) if hasattr(pkt, "time") else now

        src_ip = dst_ip = ""
        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        proto = "other"
        info = ""

        if IP in pkt:  # type: ignore[operator]
            ip_layer = pkt[IP]  # type: ignore[index]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto = str(ip_layer.proto)

        if TCP in pkt:  # type: ignore[operator]
            tcp_layer = pkt[TCP]  # type: ignore[index]
            src_port = int(tcp_layer.sport)
            dst_port = int(tcp_layer.dport)
            flags = tcp_layer.sprintf("%TCP.flags%")
            info = f"TCP {flags}"
        elif UDP in pkt:  # type: ignore[operator]
            udp_layer = pkt[UDP]  # type: ignore[index]
            src_port = int(udp_layer.sport)
            dst_port = int(udp_layer.dport)
            info = "UDP datagram"

        length = len(pkt)

        headers.append(
            PacketHeader(
                capture_id=capture.id,
                timestamp=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                length=length,
                info=info,
            )
        )

    if packets:
        await asyncio.to_thread(wrpcap, str(pcap_path), packets, append=False)

    capture.started_at = capture.created_at
    capture.finished_at = datetime.utcnow()
    capture.pcap_path = str(pcap_path) if packets else None
    capture.packet_count = len(packets)

    db.add_all(headers)
    await db.commit()
    await db.refresh(capture)

    return capture.id