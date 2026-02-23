from __future__ import annotations

import asyncio
import os
import subprocess
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.packet_capture import PacketCapture, PacketCaptureStatus, PacketHeader


def _get_default_interface() -> str:
    """Get the default network interface."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0 and result.stdout:
            parts = result.stdout.split()
            if "dev" in parts:
                idx = parts.index("dev")
                if idx + 1 < len(parts):
                    return parts[idx + 1]
    except Exception:
        pass
    return "eth0"


async def capture_to_pcap(
    db: AsyncSession,
    duration_seconds: int = 300,
    iface: str | None = None,
    bpf_filter: str | None = None,
) -> int:
    """Perform a time-bounded packet capture and store metadata in the database.
    
    Uses scapy for packet capture. Requires appropriate permissions.
    
    Args:
        db: Database session
        duration_seconds: How long to capture packets
        iface: Network interface to capture on (None = auto-detect)
        bpf_filter: Optional BPF filter expression
        
    Returns:
        The ID of the created PacketCapture record
    """
    captures_dir = Path(getattr(settings, "pcap_storage_dir", "/tmp/pcaps"))
    captures_dir.mkdir(parents=True, exist_ok=True)
    
    interface = iface or _get_default_interface()
    filename = f"capture_{uuid.uuid4().hex[:8]}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pcap"
    filepath = captures_dir / filename
    
    capture = PacketCapture(
        filename=filename,
        filepath=str(filepath),
        interface=interface,
        bpf_filter=bpf_filter,
        duration_seconds=duration_seconds,
        status=PacketCaptureStatus.RUNNING,
        started_at=datetime.utcnow(),
    )
    db.add(capture)
    await db.commit()
    await db.refresh(capture)
    
    try:
        packets = await _run_capture(
            interface=interface,
            duration=duration_seconds,
            bpf_filter=bpf_filter,
            output_file=str(filepath),
        )
        
        file_size = filepath.stat().st_size if filepath.exists() else 0
        
        capture.status = PacketCaptureStatus.COMPLETED
        capture.finished_at = datetime.utcnow()
        capture.packet_count = packets
        capture.file_size_bytes = file_size
        await db.commit()
        
    except PermissionError as e:
        capture.status = PacketCaptureStatus.FAILED
        capture.error_message = "Insufficient permissions for packet capture. Root access required."
        capture.finished_at = datetime.utcnow()
        await db.commit()
        
    except Exception as e:
        capture.status = PacketCaptureStatus.FAILED
        capture.error_message = str(e)
        capture.finished_at = datetime.utcnow()
        await db.commit()
    
    return capture.id


async def _run_capture(
    interface: str,
    duration: int,
    bpf_filter: Optional[str],
    output_file: str,
) -> int:
    """Run the actual packet capture using scapy.
    
    Returns the number of packets captured.
    """
    def _capture_sync() -> int:
        try:
            from scapy.all import sniff, wrpcap
            
            packets = sniff(
                iface=interface,
                timeout=min(duration, 60),
                filter=bpf_filter,
                store=True,
            )
            
            if packets:
                wrpcap(output_file, packets)
            else:
                Path(output_file).touch()
            
            return len(packets)
            
        except PermissionError:
            raise
        except Exception as e:
            Path(output_file).touch()
            return 0
    
    loop = asyncio.get_event_loop()
    packet_count = await loop.run_in_executor(None, _capture_sync)
    return packet_count


async def parse_pcap_headers(
    db: AsyncSession,
    capture_id: int,
    max_packets: int = 1000,
) -> int:
    """Parse packet headers from a PCAP file and store in database.
    
    Args:
        db: Database session
        capture_id: ID of the PacketCapture record
        max_packets: Maximum number of packet headers to store
        
    Returns:
        Number of headers parsed and stored
    """
    capture = await db.get(PacketCapture, capture_id)
    if not capture:
        raise ValueError(f"Capture {capture_id} not found")
    
    filepath = Path(capture.filepath)
    if not filepath.exists():
        return 0
    
    def _parse_sync() -> list[dict]:
        try:
            from scapy.all import rdpcap, IP, TCP, UDP
            
            packets = rdpcap(str(filepath))
            headers = []
            
            for i, pkt in enumerate(packets[:max_packets]):
                if IP not in pkt:
                    continue
                    
                ip_layer = pkt[IP]
                header_data = {
                    "timestamp": datetime.fromtimestamp(float(pkt.time)),
                    "src_ip": ip_layer.src,
                    "dst_ip": ip_layer.dst,
                    "protocol": ip_layer.proto,
                    "length": len(pkt),
                }
                
                if TCP in pkt:
                    header_data["src_port"] = pkt[TCP].sport
                    header_data["dst_port"] = pkt[TCP].dport
                    header_data["protocol"] = "TCP"
                elif UDP in pkt:
                    header_data["src_port"] = pkt[UDP].sport
                    header_data["dst_port"] = pkt[UDP].dport
                    header_data["protocol"] = "UDP"
                else:
                    header_data["protocol"] = str(ip_layer.proto)
                
                headers.append(header_data)
            
            return headers
        except Exception:
            return []
    
    loop = asyncio.get_event_loop()
    headers_data = await loop.run_in_executor(None, _parse_sync)
    
    for hdr in headers_data:
        packet_header = PacketHeader(
            capture_id=capture_id,
            timestamp=hdr["timestamp"],
            src_ip=hdr.get("src_ip"),
            dst_ip=hdr.get("dst_ip"),
            src_port=hdr.get("src_port"),
            dst_port=hdr.get("dst_port"),
            protocol=hdr.get("protocol"),
            length=hdr.get("length", 0),
        )
        db.add(packet_header)
    
    await db.commit()
    return len(headers_data)


async def get_capture_stats(db: AsyncSession, capture_id: int) -> dict:
    """Get statistics for a packet capture."""
    from sqlalchemy import func, select
    
    capture = await db.get(PacketCapture, capture_id)
    if not capture:
        return {}
    
    result = await db.execute(
        select(
            func.count(PacketHeader.id).label("header_count"),
            func.count(func.distinct(PacketHeader.src_ip)).label("unique_sources"),
            func.count(func.distinct(PacketHeader.dst_ip)).label("unique_destinations"),
        ).where(PacketHeader.capture_id == capture_id)
    )
    row = result.first()
    
    return {
        "capture_id": capture_id,
        "filename": capture.filename,
        "status": capture.status.value,
        "packet_count": capture.packet_count,
        "file_size_bytes": capture.file_size_bytes,
        "duration_seconds": capture.duration_seconds,
        "interface": capture.interface,
        "bpf_filter": capture.bpf_filter,
        "started_at": capture.started_at,
        "finished_at": capture.finished_at,
        "parsed_headers": row.header_count if row else 0,
        "unique_sources": row.unique_sources if row else 0,
        "unique_destinations": row.unique_destinations if row else 0,
    }
