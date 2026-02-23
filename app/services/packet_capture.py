from __future__ import annotations

import asyncio
import logging
import os
import shlex
import shutil
import subprocess
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.celery_app import celery_app
from app.core.config import settings
from app.models.packet_capture import PacketCapture, PacketCaptureStatus, PacketHeader
from app.models.pcap_meta import PcapFile


logger = logging.getLogger(__name__)


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

    Capture strategy:
    - Prefer tcpdump (writes packets directly to disk, lowest overhead).
    - Fall back to Scapy streaming into a PcapWriter (no in-memory packet lists).

    After a successful capture, enqueue a Celery task to index packet metadata
    into PcapPacket for the PacketBrowser.

    Returns:
        The ID of the created PacketCapture record.
    """
    from sqlalchemy import select

    captures_dir = Path(getattr(settings, "pcap_storage_dir", "/tmp/pcaps"))
    captures_dir.mkdir(parents=True, exist_ok=True)

    interface = iface or _get_default_interface()
    filename = (
        f"capture_{uuid.uuid4().hex[:8]}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pcap"
    )
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

        pcap_file = (
            await db.execute(select(PcapFile).where(PcapFile.filepath == str(filepath)))
        ).scalar_one_or_none()
        if not pcap_file:
            pcap_file = PcapFile(
                capture_id=capture.id,
                filename=filename,
                filepath=str(filepath),
                interface=interface,
                bpf_filter=bpf_filter,
                file_size_bytes=file_size,
                captured_started_at=capture.started_at,
                captured_finished_at=capture.finished_at,
            )
            db.add(pcap_file)
        else:
            pcap_file.capture_id = capture.id
            pcap_file.filename = filename
            pcap_file.interface = interface
            pcap_file.bpf_filter = bpf_filter
            pcap_file.file_size_bytes = file_size
            pcap_file.captured_started_at = capture.started_at
            pcap_file.captured_finished_at = capture.finished_at

        await db.commit()
        await db.refresh(pcap_file)

        try:
            celery_app.send_task("app.tasks.index_pcap_file", args=[pcap_file.id])
        except Exception:
            # Capture completion should not fail if the broker/worker is unavailable.
            logger.exception("Failed to enqueue index_pcap_file task for %s", pcap_file.id)

    except PermissionError:
        capture.status = PacketCaptureStatus.FAILED
        capture.error_message = (
            "Insufficient permissions for packet capture. Root access required."
        )
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
    """Capture packets to a raw .pcap file.

    Prefers tcpdump if present, otherwise uses Scapy streaming into a PcapWriter.

    Returns:
        The number of packets captured when using Scapy. When using tcpdump, this
        returns 0 (packet count will be derived during indexing).
    """
    tcpdump_path = shutil.which("tcpdump")
    if tcpdump_path:
        await _run_tcpdump_capture(
            tcpdump_path=tcpdump_path,
            interface=interface,
            duration=duration,
            bpf_filter=bpf_filter,
            output_file=output_file,
        )
        return 0

    return await _run_scapy_capture(
        interface=interface,
        duration=duration,
        bpf_filter=bpf_filter,
        output_file=output_file,
    )


async def _run_tcpdump_capture(
    tcpdump_path: str,
    interface: str,
    duration: int,
    bpf_filter: Optional[str],
    output_file: str,
) -> None:
    args: list[str] = [
        tcpdump_path,
        "-i",
        interface,
        "-w",
        output_file,
        "-U",
        "-s",
        "0",
        "-nn",
    ]

    if bpf_filter:
        args.extend(shlex.split(bpf_filter))

    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        try:
            await asyncio.wait_for(proc.wait(), timeout=duration)
        except asyncio.TimeoutError:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=10)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
    finally:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()

    stderr = b""
    if proc.stderr is not None:
        stderr = await proc.stderr.read()

    if stderr:
        msg = stderr.decode(errors="ignore").strip()
        lowered = msg.lower()
        if "you don't have permission" in lowered or "permission denied" in lowered:
            raise PermissionError(msg)

    if not Path(output_file).exists():
        Path(output_file).touch()


async def _run_scapy_capture(
    interface: str,
    duration: int,
    bpf_filter: Optional[str],
    output_file: str,
) -> int:
    def _capture_sync() -> int:
        from scapy.all import PcapWriter, sniff

        packet_count = 0
        writer = PcapWriter(output_file, append=False, sync=True)

        def _write(pkt) -> None:
            nonlocal packet_count
            writer.write(pkt)
            packet_count += 1

        try:
            sniff(
                iface=interface,
                timeout=duration,
                filter=bpf_filter,
                store=False,
                prn=_write,
            )
            return packet_count
        finally:
            writer.close()

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _capture_sync)


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
            from scapy.all import IP, IPv6, PcapReader, TCP, UDP

            headers: list[dict] = []
            reader = PcapReader(str(filepath))
            try:
                for pkt in reader:
                    if len(headers) >= max_packets:
                        break

                    ip_layer = None
                    if IP in pkt:
                        ip_layer = pkt[IP]
                    elif IPv6 in pkt:
                        ip_layer = pkt[IPv6]

                    if ip_layer is None:
                        continue

                    header_data: dict = {
                        "timestamp": datetime.utcfromtimestamp(float(pkt.time)),
                        "src_ip": getattr(ip_layer, "src", None),
                        "dst_ip": getattr(ip_layer, "dst", None),
                        "protocol": str(getattr(ip_layer, "proto", getattr(ip_layer, "nh", ""))),
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

                    headers.append(header_data)

            finally:
                reader.close()

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
