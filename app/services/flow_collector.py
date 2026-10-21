from __future__ import annotations

import asyncio
import logging
import struct
from datetime import datetime
from typing import Any, Dict, List, Tuple
from sqlalchemy import select

from app.db.session import async_session_factory
from app.models.device import Device
from app.models.metric import Metric

logger = logging.getLogger("netpulse.flow_collector")

NETFLOW_PORT = 2055


class NetFlowProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        super().__init__()
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        logger.info(f"NetFlow Collector bound to UDP port {NETFLOW_PORT}")

    def datagram_received(self, data: bytes, addr: tuple[str, int]):
        # Run parsing in background so we do not block socket reading
        asyncio.create_task(self.process_packet(data, addr))

    async def process_packet(self, data: bytes, addr: tuple[str, int]):
        if len(data) < 24:
            logger.debug(f"Malformed packet received from {addr[0]}: too short ({len(data)} bytes)")
            return

        try:
            # NetFlow Header (first 2 bytes is version)
            version = struct.unpack("!H", data[:2])[0]
            if version == 5:
                await self.parse_v5(data, addr)
            elif version == 9:
                logger.debug(f"NetFlow v9 packet from {addr[0]} received. Template processing fallback active (skipping parse).")
            else:
                logger.debug(f"Unsupported NetFlow version {version} from {addr[0]}")
        except Exception as e:
            logger.error(f"Error parsing NetFlow datagram: {e}")

    async def parse_v5(self, data: bytes, addr: tuple[str, int]):
        # NetFlow v5 Header:
        # 0-1: Version (5)
        # 2-3: Count
        # 4-7: SysUptime
        # 8-11: Unix Secs
        # 12-15: Unix Nsecs
        # 16-19: Flow Sequence
        # 20: Engine Type
        # 21: Engine ID
        # 22-23: Sampling Interval
        if len(data) < 24:
            return

        header = struct.unpack("!HHIIIIBBH", data[:24])
        count = header[1]

        # Each record is 48 bytes
        record_offset = 24
        expected_len = 24 + (count * 48)
        if len(data) < expected_len:
            logger.warning(f"NetFlow v5 payload length ({len(data)}) less than expected ({expected_len}) based on count {count}")
            return

        async with async_session_factory() as session:
            for i in range(count):
                offset = record_offset + (i * 48)
                record_data = data[offset : offset + 48]

                # Format for 48 bytes NetFlow v5 record:
                # !IIIHHIIIIHHBBBBHHBBH
                # srcaddr (4B), dstaddr (4B), nexthop (4B), input (2B), output (2B),
                # dPkts (4B), dOctets (4B), first (4B), last (4B), srcport (2B), dstport (2B),
                # pad1 (1B), tcp_flags (1B), prot (1B), tos (1B), src_as (2B), dst_as (2B),
                # src_mask (1B), dst_mask (1B), pad2 (2B)
                rec = struct.unpack("!IIIHHIIIIHHBBBBHHBBH", record_data)

                src_ip = self.ip_to_str(rec[0])
                dst_ip = self.ip_to_str(rec[1])
                packets = rec[5]
                bytes_count = rec[6]
                src_port = rec[9]
                dst_port = rec[10]
                proto = rec[13]

                # 1. Update/Create source device
                await self.upsert_device_last_seen(session, src_ip)
                # 2. Update/Create destination device
                await self.upsert_device_last_seen(session, dst_ip)

                # 3. Save metric record
                # Locate device ID for source to associate the metric
                src_device_id = await self.get_device_id(session, src_ip)

                metric = Metric(
                    device_id=src_device_id,
                    timestamp=datetime.utcnow(),
                    metric_type="traffic_flow",
                    value=float(bytes_count),
                    tags={
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": proto,
                        "packets": packets,
                        "exporter_ip": addr[0]
                    }
                )
                session.add(metric)

            await session.commit()

    def ip_to_str(self, ip_int: int) -> str:
        return f"{(ip_int >> 24) & 0xff}.{(ip_int >> 16) & 0xff}.{(ip_int >> 8) & 0xff}.{ip_int & 0xff}"

    async def get_device_id(self, session, ip: str) -> int | None:
        result = await session.execute(select(Device.id).where(Device.ip_address == ip))
        return result.scalar_one_or_none()

    async def upsert_device_last_seen(self, session, ip: str):
        # Gracefully handle validation and exclusions
        if ip.startswith("0.") or ip.startswith("127.") or ip == "255.255.255.255":
            return

        result = await session.execute(select(Device).where(Device.ip_address == ip))
        device = result.scalar_one_or_none()
        if device is None:
            # Discovered a new node passively via NetFlow!
            device = Device(
                ip_address=ip,
                last_seen=datetime.utcnow(),
                device_type="host" # Default guess
            )
            session.add(device)
        else:
            device.last_seen = datetime.utcnow()


async def start_flow_collector() -> None:
    """Start NetFlow daemon background task."""
    loop = asyncio.get_running_loop()

    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    if hasattr(socket, "SO_REUSEPORT"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    try:
        sock.bind(("0.0.0.0", NETFLOW_PORT))
    except Exception as e:
        logger.error(f"Failed to bind NetFlow Collector UDP socket: {e}")
        sock.close()
        return

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: NetFlowProtocol(),
        sock=sock
    )

    try:
        while True:
            await asyncio.sleep(3600) # Keep task alive indefinitely
    except asyncio.CancelledError:
        logger.info("NetFlow Collector task stopped.")
    finally:
        transport.close()
