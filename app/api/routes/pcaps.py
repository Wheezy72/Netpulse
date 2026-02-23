from __future__ import annotations

import base64
from datetime import datetime
from typing import Any, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, require_role
from app.models.pcap_meta import PcapFile, PcapPacket

router = APIRouter()


def _encode_cursor(ts: datetime, packet_index: int) -> str:
    raw = f"{ts.isoformat()}|{packet_index}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _decode_cursor(cursor: str) -> Tuple[datetime, int]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8")
        ts_str, idx_str = raw.split("|", 1)
        return datetime.fromisoformat(ts_str), int(idx_str)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor",
        ) from exc


class PcapFileResponse(BaseModel):
    id: int
    filename: str
    interface: Optional[str]
    bpf_filter: Optional[str]
    file_size_bytes: int
    packet_count: int
    captured_started_at: Optional[str]
    captured_finished_at: Optional[str]
    indexed_at: Optional[str]
    index_error: Optional[str]

    class Config:
        from_attributes = True


class PcapPacketResponse(BaseModel):
    id: int
    packet_index: int
    timestamp: str
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    length: int

    class Config:
        from_attributes = True


class PacketQueryResponse(BaseModel):
    items: List[PcapPacketResponse]
    next_cursor: Optional[str] = None


class PcapZeekSummaryResponse(BaseModel):
    pcap_file_id: int
    indexing_status: str
    zeek_summary: Optional[dict[str, Any]] = None


@router.get(
    "/",
    response_model=List[PcapFileResponse],
    summary="List PCAP files",
    dependencies=[Depends(require_role())],
)
async def list_pcap_files(
    db: AsyncSession = Depends(db_session),
    limit: int = 50,
    offset: int = 0,
) -> List[PcapFileResponse]:
    result = await db.execute(
        select(PcapFile)
        .order_by(PcapFile.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    files = result.scalars().all()

    return [
        PcapFileResponse(
            id=f.id,
            filename=f.filename,
            interface=f.interface,
            bpf_filter=f.bpf_filter,
            file_size_bytes=f.file_size_bytes,
            packet_count=f.packet_count,
            captured_started_at=f.captured_started_at.isoformat() if f.captured_started_at else None,
            captured_finished_at=f.captured_finished_at.isoformat() if f.captured_finished_at else None,
            indexed_at=f.indexed_at.isoformat() if f.indexed_at else None,
            index_error=f.index_error,
        )
        for f in files
    ]


@router.get(
    "/{pcap_file_id}/packets",
    response_model=PacketQueryResponse,
    summary="Query packets for a PCAP file (cursor pagination)",
    dependencies=[Depends(require_role())],
)
async def query_pcap_packets(
    pcap_file_id: int,
    db: AsyncSession = Depends(db_session),
    limit: int = 200,
    cursor: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
) -> PacketQueryResponse:
    if limit < 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="limit must be >= 1",
        )
    if limit > 1000:
        limit = 1000

    pcap_file = await db.get(PcapFile, pcap_file_id)
    if not pcap_file:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PCAP not found")

    stmt = select(PcapPacket).where(PcapPacket.file_id == pcap_file_id)

    if src_ip:
        stmt = stmt.where(PcapPacket.src_ip == src_ip)
    if dst_ip:
        stmt = stmt.where(PcapPacket.dst_ip == dst_ip)
    if protocol:
        stmt = stmt.where(PcapPacket.protocol == protocol)
    if src_port is not None:
        stmt = stmt.where(PcapPacket.src_port == src_port)
    if dst_port is not None:
        stmt = stmt.where(PcapPacket.dst_port == dst_port)

    if cursor:
        cursor_ts, cursor_idx = _decode_cursor(cursor)
        stmt = stmt.where(
            or_(
                PcapPacket.timestamp > cursor_ts,
                and_(
                    PcapPacket.timestamp == cursor_ts,
                    PcapPacket.packet_index > cursor_idx,
                ),
            )
        )

    stmt = stmt.order_by(PcapPacket.timestamp.asc(), PcapPacket.packet_index.asc()).limit(limit + 1)

    result = await db.execute(stmt)
    packets = result.scalars().all()

    has_more = len(packets) > limit
    if has_more:
        packets = packets[:limit]

    items = [
        PcapPacketResponse(
            id=p.id,
            packet_index=p.packet_index,
            timestamp=p.timestamp.isoformat(),
            src_ip=p.src_ip,
            dst_ip=p.dst_ip,
            src_port=p.src_port,
            dst_port=p.dst_port,
            protocol=p.protocol,
            length=p.length,
        )
        for p in packets
    ]

    next_cursor = None
    if has_more and packets:
        last = packets[-1]
        next_cursor = _encode_cursor(last.timestamp, last.packet_index)

    return PacketQueryResponse(items=items, next_cursor=next_cursor)


@router.get(
    "/{pcap_file_id}/zeek-summary",
    response_model=PcapZeekSummaryResponse,
    summary="Get Zeek summary for a PCAP file",
    dependencies=[Depends(require_role())],
)
async def get_pcap_zeek_summary(
    pcap_file_id: int,
    db: AsyncSession = Depends(db_session),
) -> PcapZeekSummaryResponse:
    pcap_file = await db.get(PcapFile, pcap_file_id)
    if not pcap_file:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PCAP not found")

    if pcap_file.index_error:
        indexing_status = "error"
    elif pcap_file.indexed_at:
        indexing_status = "indexed"
    else:
        indexing_status = "pending"

    return PcapZeekSummaryResponse(
        pcap_file_id=pcap_file_id,
        indexing_status=indexing_status,
        zeek_summary=pcap_file.zeek_summary,
    )
