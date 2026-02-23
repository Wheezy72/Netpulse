from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, require_role
from app.models.packet_capture import PacketHeader

router = APIRouter()


class PacketHeaderResponse(BaseModel):
    id: int
    capture_id: int
    timestamp: str
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    length: int
    info: Optional[str]


class PacketQueryResponse(BaseModel):
    packets: List[PacketHeaderResponse]
    next_cursor: Optional[int]
    has_more: bool


@router.get(
    "/query",
    response_model=PacketQueryResponse,
    summary="Query packet headers with cursor pagination",
    dependencies=[Depends(require_role())],
)
async def query_packets(
    db: AsyncSession = Depends(db_session),
    capture_id: Optional[int] = None,
    cursor: Optional[int] = None,
    limit: int = 250,
) -> PacketQueryResponse:
    if limit < 1 or limit > 2000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Limit must be between 1 and 2000",
        )

    stmt = select(PacketHeader).order_by(PacketHeader.id.desc())

    if capture_id is not None:
        stmt = stmt.where(PacketHeader.capture_id == capture_id)

    if cursor is not None:
        stmt = stmt.where(PacketHeader.id < cursor)

    stmt = stmt.limit(limit + 1)

    result = await db.execute(stmt)
    rows = result.scalars().all()

    has_more = len(rows) > limit
    if has_more:
        rows = rows[:limit]

    next_cursor = rows[-1].id if has_more and rows else None

    packets = [
        PacketHeaderResponse(
            id=r.id,
            capture_id=r.capture_id,
            timestamp=r.timestamp.isoformat(),
            src_ip=r.src_ip,
            dst_ip=r.dst_ip,
            src_port=r.src_port,
            dst_port=r.dst_port,
            protocol=r.protocol,
            length=r.length,
            info=r.info,
        )
        for r in rows
    ]

    return PacketQueryResponse(packets=packets, next_cursor=next_cursor, has_more=has_more)
