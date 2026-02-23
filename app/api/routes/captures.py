from __future__ import annotations

from typing import Any, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session
from app.models.packet_capture import PacketCapture, PacketCaptureStatus
from app.services.packet_capture import capture_to_pcap, get_capture_stats, parse_pcap_headers
from app.tasks import packet_capture_recent_task

router = APIRouter()


class StartCaptureRequest(BaseModel):
    duration_seconds: int = 60
    interface: Optional[str] = None
    bpf_filter: Optional[str] = None


class CaptureResponse(BaseModel):
    id: int
    filename: str
    status: str
    interface: Optional[str]
    bpf_filter: Optional[str]
    duration_seconds: int
    packet_count: int
    file_size_bytes: int
    started_at: Optional[str]
    finished_at: Optional[str]
    error_message: Optional[str]

    class Config:
        from_attributes = True


@router.post(
    "/start",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start a new packet capture",
)
async def start_capture(
    payload: StartCaptureRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(db_session),
) -> dict[str, Any]:
    """Start a new packet capture session.
    
    The capture runs asynchronously. Use the returned capture_id to check status.
    """
    if payload.duration_seconds < 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Duration must be at least 1 second"
        )
    
    if payload.duration_seconds > 300:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Duration cannot exceed 300 seconds (5 minutes)"
        )
    
    capture_id = await capture_to_pcap(
        db,
        duration_seconds=payload.duration_seconds,
        iface=payload.interface,
        bpf_filter=payload.bpf_filter,
    )
    
    return {
        "capture_id": capture_id,
        "status": "started",
        "message": f"Capture started for {payload.duration_seconds} seconds"
    }


@router.get(
    "/",
    response_model=List[CaptureResponse],
    summary="List all packet captures",
)
async def list_captures(
    db: AsyncSession = Depends(db_session),
    limit: int = 50,
    offset: int = 0,
) -> List[CaptureResponse]:
    """Retrieve a list of all packet captures."""
    result = await db.execute(
        select(PacketCapture)
        .order_by(PacketCapture.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    captures = result.scalars().all()
    
    return [
        CaptureResponse(
            id=c.id,
            filename=c.filename,
            status=c.status.value,
            interface=c.interface,
            bpf_filter=c.bpf_filter,
            duration_seconds=c.duration_seconds,
            packet_count=c.packet_count,
            file_size_bytes=c.file_size_bytes,
            started_at=c.started_at.isoformat() if c.started_at else None,
            finished_at=c.finished_at.isoformat() if c.finished_at else None,
            error_message=c.error_message,
        )
        for c in captures
    ]


@router.get(
    "/{capture_id}",
    summary="Get capture details",
)
async def get_capture(
    capture_id: int,
    db: AsyncSession = Depends(db_session),
) -> dict[str, Any]:
    """Get detailed information about a specific capture."""
    stats = await get_capture_stats(db, capture_id)
    if not stats:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Capture not found"
        )
    return stats


@router.post(
    "/{capture_id}/parse",
    summary="Parse packet headers from capture",
)
async def parse_capture(
    capture_id: int,
    db: AsyncSession = Depends(db_session),
    max_packets: int = 1000,
) -> dict[str, Any]:
    """Parse and store packet headers from a completed capture."""
    capture = await db.get(PacketCapture, capture_id)
    if not capture:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Capture not found"
        )
    
    if capture.status != PacketCaptureStatus.COMPLETED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Capture is not completed (status: {capture.status.value})"
        )
    
    headers_parsed = await parse_pcap_headers(db, capture_id, max_packets)
    
    return {
        "capture_id": capture_id,
        "headers_parsed": headers_parsed,
        "message": f"Parsed {headers_parsed} packet headers"
    }


@router.delete(
    "/{capture_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a capture",
)
async def delete_capture(
    capture_id: int,
    db: AsyncSession = Depends(db_session),
) -> None:
    """Delete a packet capture and its associated data."""
    from pathlib import Path
    
    capture = await db.get(PacketCapture, capture_id)
    if not capture:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Capture not found"
        )
    
    filepath = Path(capture.filepath)
    if filepath.exists():
        filepath.unlink()
    
    await db.delete(capture)
    await db.commit()
