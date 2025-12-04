from __future__ import annotations

from typing import Optional

from celery.result import AsyncResult
from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, require_role
from app.core.celery_app import celery_app
from app.models.packet_capture import PacketCapture, PacketHeader
from app.models.user import UserRole
from app.tasks import packet_capture_recent_task

# Vault: packet capture and PCAP export. In business networks, these
# endpoints should be restricted to operators and admins.
router = APIRouter()


class CaptureRequest(BaseModel):
    duration_seconds: int = 300
    bpf_filter: Optional[str] = None


class CaptureTaskResponse(BaseModel):
    task_id: str


class CaptureStatusResponse(BaseModel):
    ready: bool
    capture_id: Optional[int] = None
    state: str
    error: Optional[str] = None


class CaptureSummary(BaseModel):
    id: int
    iface: str
    bpf_filter: Optional[str]
    packet_count: int
    created_at: str
    started_at: Optional[str]
    finished_at: Optional[str]


class CaptureDetail(BaseModel):
    capture: CaptureSummary
    headers: list[dict]


@router.post(
    "/pcap/recent",
    response_model=CaptureTaskResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start a time-bounded capture and export as PCAP",
    dependencies=[Depends(require_role(UserRole.OPERATOR, UserRole.ADMIN))],
)
async def start_recent_capture(payload: CaptureRequest) -> CaptureTaskResponse:
    """Trigger a Celery task that captures packets for the requested duration.

    The client receives a task_id and can poll /pcap/task/{task_id} until
    the capture is complete and a PacketCapture row is available.
    """
    if payload.duration_seconds <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="duration_seconds must be positive",
        )

    task = packet_capture_recent_task.delay(
        duration_seconds=payload.duration_seconds,
        bpf_filter=payload.bpf_filter,
    )
    return CaptureTaskResponse(task_id=task.id)


@router.get(
    "/pcap/task/{task_id}",
    response_model=CaptureStatusResponse,
    summary="Check status of a capture task",
)
async def capture_task_status(task_id: str) -> CaptureStatusResponse:
    result = AsyncResult(task_id, app=celery_app)
    if not result.ready():
        return CaptureStatusResponse(
            ready=False,
            capture_id=None,
            state=result.state,
            error=None,
        )

    if result.failed():
        return CaptureStatusResponse(
            ready=True,
            capture_id=None,
            state=result.state,
            error=str(result.result),
        )

    capture_id = int(result.result)
    return CaptureStatusResponse(
        ready=True,
        capture_id=capture_id,
        state=result.state,
        error=None,
    )


@router.get(
    "/pcap/{capture_id}",
    response_model=CaptureDetail,
    summary="Get capture summary and packet headers",
)
async def get_capture(
    capture_id: int,
    db: AsyncSession = Depends(db_session),
) -> CaptureDetail:
    capture = await db.get(PacketCapture, capture_id)
    if capture is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Capture not found")

    result = await db.execute(
        select(PacketHeader).where(PacketHeader.capture_id == capture_id).order_by(PacketHeader.timestamp)
    )
    headers = result.scalars().all()

    summary = CaptureSummary(
        id=capture.id,
        iface=capture.iface,
        bpf_filter=capture.bpf_filter,
        packet_count=capture.packet_count,
        created_at=capture.created_at.isoformat(),
        started_at=capture.started_at.isoformat() if capture.started_at else None,
        finished_at=capture.finished_at.isoformat() if capture.finished_at else None,
    )

    header_dicts = [
        {
            "timestamp": h.timestamp.isoformat(),
            "src_ip": h.src_ip,
            "dst_ip": h.dst_ip,
            "src_port": h.src_port,
            "dst_port": h.dst_port,
            "protocol": h.protocol,
            "length": h.length,
            "info": h.info,
        }
        for h in headers
    ]

    return CaptureDetail(capture=summary, headers=header_dicts)


@router.get(
    "/pcap/{capture_id}/download",
    summary="Download PCAP file for a capture",
)
async def download_pcap(
    capture_id: int,
    db: AsyncSession = Depends(db_session),
) -> Response:
    capture = await db.get(PacketCapture, capture_id)
    if capture is None or not capture.pcap_path:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PCAP not found")

    try:
        data = Path(capture.pcap_path).read_bytes()
    except FileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PCAP file missing") from exc

    return Response(
        content=data,
        media_type="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition": f'attachment; filename="capture_{capture.id}.pcap"'},
    )