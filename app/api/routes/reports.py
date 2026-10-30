from __future__ import annotations

import io
from datetime import datetime, timedelta
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, get_current_user
from app.models.device import Device
from app.models.scan_job import ScanJob
from app.models.user import User
from app.services.pdf_report import (
    build_inventory_pdf,
    build_logs_pdf,
    build_scan_pdf,
    fallback_pdf,
)
from app.core.clock import utcnow

router = APIRouter()


class ReportRequest(BaseModel):
    report_type: str
    title: Optional[str] = None
    include_devices: bool = True
    include_metrics: bool = True
    include_alerts: bool = True
    date_range_days: int = 7


class ReportMetadata(BaseModel):
    id: str
    name: str
    report_type: str
    created_at: str
    file_size: int


def _generate_short_name(report_type: str, date_range_days: int = 7) -> str:
    """Generate a readable report name like NetReport_Jan17-24_2026."""
    now = datetime.now()
    start_date = now - timedelta(days=date_range_days)

    if start_date.month == now.month:
        date_range = f"{start_date.strftime('%b')}{start_date.day}-{now.day}"
    else:
        date_range = f"{start_date.strftime('%b%d')}-{now.strftime('%b%d')}"

    year = now.strftime("%Y")
    suffix = "" if report_type in ("", "network_summary") else f"_{report_type.replace('_', '-')}"
    return f"NetReport_{date_range}_{year}{suffix}"


def _device_is_online(device: Any, window_minutes: int = 10) -> bool:
    """A device counts as online when it was seen in the last few minutes.

    ``Device`` has no ``is_online`` column; deriving it from ``last_seen`` is
    the same rule the Devices view uses, and keeps the report honest instead
    of raising AttributeError.
    """
    last_seen = getattr(device, "last_seen", None)
    if last_seen is None:
        return False
    if last_seen.tzinfo is not None:
        now = datetime.now(last_seen.tzinfo)
    else:
        now = utcnow()
    try:
        return (now - last_seen).total_seconds() <= window_minutes * 60
    except TypeError:
        # Mixed naive/aware datetimes — compare as naive UTC.
        return (
            utcnow().replace(tzinfo=None) - last_seen.replace(tzinfo=None)
        ).total_seconds() <= window_minutes * 60


def _pdf_response(content: bytes, filename: str) -> StreamingResponse:
    return StreamingResponse(
        io.BytesIO(content),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}.pdf"'},
    )


@router.post(
    "/generate",
    summary="Generate a PDF report",
)
async def generate_report(
    request: ReportRequest,
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> StreamingResponse:
    """Generate the inventory report for the requested report type."""
    short_name = _generate_short_name(request.report_type, request.date_range_days)
    title = request.title or f"NetPulse {request.report_type.replace('_', ' ').title()} Report"

    devices: List[Any] = []
    if request.include_devices:
        result = await db.execute(select(Device).limit(500))
        devices = list(result.scalars().all())

    try:
        content = build_inventory_pdf(
            devices=devices,
            title=title,
            report_type=request.report_type,
            is_online=_device_is_online,
        )
    except ImportError:  # pragma: no cover - reportlab missing
        content = fallback_pdf(title, "reportlab is not installed on this host")

    response = _pdf_response(content, short_name)
    response.headers["X-Report-Name"] = short_name
    _ = current_user
    return response


@router.get(
    "/types",
    summary="List available report types",
)
async def list_report_types(
    current_user: User = Depends(get_current_user),
) -> List[dict[str, str]]:
    """Get all available report types."""
    _ = current_user
    return [
        {"id": "network_summary", "name": "Network Summary", "description": "Overview of all network devices and status"},
        {"id": "security_audit", "name": "Security Audit", "description": "Security posture assessment"},
        {"id": "device_inventory", "name": "Device Inventory", "description": "Complete list of discovered devices"},
        {"id": "performance", "name": "Performance Report", "description": "Network performance metrics"},
        {"id": "incident", "name": "Incident Report", "description": "Recent incidents and alerts"},
        {"id": "compliance", "name": "Compliance Report", "description": "Compliance status and findings"},
    ]


@router.get(
    "/devices/pdf",
    summary="Generate device inventory PDF",
)
async def generate_devices_pdf(
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> StreamingResponse:
    """Generate a PDF report of all discovered devices."""
    _ = current_user
    result = await db.execute(select(Device).order_by(Device.ip_address).limit(500))
    devices = list(result.scalars().all())

    try:
        content = build_inventory_pdf(
            devices=devices,
            title="Device Inventory Report",
            report_type="device_inventory",
            is_online=_device_is_online,
        )
    except ImportError:  # pragma: no cover - reportlab missing
        content = fallback_pdf("Device Inventory Report", "reportlab is not installed")

    now = datetime.now()
    filename = f"Devices_{now.strftime('%b%d')}_{now.strftime('%Y')}"
    return _pdf_response(content, filename)


class LogsPDFRequest(BaseModel):
    level: Optional[str] = None
    limit: int = 500


@router.post(
    "/logs/pdf",
    summary="Generate logs PDF",
)
async def generate_logs_pdf(
    request: LogsPDFRequest = LogsPDFRequest(),
    current_user: User = Depends(get_current_user),
) -> StreamingResponse:
    """Generate a PDF report of application logs."""
    _ = current_user
    from app.services.logging_service import memory_handler

    logs_data = memory_handler.get_logs(level=request.level, limit=max(1, min(request.limit, 1000)))
    logs = [log.to_dict() for log in logs_data]
    total = memory_handler.get_stats().get("total", len(logs))

    try:
        content = build_logs_pdf(logs=logs, total=total, level_filter=request.level)
    except ImportError:  # pragma: no cover - reportlab missing
        content = fallback_pdf("Application log report", f"{len(logs)} entries")

    now = datetime.now()
    filename = f"Logs_{now.strftime('%b%d')}_{now.strftime('%Y')}"
    return _pdf_response(content, filename)


class ScanResultsPDFRequest(BaseModel):
    scan_id: Optional[str] = None
    scan_type: Optional[str] = None
    target: Optional[str] = None
    results: Optional[str] = None
    command: Optional[str] = None


@router.post(
    "/scan/pdf",
    summary="Generate scan results PDF",
)
async def generate_scan_pdf(
    request: ScanResultsPDFRequest,
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> StreamingResponse:
    """Generate a PDF report of scan results.

    With a ``scan_id`` the report is built from the stored job and its artifact,
    so it reflects the scan that ran rather than whatever the caller pasted in.
    """
    _ = current_user
    summary: dict[str, Any] | None = None
    results = request.results or ""
    scan_type = request.scan_type
    target = request.target
    command = request.command

    if request.scan_id:
        job = await db.get(ScanJob, request.scan_id)
        if job is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found",
            )
        scan_type = scan_type or job.profile
        target = target or job.target
        summary = job.result_summary or None
        if not results and job.artifact_path:
            try:
                with open(job.artifact_path, "r", encoding="utf-8", errors="replace") as handle:
                    results = handle.read()
            except OSError:
                results = "The scan artifact is no longer on disk."
        command = command or (summary or {}).get("command")  # type: ignore[assignment]

    try:
        content = build_scan_pdf(
            scan_type=scan_type,
            target=target,
            command=command,
            results=results,
            summary=summary,
        )
    except ImportError:  # pragma: no cover - reportlab missing
        content = fallback_pdf("Scan report", f"{scan_type or 'scan'} on {target or 'unknown target'}")

    now = datetime.now()
    filename = f"Scan_{scan_type or 'results'}_{now.strftime('%b%d_%H%M')}"
    return _pdf_response(content, filename)
