from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, get_current_user
from app.db.session import async_session_factory
from app.models.syslog_event import SyslogEvent
from app.models.user import User

logger = logging.getLogger(__name__)

router = APIRouter()

syslog_listener_task = None
syslog_listener_running = False
_transport = None

SEVERITY_MAP = {
    0: "Emergency",
    1: "Alert",
    2: "Critical",
    3: "Error",
    4: "Warning",
    5: "Notice",
    6: "Info",
    7: "Debug",
}

FACILITY_MAP = {
    0: "kern",
    1: "user",
    2: "mail",
    3: "daemon",
    4: "auth",
    5: "syslog",
    6: "lpr",
    7: "news",
    8: "uucp",
    9: "cron",
    10: "authpriv",
    11: "ftp",
    16: "local0",
    17: "local1",
    18: "local2",
    19: "local3",
    20: "local4",
    21: "local5",
    22: "local6",
    23: "local7",
}


def _parse_syslog_message(data: bytes, addr: tuple) -> Dict[str, Any]:
    raw = data.decode(errors="replace").strip()
    source_ip = addr[0]
    timestamp = datetime.utcnow()
    facility = "unknown"
    severity = "Info"
    hostname = source_ip
    message = raw

    pri_match = re.match(r"^<(\d+)>(.*)$", raw)
    if pri_match:
        pri = int(pri_match.group(1))
        rest = pri_match.group(2)
        facility_num = pri >> 3
        severity_num = pri & 0x07
        facility = FACILITY_MAP.get(facility_num, f"facility-{facility_num}")
        severity = SEVERITY_MAP.get(severity_num, f"severity-{severity_num}")

        ts_match = re.match(
            r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$",
            rest,
        )
        if ts_match:
            hostname = ts_match.group(2)
            message = ts_match.group(3)
        else:
            host_match = re.match(r"^(\S+)\s+(.*)$", rest)
            if host_match:
                hostname = host_match.group(1)
                message = host_match.group(2)
            else:
                message = rest

    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "facility": facility,
        "severity": severity,
        "hostname": hostname,
        "message": message,
    }


async def _persist_syslog_event(parsed: dict[str, Any]) -> None:
    try:
        async with async_session_factory() as session:
            event = SyslogEvent(
                timestamp=parsed["timestamp"],
                source_ip=parsed["source_ip"],
                facility=parsed.get("facility"),
                severity=parsed.get("severity"),
                hostname=parsed.get("hostname"),
                message=parsed.get("message") or "",
            )
            session.add(event)
            await session.commit()
    except Exception as exc:
        logger.warning("Failed to persist syslog event: %s", exc)


class SyslogProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data: bytes, addr: tuple) -> None:
        parsed = _parse_syslog_message(data, addr)
        asyncio.create_task(_persist_syslog_event(parsed))

    def error_received(self, exc: Exception) -> None:
        pass

    def connection_lost(self, exc: Optional[Exception]) -> None:
        pass


@router.get("/messages")
async def get_messages(
    severity: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    conditions = []

    if severity:
        conditions.append(func.lower(func.coalesce(SyslogEvent.severity, "")) == severity.lower())
    if source_ip:
        conditions.append(SyslogEvent.source_ip == source_ip)
    if search:
        search_lower = search.lower()
        conditions.append(
            func.lower(SyslogEvent.message).contains(search_lower)
            | func.lower(func.coalesce(SyslogEvent.hostname, "")).contains(search_lower)
        )

    base_stmt = select(SyslogEvent)
    if conditions:
        base_stmt = base_stmt.where(*conditions)

    count_stmt = select(func.count()).select_from(base_stmt.subquery())
    total = (await db.execute(count_stmt)).scalar_one()

    page_stmt = (
        base_stmt.order_by(SyslogEvent.timestamp.desc())
        .offset(offset)
        .limit(limit)
    )
    events = (await db.execute(page_stmt)).scalars().all()

    messages = [
        {
            "timestamp": e.timestamp.isoformat(),
            "source_ip": e.source_ip,
            "facility": e.facility,
            "severity": e.severity,
            "hostname": e.hostname,
            "message": e.message,
        }
        for e in events
    ]

    return {"messages": messages, "total": total}


@router.post("/start")
async def start_listener(
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    global syslog_listener_running, _transport

    if syslog_listener_running:
        return {"status": "already_running", "port": 1514}

    loop = asyncio.get_event_loop()
    try:
        transport, _ = await loop.create_datagram_endpoint(
            SyslogProtocol,
            local_addr=("0.0.0.0", 1514),
        )
        _transport = transport
        syslog_listener_running = True
        return {"status": "started", "port": 1514}
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"Failed to start syslog listener: {str(e)}")


@router.post("/stop")
async def stop_listener(
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    global syslog_listener_running, _transport

    if not syslog_listener_running:
        return {"status": "not_running"}

    if _transport:
        _transport.close()
        _transport = None

    syslog_listener_running = False
    return {"status": "stopped"}


@router.get("/status")
async def get_status(
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    count_stmt = select(func.count()).select_from(SyslogEvent)
    message_count = (await db.execute(count_stmt)).scalar_one()

    return {
        "running": syslog_listener_running,
        "message_count": message_count,
        "port": 1514,
    }


@router.delete("/messages")
async def clear_messages(
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    await db.execute(delete(SyslogEvent))
    await db.commit()
    return {"status": "cleared"}
