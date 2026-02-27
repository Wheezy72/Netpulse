from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import shutil
from datetime import datetime
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, require_admin, require_role
from app.core.config import settings
from app.models.enforcement_action import EnforcementAction
from app.models.user import User

router = APIRouter()
logger = logging.getLogger(__name__)

MAC_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")


def _validate_ip(ip: str) -> bool:
    """Validate an IPv4 address."""
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
    except ValueError:
        return False


async def _get_latest_action(db: AsyncSession, ip: str) -> EnforcementAction | None:
    stmt = (
        select(EnforcementAction)
        .where(EnforcementAction.ip == ip)
        .order_by(EnforcementAction.created_at.desc())
        .limit(1)
    )
    return (await db.execute(stmt)).scalars().first()


async def _get_current_state(db: AsyncSession, ip: str) -> str | None:
    latest = await _get_latest_action(db, ip)
    if latest is None:
        return None
    return latest.action_type


class BlockRequest(BaseModel):
    ip: str
    reason: str


class UnblockRequest(BaseModel):
    ip: str


class QuarantineRequest(BaseModel):
    ip: str
    mac: str
    reason: str


class ArpFixRequest(BaseModel):
    target_ip: str
    correct_mac: str


class AttemptKickRequest(BaseModel):
    ip: str
    duration_s: float = Field(8.0, ge=1.0, le=60.0)


@router.post("/block")
async def block_device(
    request: BlockRequest,
    db: AsyncSession = Depends(db_session),
    _user: User = Depends(require_admin),
) -> Dict[str, Any]:
    if not _validate_ip(request.ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    current_state = await _get_current_state(db, request.ip)
    note: str | None = None

    # Idempotent behaviour: if it's already blocked/quarantined, don't error.
    if current_state not in {"block", "quarantine"}:
        action = EnforcementAction(
            ip=request.ip,
            mac=None,
            action_type="block",
            reason=request.reason,
            created_at=datetime.utcnow(),
        )
        db.add(action)
        await db.commit()
        await db.refresh(action)
        timestamp = action.created_at.isoformat()
        state = action.action_type
    else:
        timestamp = datetime.utcnow().isoformat()
        state = current_state
        note = f"Device {request.ip} was already {current_state}"

    payload: Dict[str, Any] = {
        "status": "blocked",
        "state": state,
        "ip": request.ip,
        "reason": request.reason,
        "timestamp": timestamp,
    }
    if note:
        payload["note"] = note

    return payload


@router.post("/unblock")
async def unblock_device(
    request: UnblockRequest,
    db: AsyncSession = Depends(db_session),
    _user: User = Depends(require_admin),
) -> Dict[str, Any]:
    if not _validate_ip(request.ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    current_state = await _get_current_state(db, request.ip)
    note: str | None = None

    # Idempotent: if it's already unblocked, return OK without inserting noise.
    if current_state in {"block", "quarantine"}:
        db.add(
            EnforcementAction(
                ip=request.ip,
                mac=None,
                action_type="unblock",
                reason=None,
                created_at=datetime.utcnow(),
            )
        )
        await db.commit()
    else:
        note = f"Device {request.ip} was not blocked"

    payload: Dict[str, Any] = {"status": "unblocked", "state": "unblock", "ip": request.ip}
    if note:
        payload["note"] = note
    return payload


@router.get("/blocked")
async def get_blocked_devices(
    db: AsyncSession = Depends(db_session),
    _user: User = Depends(require_role()),
) -> List[Dict[str, Any]]:
    stmt = select(EnforcementAction).order_by(EnforcementAction.created_at.desc())
    actions = (await db.execute(stmt)).scalars().all()

    latest_by_ip: Dict[str, EnforcementAction] = {}
    for action in actions:
        if action.ip not in latest_by_ip:
            latest_by_ip[action.ip] = action

    devices: List[Dict[str, Any]] = []
    for ip, action in latest_by_ip.items():
        if action.action_type not in {"block", "quarantine"}:
            continue

        item: Dict[str, Any] = {
            "ip": action.ip,
            "reason": action.reason,
            "timestamp": action.created_at.isoformat(),
        }
        if action.mac:
            item["mac"] = action.mac
        if action.action_type == "quarantine":
            item["type"] = "quarantine"

        devices.append(item)

    devices.sort(key=lambda d: d.get("timestamp", ""), reverse=True)
    return devices


@router.post("/quarantine")
async def quarantine_device(
    request: QuarantineRequest,
    db: AsyncSession = Depends(db_session),
    _user: User = Depends(require_admin),
) -> Dict[str, Any]:
    if not _validate_ip(request.ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    if not MAC_PATTERN.match(request.mac):
        raise HTTPException(status_code=400, detail="Invalid MAC address format")

    action = EnforcementAction(
        ip=request.ip,
        mac=request.mac,
        action_type="quarantine",
        reason=request.reason,
        created_at=datetime.utcnow(),
    )
    db.add(action)
    await db.commit()
    await db.refresh(action)

    return {
        "status": "quarantined",
        "state": action.action_type,
        "ip": request.ip,
        "mac": request.mac,
        "reason": request.reason,
        "timestamp": action.created_at.isoformat(),
    }


@router.post("/arp-fix")
async def arp_fix(
    request: ArpFixRequest,
    _user: User = Depends(require_admin),
) -> Dict[str, Any]:
    if not _validate_ip(request.target_ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    if not MAC_PATTERN.match(request.correct_mac):
        raise HTTPException(status_code=400, detail="Invalid MAC address format")

    arping_path = shutil.which("arping")
    if arping_path:
        try:
            proc = await asyncio.create_subprocess_exec(
                arping_path,
                "-c",
                "3",
                "-S",
                request.target_ip,
                request.target_ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            return {
                "status": "arp_fix_sent",
                "target_ip": request.target_ip,
                "correct_mac": request.correct_mac,
                "output": stdout.decode(errors="replace"),
            }
        except asyncio.TimeoutError:
            return {
                "status": "arp_fix_timeout",
                "target_ip": request.target_ip,
                "correct_mac": request.correct_mac,
                "note": "arping timed out after 10 seconds",
            }
        except Exception as exc:
            return {
                "status": "arp_fix_error",
                "target_ip": request.target_ip,
                "correct_mac": request.correct_mac,
                "error": str(exc),
            }

    return {
        "status": "manual_action_required",
        "target_ip": request.target_ip,
        "correct_mac": request.correct_mac,
        "note": "arping is not available. Please manually send corrective ARP responses.",
    }


async def _attempt_kick_worker(target_ip: str, duration_s: float) -> None:
    """Best-effort L2 disruption via ARP poisoning.

    NetPulse runs as a side-node; it cannot reliably block traffic with iptables.
    This worker uses the existing Scapy-based ARP spoofing service as a best-effort
    attempt to disrupt the target host on the local broadcast domain.

    NOTE: This requires CAP_NET_RAW (typically root) and the target must be on the
    same L2 segment.
    """

    def _kick() -> None:
        import time

        from app.services import arp_spoof

        gateway_ip = settings.pulse_gateway_ip
        if not _validate_ip(gateway_ip):
            raise RuntimeError("Invalid pulse_gateway_ip setting")

        session = arp_spoof.poison(target_ip, gateway_ip, iface=None, interval=1.0)
        time.sleep(duration_s)
        session.stop(restore_network=True)

    try:
        await asyncio.to_thread(_kick)
    except Exception:
        logger.exception("Attempt-kick failed for %s", target_ip)


@router.post("/attempt-kick")
async def attempt_kick(
    request: AttemptKickRequest,
    _user: User = Depends(require_admin),
) -> Dict[str, Any]:
    if not _validate_ip(request.ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    asyncio.create_task(_attempt_kick_worker(request.ip, request.duration_s))
    return {"status": "kick_scheduled", "ip": request.ip, "duration_s": request.duration_s}
