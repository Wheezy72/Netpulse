from __future__ import annotations

import asyncio
import re
import shutil
from datetime import datetime
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, get_current_user
from app.models.enforcement_action import EnforcementAction
from app.models.user import User

router = APIRouter()

IP_PATTERN = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)
MAC_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")


def _validate_ip(ip: str) -> bool:
    return bool(IP_PATTERN.match(ip))


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


class KillConnectionRequest(BaseModel):
    ip: str


@router.post("/block")
async def block_device(
    request: BlockRequest,
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    if not _validate_ip(request.ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    current_state = await _get_current_state(db, request.ip)
    if current_state in {"block", "quarantine"}:
        raise HTTPException(status_code=409, detail=f"Device {request.ip} is already blocked")

    iptables_path = shutil.which("iptables")
    note: str | None = None

    if not iptables_path:
        note = "iptables not available - recorded in database only"
    else:
        try:
            proc = await asyncio.create_subprocess_exec(
                iptables_path, "-I", "FORWARD", "-s", request.ip, "-j", "DROP",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=5)

            proc2 = await asyncio.create_subprocess_exec(
                iptables_path, "-I", "FORWARD", "-d", request.ip, "-j", "DROP",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc2.communicate(), timeout=5)
        except Exception:
            pass

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

    payload: Dict[str, Any] = {
        "status": "blocked",
        "ip": request.ip,
        "reason": request.reason,
        "timestamp": action.created_at.isoformat(),
    }
    if note:
        payload["note"] = note

    return payload


@router.post("/unblock")
async def unblock_device(
    request: UnblockRequest,
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    if not _validate_ip(request.ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    current_state = await _get_current_state(db, request.ip)
    if current_state not in {"block", "quarantine"}:
        raise HTTPException(status_code=404, detail=f"Device {request.ip} is not blocked")

    iptables_path = shutil.which("iptables")
    if iptables_path:
        try:
            proc = await asyncio.create_subprocess_exec(
                iptables_path, "-D", "FORWARD", "-s", request.ip, "-j", "DROP",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=5)

            proc2 = await asyncio.create_subprocess_exec(
                iptables_path, "-D", "FORWARD", "-d", request.ip, "-j", "DROP",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc2.communicate(), timeout=5)
        except Exception:
            pass

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

    return {"status": "unblocked", "ip": request.ip}


@router.get("/blocked")
async def get_blocked_devices(
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
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
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    if not _validate_ip(request.ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    if not MAC_PATTERN.match(request.mac):
        raise HTTPException(status_code=400, detail="Invalid MAC address format")

    iptables_path = shutil.which("iptables")
    if iptables_path:
        try:
            proc = await asyncio.create_subprocess_exec(
                iptables_path, "-I", "FORWARD", "-s", request.ip, "-j", "DROP",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=5)

            proc2 = await asyncio.create_subprocess_exec(
                iptables_path, "-I", "FORWARD", "-d", request.ip, "-j", "DROP",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc2.communicate(), timeout=5)
        except Exception:
            pass

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
        "ip": request.ip,
        "mac": request.mac,
        "reason": request.reason,
        "timestamp": action.created_at.isoformat(),
    }


@router.post("/arp-fix")
async def arp_fix(
    request: ArpFixRequest,
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    if not _validate_ip(request.target_ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    if not MAC_PATTERN.match(request.correct_mac):
        raise HTTPException(status_code=400, detail="Invalid MAC address format")

    arping_path = shutil.which("arping")
    if arping_path:
        try:
            proc = await asyncio.create_subprocess_exec(
                arping_path, "-c", "3", "-S", request.target_ip, request.target_ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
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
        except Exception as e:
            return {
                "status": "arp_fix_error",
                "target_ip": request.target_ip,
                "correct_mac": request.correct_mac,
                "error": str(e),
            }

    return {
        "status": "manual_action_required",
        "target_ip": request.target_ip,
        "correct_mac": request.correct_mac,
        "note": "arping is not available. Please manually send corrective ARP responses.",
    }


@router.post("/kill-connection")
async def kill_connection(
    request: KillConnectionRequest,
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    if not _validate_ip(request.ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    conntrack_path = shutil.which("conntrack")
    if conntrack_path:
        try:
            proc = await asyncio.create_subprocess_exec(
                conntrack_path, "-D", "-s", request.ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)
            output = stdout.decode(errors="replace") + stderr.decode(errors="replace")
            return {
                "status": "connections_killed",
                "ip": request.ip,
                "output": output.strip(),
            }
        except Exception as e:
            return {
                "status": "kill_error",
                "ip": request.ip,
                "error": str(e),
            }

    ss_path = shutil.which("ss")
    if ss_path:
        try:
            proc = await asyncio.create_subprocess_exec(
                ss_path, "-K", f"src={request.ip}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)
            output = stdout.decode(errors="replace") + stderr.decode(errors="replace")
            return {
                "status": "connections_killed",
                "ip": request.ip,
                "tool": "ss",
                "output": output.strip(),
            }
        except Exception as e:
            return {
                "status": "kill_error",
                "ip": request.ip,
                "error": str(e),
            }

    return {
        "status": "manual_action_required",
        "ip": request.ip,
        "note": "Neither conntrack nor ss with kill support is available.",
    }
