from __future__ import annotations

import asyncio
import ipaddress
import re
import shutil
from datetime import datetime
from typing import Any, Dict, List, Sequence

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, require_admin, require_role
from app.models.enforcement_action import EnforcementAction
from app.models.user import User

router = APIRouter()

MAC_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")

_IPTABLES_TABLE = "raw"
_IPTABLES_CHAIN = "PREROUTING"


def _validate_ip(ip: str) -> bool:
    """Validate an IPv4 address."""
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
    except ValueError:
        return False


async def _run_cmd(argv: Sequence[str], timeout_s: float = 5.0) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
    except asyncio.TimeoutError:
        proc.kill()
        stdout, stderr = await proc.communicate()
        return 124, stdout.decode(errors="replace"), stderr.decode(errors="replace")

    return proc.returncode or 0, stdout.decode(errors="replace"), stderr.decode(errors="replace")


async def _iptables_rule_exists(iptables_path: str, rule_args: Sequence[str]) -> bool:
    rc, _, _ = await _run_cmd(
        [iptables_path, "-t", _IPTABLES_TABLE, "-C", _IPTABLES_CHAIN, *rule_args],
        timeout_s=5.0,
    )
    return rc == 0


async def _iptables_ensure_rule(iptables_path: str, rule_args: Sequence[str]) -> None:
    if await _iptables_rule_exists(iptables_path, rule_args):
        return
    await _run_cmd(
        [iptables_path, "-t", _IPTABLES_TABLE, "-I", _IPTABLES_CHAIN, *rule_args],
        timeout_s=5.0,
    )


async def _iptables_delete_rule(iptables_path: str, rule_args: Sequence[str]) -> None:
    # Remove all matching instances (defensive) with a small cap.
    for _ in range(6):
        if not await _iptables_rule_exists(iptables_path, rule_args):
            return
        await _run_cmd(
            [iptables_path, "-t", _IPTABLES_TABLE, "-D", _IPTABLES_CHAIN, *rule_args],
            timeout_s=5.0,
        )


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
    _user: User = Depends(require_admin),
) -> Dict[str, Any]:
    if not _validate_ip(request.ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    current_state = await _get_current_state(db, request.ip)

    iptables_path = shutil.which("iptables")
    note: str | None = None

    if not iptables_path:
        note = "iptables not available - recorded in database only"
    else:
        # Kill-switch: drop traffic to/from the device as early as possible.
        # Use raw/PREROUTING to bypass conntrack.
        try:
            await _iptables_ensure_rule(iptables_path, ["-s", request.ip, "-j", "DROP"])
            await _iptables_ensure_rule(iptables_path, ["-d", request.ip, "-j", "DROP"])
        except Exception:
            # Best-effort: still record the intent in DB.
            note = "Failed to apply iptables rule; recorded in database only"

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
    else:
        timestamp = datetime.utcnow().isoformat()
        note = note or f"Device {request.ip} was already {current_state}"

    payload: Dict[str, Any] = {
        "status": "blocked",
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

    iptables_path = shutil.which("iptables")
    note: str | None = None

    if iptables_path:
        try:
            await _iptables_delete_rule(iptables_path, ["-s", request.ip, "-j", "DROP"])
            await _iptables_delete_rule(iptables_path, ["-d", request.ip, "-j", "DROP"])
        except Exception:
            note = "Failed to remove iptables rule(s); recorded in database only"
    else:
        note = "iptables not available - recorded in database only"

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
        note = note or f"Device {request.ip} was not blocked"

    payload: Dict[str, Any] = {"status": "unblocked", "ip": request.ip}
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

    iptables_path = shutil.which("iptables")
    note: str | None = None

    if iptables_path:
        try:
            await _iptables_ensure_rule(iptables_path, ["-s", request.ip, "-j", "DROP"])
            await _iptables_ensure_rule(iptables_path, ["-d", request.ip, "-j", "DROP"])
        except Exception:
            note = "Failed to apply iptables rule; recorded in database only"
    else:
        note = "iptables not available - recorded in database only"

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

    payload: Dict[str, Any] = {
        "status": "quarantined",
        "ip": request.ip,
        "mac": request.mac,
        "reason": request.reason,
        "timestamp": action.created_at.isoformat(),
    }
    if note:
        payload["note"] = note
    return payload


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


@router.post("/kill-connection")
async def kill_connection(
    request: KillConnectionRequest,
    _user: User = Depends(require_admin),
) -> Dict[str, Any]:
    if not _validate_ip(request.ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    conntrack_path = shutil.which("conntrack")
    if conntrack_path:
        try:
            proc = await asyncio.create_subprocess_exec(
                conntrack_path,
                "-D",
                "-s",
                request.ip,
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
        except Exception as exc:
            return {
                "status": "kill_error",
                "ip": request.ip,
                "error": str(exc),
            }

    ss_path = shutil.which("ss")
    if ss_path:
        try:
            proc = await asyncio.create_subprocess_exec(
                ss_path,
                "-K",
                f"src={request.ip}",
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
        except Exception as exc:
            return {
                "status": "kill_error",
                "ip": request.ip,
                "error": str(exc),
            }

    return {
        "status": "manual_action_required",
        "ip": request.ip,
        "note": "Neither conntrack nor ss with kill support is available.",
    }
