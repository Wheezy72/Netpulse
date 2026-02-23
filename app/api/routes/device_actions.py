from __future__ import annotations

import asyncio
import re
import shutil
from datetime import datetime
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.deps import get_current_user
from app.models.user import User

router = APIRouter()

blocked_devices: Dict[str, Dict[str, Any]] = {}

IP_PATTERN = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)
MAC_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")


def _validate_ip(ip: str) -> bool:
    return bool(IP_PATTERN.match(ip))


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
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    if not _validate_ip(request.ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    if request.ip in blocked_devices:
        raise HTTPException(status_code=409, detail=f"Device {request.ip} is already blocked")

    iptables_path = shutil.which("iptables")
    if not iptables_path:
        blocked_devices[request.ip] = {
            "ip": request.ip,
            "reason": request.reason,
            "timestamp": datetime.utcnow().isoformat(),
            "note": "iptables not available - recorded in memory only",
        }
        return {
            "status": "blocked",
            "ip": request.ip,
            "reason": request.reason,
            "timestamp": blocked_devices[request.ip]["timestamp"],
            "note": "iptables not available - recorded in memory only",
        }

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

    now = datetime.utcnow().isoformat()
    blocked_devices[request.ip] = {
        "ip": request.ip,
        "reason": request.reason,
        "timestamp": now,
    }

    return {
        "status": "blocked",
        "ip": request.ip,
        "reason": request.reason,
        "timestamp": now,
    }


@router.post("/unblock")
async def unblock_device(
    request: UnblockRequest,
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    if not _validate_ip(request.ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    if request.ip not in blocked_devices:
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

    del blocked_devices[request.ip]
    return {"status": "unblocked", "ip": request.ip}


@router.get("/blocked")
async def get_blocked_devices(
    current_user: User = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    return list(blocked_devices.values())


@router.post("/quarantine")
async def quarantine_device(
    request: QuarantineRequest,
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

    now = datetime.utcnow().isoformat()
    blocked_devices[request.ip] = {
        "ip": request.ip,
        "mac": request.mac,
        "reason": request.reason,
        "timestamp": now,
        "type": "quarantine",
    }

    return {
        "status": "quarantined",
        "ip": request.ip,
        "mac": request.mac,
        "reason": request.reason,
        "timestamp": now,
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
