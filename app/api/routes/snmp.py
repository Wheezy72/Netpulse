from __future__ import annotations

import asyncio
import re
import shutil
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.deps import get_current_user, require_admin
from app.models.user import User

router = APIRouter()


class SnmpPollRequest(BaseModel):
    target: str
    community: str = "public"
    version: str = "2c"
    oids: Optional[List[str]] = None


class SnmpWalkRequest(BaseModel):
    target: str
    community: str = "public"
    oid: str = "1.3.6.1.2.1.1"


COMMON_OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "ifNumber": "1.3.6.1.2.1.2.1.0",
}

OID_TO_LABEL = {v: k for k, v in COMMON_OIDS.items()}

DEFAULT_POLL_OIDS = [
    "1.3.6.1.2.1.1.1.0",
    "1.3.6.1.2.1.1.3.0",
    "1.3.6.1.2.1.1.5.0",
    "1.3.6.1.2.1.1.6.0",
    "1.3.6.1.2.1.2.1.0",
]

IP_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.\-:]+$")
COMMUNITY_PATTERN = re.compile(r"^[\x21-\x7e]{1,64}$")
OID_PATTERN = re.compile(r"^\d+(?:\.\d+)*$")
ALLOWED_VERSIONS = {"1", "2c", "3"}


def _parse_snmp_line(line: str) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line or "=" not in line:
        return None
    match = re.match(r"^(.+?)\s*=\s*(\w+):\s*(.*)$", line)
    if not match:
        match_notype = re.match(r"^(.+?)\s*=\s*(.*)$", line)
        if match_notype:
            oid_part = match_notype.group(1).strip()
            value = match_notype.group(2).strip()
            label = oid_part.split("::")[-1] if "::" in oid_part else oid_part
            label = re.sub(r"\.\d+$", "", label)
            return {"oid": oid_part, "label": label, "value": value, "type": "Unknown"}
        return None
    oid_part = match.group(1).strip()
    value_type = match.group(2).strip()
    value = match.group(3).strip().strip('"')
    label = oid_part.split("::")[-1] if "::" in oid_part else oid_part
    label = re.sub(r"\.\d+$", "", label)
    return {"oid": oid_part, "label": label, "value": value, "type": value_type}


@router.post("/poll")
async def snmp_poll(
    request: SnmpPollRequest,
    current_user: User = Depends(require_admin),
) -> Dict[str, Any]:
    if not IP_PATTERN.match(request.target):
        raise HTTPException(status_code=400, detail="Invalid target format")
    if request.version not in ALLOWED_VERSIONS:
        raise HTTPException(status_code=400, detail="Invalid SNMP version")
    if not COMMUNITY_PATTERN.match(request.community):
        raise HTTPException(status_code=400, detail="Invalid SNMP community string")

    oids = request.oids if request.oids else DEFAULT_POLL_OIDS
    if len(oids) > 50:
        raise HTTPException(status_code=400, detail="Too many OIDs requested")

    normalized_oids: List[str] = []
    for oid in oids:
        oid = str(oid).strip().lstrip(".")
        if not OID_PATTERN.match(oid):
            raise HTTPException(status_code=400, detail=f"Invalid OID: {oid}")
        normalized_oids.append(oid)

    snmpget_path = shutil.which("snmpget")
    if not snmpget_path:
        raise HTTPException(status_code=503, detail="snmpget is not installed on this system")

    version_flag = f"-v{request.version}"
    cmd = [snmpget_path, version_flag, "-c", request.community, request.target] + normalized_oids

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="SNMP poll timed out after 5 seconds")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SNMP poll failed: {str(e)}")

    output = stdout.decode(errors="replace")
    err_output = stderr.decode(errors="replace")

    if proc.returncode != 0 and not output.strip():
        raise HTTPException(status_code=502, detail=f"SNMP poll error: {err_output or 'Unknown error'}")

    results = []
    for line in output.strip().split("\n"):
        parsed = _parse_snmp_line(line)
        if parsed:
            results.append(parsed)

    return {"results": results, "target": request.target}


@router.post("/walk")
async def snmp_walk(
    request: SnmpWalkRequest,
    current_user: User = Depends(require_admin),
) -> Dict[str, Any]:
    if not IP_PATTERN.match(request.target):
        raise HTTPException(status_code=400, detail="Invalid target format")
    if not COMMUNITY_PATTERN.match(request.community):
        raise HTTPException(status_code=400, detail="Invalid SNMP community string")

    request_oid = request.oid.strip().lstrip(".")
    if not OID_PATTERN.match(request_oid):
        raise HTTPException(status_code=400, detail="Invalid OID format")

    snmpwalk_path = shutil.which("snmpwalk")
    if not snmpwalk_path:
        raise HTTPException(status_code=503, detail="snmpwalk is not installed on this system")

    cmd = [snmpwalk_path, "-v2c", "-c", request.community, request.target, request_oid]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="SNMP walk timed out after 30 seconds")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SNMP walk failed: {str(e)}")

    output = stdout.decode(errors="replace")
    err_output = stderr.decode(errors="replace")

    if proc.returncode != 0 and not output.strip():
        raise HTTPException(status_code=502, detail=f"SNMP walk error: {err_output or 'Unknown error'}")

    results = []
    for line in output.strip().split("\n"):
        parsed = _parse_snmp_line(line)
        if parsed:
            results.append(parsed)

    return {"results": results, "target": request.target, "oid": request.oid}


@router.get("/oid-groups")
async def get_oid_groups(
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    return COMMON_OIDS
