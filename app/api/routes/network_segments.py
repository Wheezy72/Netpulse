from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, require_admin, require_compliance_role
from app.models.network_segment import NetworkSegment
from app.models.user import User

router = APIRouter()


class NetworkSegmentCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    cidr: str = Field(..., min_length=1, max_length=50)
    description: Optional[str] = None
    vlan_id: Optional[int] = None
    is_active: bool = True
    scan_enabled: bool = True


class NetworkSegmentUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    cidr: Optional[str] = Field(None, min_length=1, max_length=50)
    description: Optional[str] = None
    vlan_id: Optional[int] = None
    is_active: Optional[bool] = None
    scan_enabled: Optional[bool] = None


class NetworkSegmentOut(BaseModel):
    id: int
    name: str
    cidr: str
    description: Optional[str]
    vlan_id: Optional[int]
    is_active: bool
    scan_enabled: bool

    class Config:
        from_attributes = True


@router.get("", response_model=List[NetworkSegmentOut])
async def list_network_segments(
    db: AsyncSession = Depends(db_session),
    _user: User = Depends(require_compliance_role()),
):
    result = await db.execute(
        select(NetworkSegment).order_by(NetworkSegment.name)
    )
    return result.scalars().all()


@router.get("/detect-gateway")
async def detect_gateway(
    _user: User = Depends(require_compliance_role()),
):
    """
    Auto-detect the default gateway of the host system.
    Returns: {"gateway_ip": "..."}
    """
    import sys
    import subprocess
    import socket
    import struct

    # 1. Try Scapy
    try:
        from scapy.all import conf
        route = conf.route.route("0.0.0.0")
        if route and len(route) >= 3 and route[2] and route[2] != "0.0.0.0":
            return {"gateway_ip": str(route[2])}
    except Exception:
        pass

    # 2. Try Linux /proc/net/route
    try:
        with open("/proc/net/route", "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[1] == "00000000":
                    gw_hex = parts[2]
                    res = socket.inet_ntoa(struct.pack("<L", int(gw_hex, 16)))
                    return {"gateway_ip": res}
    except Exception:
        pass

    system = sys.platform.lower()

    # SECURITY RATIONALE:
    # 1. No shell=True is used (we explicitly pass shell=False).
    # 2. All arguments are hardcoded string constants with zero user-controlled input.
    # 3. Execution parameters are strictly restricted to system routes queries.
    # 4. This endpoint requires pre-authenticated Compliance Role privileges.
    if "win" in system:
        # Windows route print
        try:
            out = subprocess.check_output(
                ["route", "print", "0.0.0.0"],
                text=True,
                stderr=subprocess.DEVNULL,
                shell=False
            )
            for line in out.splitlines():
                parts = line.strip().split()
                if len(parts) >= 4 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    return {"gateway_ip": parts[2]}
        except Exception:
            pass

    elif "darwin" in system:
        # macOS route -n get default
        try:
            out = subprocess.check_output(
                ["route", "-n", "get", "default"],
                text=True,
                stderr=subprocess.DEVNULL,
                shell=False
            )
            for line in out.splitlines():
                if "gateway" in line.lower():
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        return {"gateway_ip": parts[1]}
        except Exception:
            pass

    # Fallback to ip route on Linux/macOS
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"],
            text=True,
            stderr=subprocess.DEVNULL,
            shell=False
        )
        parts = out.strip().split()
        if len(parts) >= 3 and parts[1] == "via":
            return {"gateway_ip": parts[2]}
    except Exception:
        pass

    # Final fallback: query local socket connection
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        if local_ip:
            octets = local_ip.split(".")
            if len(octets) == 4:
                return {"gateway_ip": f"{octets[0]}.{octets[1]}.{octets[2]}.1"}
    except Exception:
        pass

    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Unable to auto-detect default gateway."
    )


@router.post("", response_model=NetworkSegmentOut, status_code=status.HTTP_201_CREATED)
async def create_network_segment(
    segment: NetworkSegmentCreate,
    db: AsyncSession = Depends(db_session),
    _user: User = Depends(require_admin),
):
    import ipaddress
    try:
        ipaddress.ip_network(segment.cidr, strict=False)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid CIDR format",
        )

    new_segment = NetworkSegment(
        name=segment.name,
        cidr=segment.cidr,
        description=segment.description,
        vlan_id=segment.vlan_id,
        is_active=segment.is_active,
        scan_enabled=segment.scan_enabled,
    )
    db.add(new_segment)
    await db.commit()
    await db.refresh(new_segment)
    return new_segment


@router.put("/{segment_id}", response_model=NetworkSegmentOut)
async def update_network_segment(
    segment_id: int,
    segment: NetworkSegmentUpdate,
    db: AsyncSession = Depends(db_session),
    _user: User = Depends(require_admin),
):
    result = await db.execute(
        select(NetworkSegment).where(NetworkSegment.id == segment_id)
    )
    existing = result.scalar_one_or_none()

    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Network segment not found",
        )

    if segment.cidr is not None:
        import ipaddress
        try:
            ipaddress.ip_network(segment.cidr, strict=False)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid CIDR format",
            )

    update_data = segment.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(existing, key, value)

    await db.commit()
    await db.refresh(existing)
    return existing


@router.delete("/{segment_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_network_segment(
    segment_id: int,
    db: AsyncSession = Depends(db_session),
    _user: User = Depends(require_admin),
):
    result = await db.execute(
        select(NetworkSegment).where(NetworkSegment.id == segment_id)
    )
    existing = result.scalar_one_or_none()

    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Network segment not found",
        )

    await db.delete(existing)
    await db.commit()
