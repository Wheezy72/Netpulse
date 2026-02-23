from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, require_admin
from app.models.device import Device
from app.models.router import Router

router = APIRouter()


class RouterOut(BaseModel):
    id: int
    device_id: int
    host: str
    hostname: Optional[str]
    snmp_version: str
    community: Optional[str]
    port: int
    if_indexes: List[int]
    is_active: bool

    class Config:
        from_attributes = True


class RouterUpsert(BaseModel):
    host: str = Field(..., description="Router IP/host for SNMP polling")
    hostname: Optional[str] = None
    zone: Optional[str] = None

    snmp_version: str = Field("2c", description="SNMP version (supported: 1, 2c)")
    community: Optional[str] = Field(None, description="SNMP community (required for v1/v2c)")
    port: int = Field(161, description="SNMP UDP port")

    if_indexes: List[int] = Field(
        default_factory=list,
        description="Optional list of ifIndex values to poll. If empty, auto-discover all interfaces.",
    )

    is_active: bool = True


@router.get(
    "",
    response_model=List[RouterOut],
    summary="List SNMP router polling targets",
    dependencies=[Depends(require_admin)],
)
async def list_routers(db: AsyncSession = Depends(db_session)) -> List[RouterOut]:
    result = await db.execute(select(Router))
    routers = list(result.scalars().all())

    outs: List[RouterOut] = []
    for r in routers:
        device = await db.get(Device, r.device_id)
        outs.append(
            RouterOut(
                id=r.id,
                device_id=r.device_id,
                host=r.host,
                hostname=device.hostname if device else None,
                snmp_version=r.snmp_version,
                community=r.community,
                port=r.port,
                if_indexes=list(r.if_indexes or []),
                is_active=r.is_active,
            )
        )

    return outs


@router.post(
    "",
    response_model=RouterOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create or update an SNMP router polling target",
    dependencies=[Depends(require_admin)],
)
async def upsert_router(
    payload: RouterUpsert,
    db: AsyncSession = Depends(db_session),
) -> RouterOut:
    result = await db.execute(select(Device).where(Device.ip_address == payload.host))
    device = result.scalar_one_or_none()

    if device is None:
        device = Device(
            ip_address=payload.host,
            hostname=payload.hostname,
            device_type="router",
            zone=payload.zone,
            is_gateway=False,
            last_seen=None,
        )
        db.add(device)
        await db.flush()
    else:
        if payload.hostname is not None:
            device.hostname = payload.hostname
        if payload.zone is not None:
            device.zone = payload.zone
        if not device.device_type:
            device.device_type = "router"

    if (payload.snmp_version or "").lower().strip() in {"1", "v1", "2c"}:
        if not (payload.community or "").strip():
            raise HTTPException(status_code=400, detail="community is required for SNMPv1/v2c")

    router_result = await db.execute(select(Router).where(Router.device_id == device.id))
    router_row = router_result.scalar_one_or_none()

    if router_row is None:
        router_row = Router(
            device_id=device.id,
            host=payload.host,
            snmp_version=payload.snmp_version,
            community=payload.community,
            port=payload.port,
            if_indexes=payload.if_indexes,
            is_active=payload.is_active,
        )
        db.add(router_row)
        await db.flush()
    else:
        router_row.host = payload.host
        router_row.snmp_version = payload.snmp_version
        router_row.community = payload.community
        router_row.port = payload.port
        router_row.if_indexes = payload.if_indexes
        router_row.is_active = payload.is_active

    await db.commit()

    return RouterOut(
        id=router_row.id,
        device_id=device.id,
        host=router_row.host,
        hostname=device.hostname,
        snmp_version=router_row.snmp_version,
        community=router_row.community,
        port=router_row.port,
        if_indexes=list(router_row.if_indexes or []),
        is_active=router_row.is_active,
    )


@router.delete(
    "/{router_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an SNMP router polling target",
    dependencies=[Depends(require_admin)],
)
async def delete_router(
    router_id: int,
    db: AsyncSession = Depends(db_session),
) -> None:
    router_row = await db.get(Router, router_id)
    if router_row is None:
        raise HTTPException(status_code=404, detail="Router not found")

    await db.delete(router_row)
    await db.commit()
