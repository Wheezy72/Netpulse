from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, require_admin, require_compliance_role
from app.models.device import Device
from app.models.network import Network
from app.services.network_identity import format_mac, resolve_current_network

router = APIRouter()


class NetworkOut(BaseModel):
    """A remembered network plus what the operator needs to recognise it."""

    id: int
    name: str
    cidr: str
    gateway_ip: Optional[str] = None
    gateway_mac: Optional[str] = None
    interface: Optional[str] = None
    device_count: int = 0
    is_current: bool = False
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class NetworkUpdate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)


async def _serialize(db: AsyncSession) -> List[NetworkOut]:
    counts = dict(
        (
            await db.execute(
                select(Device.network_id, func.count(Device.id)).group_by(Device.network_id)
            )
        ).all()
    )
    current = await resolve_current_network(db)
    rows = list((await db.execute(select(Network).order_by(Network.first_seen))).scalars().all())

    return [
        NetworkOut(
            id=row.id,
            name=row.name,
            cidr=row.cidr,
            gateway_ip=row.gateway_ip,
            gateway_mac=format_mac(row.gateway_mac),
            interface=row.interface,
            device_count=int(counts.get(row.id, 0)),
            is_current=current is not None and row.id == current.id,
            first_seen=row.first_seen,
            last_seen=row.last_seen,
        )
        for row in rows
    ]


@router.get(
    "",
    response_model=List[NetworkOut],
    summary="List remembered networks",
    dependencies=[Depends(require_compliance_role())],
)
async def list_networks(db: AsyncSession = Depends(db_session)) -> List[NetworkOut]:
    """Every network this host has been attached to, oldest first.

    Listing also registers the network the host is on right now, so the first
    page load after moving to a new network already shows it.
    """
    return await _serialize(db)


@router.get(
    "/current",
    response_model=Optional[NetworkOut],
    summary="The network this host is attached to",
    dependencies=[Depends(require_compliance_role())],
)
async def current_network(db: AsyncSession = Depends(db_session)) -> Optional[NetworkOut]:
    network = await resolve_current_network(db)
    if network is None:
        return None
    for item in await _serialize(db):
        if item.id == network.id:
            return item
    return None


async def _current_network_id(db: AsyncSession) -> Optional[int]:
    try:
        current = await resolve_current_network(db)
    except Exception:  # pragma: no cover - detection is best-effort
        return None
    return current.id if current is not None else None


@router.delete(
    "/{network_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Forget a network",
)
async def delete_network(
    network_id: int,
    db: AsyncSession = Depends(db_session),
    _user=Depends(require_admin),
) -> None:
    """Remove a remembered network.

    Only networks this host is *not* attached to can go: deleting the current
    one would immediately be undone by the next detection, and its devices
    would be orphaned in between. Duplicates that detection created are folded
    together automatically, so what is left here is a network the operator
    really did leave.
    """
    network = (
        await db.execute(select(Network).where(Network.id == network_id))
    ).scalar_one_or_none()
    if network is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Network not found")

    if await _current_network_id(db) == network_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This host is attached to that network right now, so it cannot be forgotten.",
        )

    await db.execute(
        update(Device).where(Device.network_id == network_id).values(network_id=None)
    )
    await db.delete(network)
    await db.commit()


@router.post(
    "/dedupe",
    response_model=List[NetworkOut],
    summary="Fold duplicate rows for the same network together",
)
async def dedupe_networks(
    db: AsyncSession = Depends(db_session),
    _user=Depends(require_admin),
) -> List[NetworkOut]:
    """Collapse rows that share a gateway MAC.

    Detection used to key a network on its subnet, so a sweep that could not
    read the subnet created a second row for the same router. Resolving the
    current network folds those in; this endpoint also cleans up duplicates
    that belong to networks the host has since left.
    """
    rows = list(
        (await db.execute(select(Network).order_by(Network.first_seen))).scalars().all()
    )
    seen: dict[str, Network] = {}
    for row in rows:
        mac = (row.gateway_mac or "").upper()
        if not mac:
            continue
        keep = seen.get(mac)
        if keep is None:
            seen[mac] = row
            continue
        await db.execute(
            update(Device).where(Device.network_id == row.id).values(network_id=keep.id)
        )
        if row.first_seen and (keep.first_seen is None or row.first_seen < keep.first_seen):
            keep.first_seen = row.first_seen
        await db.delete(row)

    await db.commit()
    return await _serialize(db)


@router.patch(
    "/{network_id}",
    response_model=NetworkOut,
    summary="Rename a network",
)
async def rename_network(
    network_id: int,
    payload: NetworkUpdate,
    db: AsyncSession = Depends(db_session),
    _user=Depends(require_admin),
) -> NetworkOut:
    network = (
        await db.execute(select(Network).where(Network.id == network_id))
    ).scalar_one_or_none()
    if network is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Network not found",
        )

    network.name = payload.name.strip()
    await db.commit()
    await db.refresh(network)

    for item in await _serialize(db):
        if item.id == network.id:
            return item
    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Network vanished")
