from __future__ import annotations

import csv
import io
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, require_admin, require_compliance_role
from app.models.device import Device
from app.models.network import Network
from app.services.device_purge import delete_devices
from app.services.network_identity import format_mac, scoped_network_id

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


class NetworkPurge(BaseModel):
    network_id: int
    network_name: str
    deleted_devices: int = Field(description="Device rows removed, with their metrics and findings.")


async def _serialize(db: AsyncSession) -> List[NetworkOut]:
    counts = dict(
        (
            await db.execute(
                select(Device.network_id, func.count(Device.id)).group_by(Device.network_id)
            )
        ).all()
    )
    # ``scoped_network_id`` falls back to the most recently used network when
    # detection is unavailable. The badge and the purge guard must agree, or a
    # network the host cannot currently identify would be marked "safe to
    # delete" here and then be the one it is actually attached to.
    current_id = await scoped_network_id(db)
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
            is_current=current_id is not None and row.id == current_id,
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


async def _networks_this_host_may_be_on(db: AsyncSession) -> set[int]:
    """Rows that must not be treated as "a network this host has left".

    Detection is best-effort and this database already contains two rows for the
    same physical subnet (a router answering with a different gateway MAC on
    different probes), so "the detected row" is not stable enough on its own.
    The most recently used row is protected too: it is what detection falls back
    to when it cannot fingerprint anything.

    This deliberately does not protect every row sharing the current CIDR — home
    and a friend's house are commonly both ``192.168.1.0/24``, and cleaning up
    after a visit is exactly the case this exists for. What it cannot know, the
    operator decides, after reviewing the addresses.
    """
    protected: set[int] = set()
    current_id = await scoped_network_id(db)
    if current_id is not None:
        protected.add(current_id)
    latest = (
        await db.execute(select(Network.id).order_by(Network.last_seen.desc()).limit(1))
    ).scalar_one_or_none()
    if latest is not None:
        protected.add(int(latest))
    return protected


@router.get(
    "/current",
    response_model=Optional[NetworkOut],
    summary="The network this host is attached to",
    dependencies=[Depends(require_compliance_role())],
)
async def current_network(db: AsyncSession = Depends(db_session)) -> Optional[NetworkOut]:
    current_id = await scoped_network_id(db)
    if current_id is None:
        return None
    for item in await _serialize(db):
        if item.id == current_id:
            return item
    return None


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

    if network_id in await _networks_this_host_may_be_on(db):
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


@router.get(
    "/{network_id}/devices/export",
    summary="Download a network's devices as CSV",
    dependencies=[Depends(require_compliance_role())],
)
async def export_network_devices(
    network_id: int,
    db: AsyncSession = Depends(db_session),
) -> StreamingResponse:
    """The same rows the purge preview shows, as a file worth keeping.

    Deleting a network's inventory is irreversible, so the evidence of what was
    seen there — addresses, names, MACs, timestamps — can be downloaded first.
    """
    network = (
        await db.execute(select(Network).where(Network.id == network_id))
    ).scalar_one_or_none()
    if network is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Network not found")

    devices = (
        await db.execute(
            select(Device)
            .where(Device.network_id == network_id)
            .order_by(Device.ip_address)
        )
    ).scalars().all()

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        ["ip_address", "hostname", "mac_address", "device_type", "is_gateway", "last_seen", "created_at"]
    )
    for device in devices:
        writer.writerow(
            [
                device.ip_address,
                device.hostname or "",
                device.mac_address or "",
                device.device_type or "",
                "yes" if device.is_gateway else "no",
                device.last_seen.isoformat() if device.last_seen else "",
                device.created_at.isoformat() if device.created_at else "",
            ]
        )

    filename = f"network-{network_id}-devices.csv"
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.delete(
    "/{network_id}/devices",
    response_model=NetworkPurge,
    summary="Delete every device recorded on a network you have left",
)
async def purge_network_devices(
    network_id: int,
    expected_devices: Optional[int] = Query(
        None,
        description="Count the operator reviewed; refuses if the inventory moved since.",
    ),
    db: AsyncSession = Depends(db_session),
    _user=Depends(require_admin),
) -> NetworkPurge:
    """Empty the inventory of a network this host is not attached to.

    A sweep on a café or a friend's Wi-Fi leaves hundreds of rows behind, and
    back home they are a long list of strangers marked offline. They are real
    observations rather than phantoms, which is why this is an explicit choice
    and not something the app does on its own — but it does the whole job, so
    cleaning up after a trip is one action: devices go, and their metrics,
    findings and ports go with them.

    The current network is refused: its rows are being refreshed right now, and
    deleting them would just mean rediscovering them.
    """
    network = (
        await db.execute(select(Network).where(Network.id == network_id))
    ).scalar_one_or_none()
    if network is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Network not found")

    if network_id in await _networks_this_host_may_be_on(db):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This host is attached to that network right now, so its devices cannot be purged.",
        )

    device_ids = list(
        (
            await db.execute(select(Device.id).where(Device.network_id == network_id))
        ).scalars().all()
    )
    # The operator confirmed a specific list. If the inventory moved underneath
    # that review — because the host is actually back on this network, or a
    # sweep just ran — deleting is no longer what they agreed to.
    if expected_devices is not None and expected_devices != len(device_ids):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"The inventory changed since the review ({len(device_ids)} devices "
                f"now, {expected_devices} reviewed). Review the list again."
            ),
        )

    deleted = await delete_devices(db, device_ids)
    return NetworkPurge(
        network_id=network_id,
        network_name=network.name,
        deleted_devices=deleted,
    )


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
