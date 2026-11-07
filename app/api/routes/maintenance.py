"""Inventory repairs.

The one repair here is proxy ARP: a router that answers for addresses it does
not own leaves a whole subnet of rows sharing its MAC, and the inventory shows
255 hosts where there is one. Discovery no longer writes those rows, so this is
about the ones already in the database.

``GET`` is a preview and never writes, ``POST .../prune`` deletes what the same
preview would have listed. Both are admin-only.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, require_admin
from app.models.network import Network
from app.models.user import User
from app.services.phantom_devices import (
    DEFAULT_LIMIT,
    Clump,
    apply as apply_purge,
    scan,
)

router = APIRouter()

_LIMIT_QUERY = Query(
    ge=1,
    le=4096,
    description="How many addresses one MAC may hold before it counts as a proxy-ARP clump.",
)


class PhantomKeep(BaseModel):
    """The row that survives a clump: the lowest address, usually the router."""

    id: int
    ip_address: str
    hostname: str | None = None
    is_gateway: bool = False


class PhantomClump(BaseModel):
    network_id: int | None = Field(default=None, description="Network the rows belong to.")
    network_name: str | None = Field(default=None, description="Its name, for display.")
    mac_address: str = Field(description="The MAC all of these addresses answer for.")
    rows: int = Field(description="Rows in the clump, including the one that stays.")
    removable: int = Field(description="Rows that would be deleted.")
    keep: PhantomKeep
    first_dropped: str | None = None
    last_dropped: str | None = None


class PhantomReport(BaseModel):
    limit: int
    inspected: int = Field(description="Device rows read before grouping.")
    removable: int = Field(description="Rows a prune would delete.")
    clumps: list[PhantomClump]


class PhantomPurge(BaseModel):
    deleted: int
    clumps: list[PhantomClump] = Field(description="The clumps that were removed.")


async def _describe(
    db: AsyncSession,
    clumps: list[Clump],
    *,
    inspected: int,
    limit: int,
) -> PhantomReport:
    """Attach network names, because "network 3" is not a place."""
    ids = {clump.network_id for clump in clumps if clump.network_id is not None}
    names: dict[int, str] = {}
    if ids:
        rows = (
            await db.execute(select(Network.id, Network.name, Network.cidr).where(Network.id.in_(ids)))
        ).all()
        for row in rows:
            names[int(row.id)] = row.name or row.cidr or f"network {row.id}"

    return PhantomReport(
        limit=limit,
        inspected=inspected,
        removable=sum(len(clump.delete_ids) for clump in clumps),
        clumps=[
            PhantomClump(
                network_id=clump.network_id,
                network_name=names.get(clump.network_id) if clump.network_id is not None else None,
                mac_address=clump.mac,
                rows=clump.rows,
                removable=len(clump.delete_ids),
                keep=PhantomKeep(
                    id=clump.keep_id,
                    ip_address=clump.keep_ip,
                    hostname=clump.keep_hostname,
                    is_gateway=clump.keep_is_gateway,
                ),
                first_dropped=clump.first_dropped,
                last_dropped=clump.last_dropped,
            )
            for clump in clumps
        ],
    )


@router.get(
    "/phantom-devices",
    response_model=PhantomReport,
    summary="Rows invented by a proxy-ARP router",
)
async def preview_phantom_devices(
    limit: Annotated[int, _LIMIT_QUERY] = DEFAULT_LIMIT,
    db: AsyncSession = Depends(db_session),
    _user: User = Depends(require_admin),
) -> PhantomReport:
    """List the rows a prune would remove, without removing anything.

    Each clump keeps its lowest address, which is the router's own address in
    the layout that produces this, so ``removable`` is always ``rows - 1``.
    """
    clumps, inspected = await scan(db, limit=limit)
    return await _describe(db, clumps, inspected=inspected, limit=limit)


@router.post(
    "/phantom-devices/prune",
    response_model=PhantomPurge,
    summary="Delete the rows invented by a proxy ARP router",
)
async def prune_phantom_devices(
    limit: Annotated[int, _LIMIT_QUERY] = DEFAULT_LIMIT,
    db: AsyncSession = Depends(db_session),
    _user: User = Depends(require_admin),
) -> PhantomPurge:
    """Delete what the preview lists.

    The clumps are recomputed here rather than sent by the client: a request
    body naming device IDs would let a caller delete any device in the
    inventory. Both calls use the same function, so they agree.
    """
    clumps, inspected = await scan(db, limit=limit)
    report = await _describe(db, clumps, inspected=inspected, limit=limit)
    deleted = await apply_purge(db, clumps)
    return PhantomPurge(deleted=deleted, clumps=report.clumps)
