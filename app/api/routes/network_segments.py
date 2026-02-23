from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, require_admin, require_role
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
    _user: User = Depends(require_role()),
):
    result = await db.execute(
        select(NetworkSegment).order_by(NetworkSegment.name)
    )
    return result.scalars().all()


@router.post("", response_model=NetworkSegmentOut, status_code=status.HTTP_201_CREATED)
async def create_network_segment(
    segment: NetworkSegmentCreate,
    db: AsyncSession = Depends(db_session),
    _user: User = Depends(require_admin),
):
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
