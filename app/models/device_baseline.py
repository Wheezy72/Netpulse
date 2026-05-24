from __future__ import annotations

from datetime import datetime
from datetime import timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class DeviceBaseline(Base):
    __tablename__ = "device_baselines"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    mac_address: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    trusted_state: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    approved_infrastructure_links: Mapped[list[str]] = mapped_column(JSON, default=list)
    network_segment_id: Mapped[int | None] = mapped_column(
        ForeignKey("network_segments.id"),
        nullable=True,
        index=True,
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
