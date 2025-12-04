from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from sqlalchemy import DateTime, String, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    mac_address: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    device_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    os: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    vendor: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    is_gateway: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    metrics: Mapped[List["Metric"]] = relationship(
        "Metric",
        back_populates="device",
        cascade="all, delete-orphan",
    )
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship(
        "Vulnerability",
        back_populates="device",
        cascade="all, delete-orphan",
    )