from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class UptimeTarget(Base):
    __tablename__ = "uptime_targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(128))
    target: Mapped[str] = mapped_column(String(256))
    check_type: Mapped[str] = mapped_column(String(16), default="ping")
    interval_seconds: Mapped[int] = mapped_column(Integer, default=60)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_status: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    last_checked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_latency_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)


class UptimeCheck(Base):
    __tablename__ = "uptime_checks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("uptime_targets.id", ondelete="CASCADE"), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    status: Mapped[str] = mapped_column(String(16))
    latency_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
