from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import DateTime, Float, ForeignKey, Integer, JSON, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Metric(Base):
    """Time-series metric stored in TimescaleDB.

    The `metrics` table is intended to be converted into a Timescale
    hypertable on the `timestamp` column via a migration:

        SELECT create_hypertable('metrics', 'timestamp', if_not_exists =&gt; TRUE);
    """

    __tablename__ = "metrics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    device_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("devices.id"),
        nullable=True,
        index=True,
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        index=True,
    )

    metric_type: Mapped[str] = mapped_column(String(64), index=True)
    value: Mapped[float] = mapped_column(Float)

    tags: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)

    device: Mapped[Optional["Device"]] = relationship(
        "Device",
        back_populates="metrics",
    )