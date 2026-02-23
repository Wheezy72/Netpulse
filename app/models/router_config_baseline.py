from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class RouterConfigBaseline(Base):
    __tablename__ = "router_config_baselines"

    __table_args__ = (
        UniqueConstraint(
            "host",
            "driver",
            "username",
            "port",
            name="uq_router_config_baseline_host_driver_username_port",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    host: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    driver: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    username: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)

    config_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        nullable=False,
        index=True,
    )
