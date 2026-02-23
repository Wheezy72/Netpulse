from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Router(Base):
    __tablename__ = "routers"

    __table_args__ = (
        UniqueConstraint("device_id", name="uq_routers_device_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    # Link to the Device inventory entry for this router.
    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # SNMP target host/IP (duplicated for convenience; should match Device.ip_address).
    host: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # Supported: "1", "2c".
    snmp_version: Mapped[str] = mapped_column(String(8), default="2c", nullable=False)
    community: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    port: Mapped[int] = mapped_column(Integer, default=161, nullable=False)

    # Optional ifIndex selection. If empty, the poller will auto-discover ifIndexes.
    if_indexes: Mapped[List[int]] = mapped_column(JSON, default=list)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    device: Mapped["Device"] = relationship("Device")

    interface_counters: Mapped[List["RouterInterfaceCounter"]] = relationship(
        "RouterInterfaceCounter",
        back_populates="router",
        cascade="all, delete-orphan",
    )


class RouterInterfaceCounter(Base):
    __tablename__ = "router_interface_counters"

    __table_args__ = (
        UniqueConstraint(
            "router_id",
            "if_index",
            name="uq_router_interface_counters_router_id_if_index",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    router_id: Mapped[int] = mapped_column(
        ForeignKey("routers.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    if_index: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    if_descr: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    in_octets: Mapped[int] = mapped_column(BigInteger, nullable=False)
    out_octets: Mapped[int] = mapped_column(BigInteger, nullable=False)

    last_polled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        nullable=False,
        index=True,
    )

    router: Mapped[Router] = relationship("Router", back_populates="interface_counters")
