from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.core.clock import utcnow


class DevicePort(Base):
    """An open port observed on a device by a per-device deep scan.

    This is the "more detail" half of the discovery story: the light sweep
    answers *which hosts exist* and stores nothing but identity, while a
    per-device deep scan fills this table with what is actually listening.

    Rows describe the **currently observed** state — a successful scan replaces
    the previous set for that device — so the drawer never shows a port that
    was closed by a later scan.
    """

    __tablename__ = "device_ports"
    __table_args__ = (
        UniqueConstraint("device_id", "port", "protocol", name="uq_device_ports_device_port_proto"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), nullable=False, default="tcp")

    # nmap's view of the port: open / closed / filtered / open|filtered
    state: Mapped[Optional[str]] = mapped_column(String(24), nullable=True)
    service: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    product: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    extra_info: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Raw banner / NSE script output for this port, when the scan captured any.
    banner: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        onupdate=utcnow,
        nullable=False,
    )

    device: Mapped["Device"] = relationship("Device", back_populates="ports")
