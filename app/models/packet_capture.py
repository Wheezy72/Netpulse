from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class PacketCapture(Base):
    """Represents a capture session that produced a PCAP file and headers."""

    __tablename__ = "packet_captures"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    iface: Mapped[str] = mapped_column(String(64))
    bpf_filter: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    pcap_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    packet_count: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    finished_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    headers: Mapped[list["PacketHeader"]] = relationship(
        "PacketHeader",
        back_populates="capture",
        cascade="all, delete-orphan",
    )


class PacketHeader(Base):
    """Simplified representation of captured packet headers for quick inspection."""

    __tablename__ = "packet_headers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    capture_id: Mapped[int] = mapped_column(
        ForeignKey("packet_captures.id"),
        index=True,
        nullable=False,
    )

    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    src_ip: Mapped[str] = mapped_column(String(64))
    dst_ip: Mapped[str] = mapped_column(String(64))
    src_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(16))
    length: Mapped[int] = mapped_column(Integer)
    info: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    capture: Mapped[PacketCapture] = relationship(
        "PacketCapture",
        back_populates="headers",
    )