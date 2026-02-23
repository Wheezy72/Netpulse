from __future__ import annotations

from datetime import datetime
from enum import Enum

from sqlalchemy import DateTime, Enum as SAEnum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class PacketCaptureStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class PacketCapture(Base):
    """Represents a packet capture session (PCAP file)."""

    __tablename__ = "packet_captures"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    filepath: Mapped[str] = mapped_column(String(1024), nullable=False)
    interface: Mapped[str] = mapped_column(String(64), nullable=True)
    bpf_filter: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_seconds: Mapped[int] = mapped_column(Integer, default=300)
    status: Mapped[PacketCaptureStatus] = mapped_column(
        SAEnum(PacketCaptureStatus), default=PacketCaptureStatus.PENDING
    )
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    file_size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    headers: Mapped[list["PacketHeader"]] = relationship(
        "PacketHeader", back_populates="capture", cascade="all, delete-orphan"
    )


class PacketHeader(Base):
    """Stores parsed header information from captured packets."""

    __tablename__ = "packet_headers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    capture_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("packet_captures.id", ondelete="CASCADE"), nullable=False
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    src_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    length: Mapped[int] = mapped_column(Integer, default=0)
    info: Mapped[str | None] = mapped_column(Text, nullable=True)

    capture: Mapped[PacketCapture] = relationship(
        "PacketCapture", back_populates="headers"
    )
