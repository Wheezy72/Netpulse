from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class PcapFile(Base):
    """A raw .pcap file persisted to disk.

    This is distinct from PacketCapture for backward compatibility: PacketCapture
    tracks capture jobs, while PcapFile/PcapPacket are optimized for packet browsing.
    """

    __tablename__ = "pcap_files"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    capture_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("packet_captures.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    filepath: Mapped[str] = mapped_column(String(1024), nullable=False, unique=True)

    interface: Mapped[str | None] = mapped_column(String(64), nullable=True)
    bpf_filter: Mapped[str | None] = mapped_column(Text, nullable=True)

    file_size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    packet_count: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    captured_started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    captured_finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    indexed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    index_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    packets: Mapped[list["PcapPacket"]] = relationship(
        "PcapPacket", back_populates="pcap_file", cascade="all, delete-orphan"
    )


class PcapPacket(Base):
    """Metadata extracted from a packet in a .pcap file."""

    __tablename__ = "pcap_packets"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)

    file_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("pcap_files.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    packet_index: Mapped[int] = mapped_column(Integer, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    src_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)

    length: Mapped[int] = mapped_column(Integer, default=0)
    info: Mapped[str | None] = mapped_column(Text, nullable=True)

    pcap_file: Mapped[PcapFile] = relationship("PcapFile", back_populates="packets")

    __table_args__ = (
        Index("ix_pcap_packets_timestamp_brin", "timestamp", postgresql_using="brin"),
        Index("ix_pcap_packets_file_packet_index", "file_id", "packet_index"),
    )
