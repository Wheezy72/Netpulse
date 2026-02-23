from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from sqlalchemy import JSON, DateTime, Enum as SAEnum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ScanJobStatus(str, Enum):
    """Lifecycle state for a scan job."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanJob(Base):
    """Persisted scan job metadata.

    Note: This repo uses simple `Base.metadata.create_all()` for schema creation.
    In deployments with an existing database you may need to drop/recreate the
    table or add migrations when this schema changes.
    """

    __tablename__ = "scan_jobs"

    # Public identifier used by the API/WS clients.
    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    target: Mapped[str] = mapped_column(String(255), index=True)

    # A human-friendly label, e.g. "Version Detection" / "Vulnerability Assessment".
    profile: Mapped[str] = mapped_column(String(255), index=True)

    # Raw/parsed arguments used to run the scan (e.g. {"command": "...", "safe_args": [...]})
    arguments: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    status: Mapped[ScanJobStatus] = mapped_column(
        SAEnum(ScanJobStatus),
        default=ScanJobStatus.PENDING,
        nullable=False,
        index=True,
    )

    # Summary metadata such as exit_code, duration, error message, etc.
    result_summary: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    # Path to the persisted artifact, e.g. data/scans/scan_<id>.txt
    artifact_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    requested_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"),
        nullable=True,
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        nullable=False,
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
