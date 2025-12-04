from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional

from sqlalchemy import DateTime, Enum as SAEnum, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ScriptJobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"


class ScriptJob(Base):
    """Represents an execution of a Smart Script.

    This can be an uploaded script or a prebuilt template, optionally
    associated with a specific Device (for per-host history in the UI).
    """

    __tablename__ = "script_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    script_name: Mapped[str] = mapped_column(String(255), index=True)
    script_path: Mapped[str] = mapped_column(String(1024))

    # Optional association to a Device so we can show per-host history.
    device_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("devices.id"),
        nullable=True,
        index=True,
    )

    status: Mapped[ScriptJobStatus] = mapped_column(
        SAEnum(ScriptJobStatus),
        default=ScriptJobStatus.PENDING,
        nullable=False,
        index=True,
    )

    # Arbitrary parameters passed into the script's ctx.params.
    params: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    # Structured result captured from the script, if any.
    result: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    # Combined log output from the script run.
    logs: Mapped[str] = mapped_column(Text, default="")

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