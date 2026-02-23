from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import DateTime, ForeignKey, JSON
from sqlalchemy.orm import Mapped, backref, mapped_column, relationship

from app.db.base import Base


class UserSettings(Base):
    """Per-user persisted settings.

    A single row exists per user, keyed by user_id.
    """

    __tablename__ = "user_settings"

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )

    notification_settings: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    ai_settings: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    threat_intel_settings: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    scan_schedule: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)

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

    user = relationship("User", backref=backref("settings", uselist=False))
