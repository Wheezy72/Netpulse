from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import DateTime, ForeignKey, JSON, String
from sqlalchemy.orm import Mapped, backref, mapped_column, relationship

from app.db.base import Base
from app.core.clock import utcnow


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
    scan_schedule: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    # The DiceBear skin the account picked for its portrait ("fun-emoji"),
    # server-side so the admin roster can render every account in its own
    # skin. NULL means the app default.
    avatar_style: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        onupdate=utcnow,
        nullable=False,
    )

    user = relationship("User", backref=backref("settings", uselist=False))
