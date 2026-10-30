from __future__ import annotations

from datetime import datetime
from enum import Enum

from sqlalchemy import Boolean, DateTime, Enum as SAEnum, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.core.clock import utcnow


class UserRole(str, Enum):
    """Role model for RBAC.

    Deliberately reduced to two:

      - admin: everything, including destructive operations (blocking hosts,
        running scripts, restoring backups, opening a console, scanning).
      - viewer: read-only. Observes the dashboard, inventory, topology and
        reports, and changes nothing.

    A previous build also carried ``operator`` and ``auditor``. In a
    self-hosted tool used by a handful of people they added a third state
    that nobody could explain at the keyboard, so they are gone; existing
    rows are remapped by ``migrations/20261020_users_role_admin_viewer.sql``.
    """

    ADMIN = "admin"
    VIEWER = "viewer"


class User(Base):
    """Application user for authentication and role-based access control."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    # Nullable on purpose: an account can be created without an address and
    # attach one later from Settings, which is what enables password recovery.
    # NULLs do not collide in a unique index, unlike empty strings.
    email: Mapped[str | None] = mapped_column(String(255), unique=True, index=True, nullable=True)
    full_name: Mapped[str] = mapped_column(String(255), nullable=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=True)
    force_password_change: Mapped[bool] = mapped_column(Boolean, default=False)
    auth_provider: Mapped[str] = mapped_column(String(50), default="local", nullable=False)
    role: Mapped[UserRole] = mapped_column(
        SAEnum(UserRole, name="user_role"),
        # Least privilege by default: a new account observes until an admin
        # says otherwise.
        default=UserRole.VIEWER,
        nullable=False,
        index=True,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    reset_token: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    reset_token_expires: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )
