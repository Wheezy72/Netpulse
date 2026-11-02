from __future__ import annotations

import json
from datetime import datetime
from enum import Enum

from sqlalchemy import Boolean, DateTime, Enum as SAEnum, Integer, String, Text
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
    # Bumped when sessions must be invalidated ("sign out everywhere", password
    # change, admin reset). Tokens carry the version they were issued under, so
    # a stolen token stops working the moment this moves — the only way to kill
    # a bearer token before it expires.
    token_version: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
        server_default="0",
    )
    # Second factor (RFC 6238). The secret exists as soon as enrolment
    # starts so a half-finished setup verifies against the same secret; it
    # only becomes a requirement for sign-in once totp_enabled is true.
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        server_default="false",
    )
    # Recovery codes as a JSON list of sha256 digests, consumed one at a
    # time: a lost phone must not mean a lost account.
    totp_recovery_codes: Mapped[str | None] = mapped_column(Text, nullable=True)
    reset_token: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    reset_token_expires: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )


    def recovery_hashes(self) -> list[str]:
        """Hashes of the unused recovery codes (never the codes themselves)."""
        try:
            data = json.loads(self.totp_recovery_codes or "[]")
        except (TypeError, ValueError):
            return []
        return [str(item) for item in data] if isinstance(data, list) else []

    def set_recovery_hashes(self, hashes: list[str]) -> None:
        self.totp_recovery_codes = json.dumps(list(hashes))
