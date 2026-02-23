from __future__ import annotations

from datetime import datetime
from enum import Enum

from sqlalchemy import Boolean, DateTime, Enum as SAEnum, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class UserRole(str, Enum):
    """Simple role model for RBAC.

    In a production deployment you might extend this with permissions tables,
    but this covers common operational needs.
    """

    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "admin"


class User(Base):
    """Application user for authentication and role-based access control."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(255), nullable=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=True)
    auth_provider: Mapped[str] = mapped_column(String(50), default="local", nullable=False)
    role: Mapped[UserRole] = mapped_column(
        SAEnum(UserRole),
        default=UserRole.VIEWER,
        nullable=False,
        index=True,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
    )