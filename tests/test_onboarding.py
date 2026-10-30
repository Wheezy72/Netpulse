"""First-run onboarding: a fresh install must never lock its owner out.

An empty instance has no accounts and therefore no way to sign in, so the
setup screen is the only door. These tests pin the rules that keep it open —
the first account is always the administrator, it is not forced through a
second password screen, and once it exists the door closes — plus the opt-in
SETUP_TOKEN that stops a stranger claiming an internet-exposed first boot.
"""
from __future__ import annotations

import os

import pytest
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

# app.core.config reads these at import time; conftest runs too late for that.
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://netpulse:netpulse@localhost:5432/netpulse")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("ENVIRONMENT", "development")

from app.api.routes import auth  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.models.user import User, UserRole  # noqa: E402


@pytest.fixture
async def db() -> AsyncSession:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as session:
        yield session
    await engine.dispose()


@pytest.fixture(autouse=True)
def no_setup_token(monkeypatch):
    """Default to the open first-run screen; the token tests opt back in."""
    monkeypatch.setattr(auth.settings, "setup_token", None, raising=False)


def _payload(**overrides) -> auth.CreateUserRequest:
    values = dict(username="owner", password="first-owner-password")
    values.update(overrides)
    return auth.CreateUserRequest(**values)


class TestFreshInstall:
    async def test_empty_instance_asks_for_setup(self, db: AsyncSession):
        status = await auth.setup_status(db)
        assert status["needs_setup"] is True

    async def test_setup_status_is_false_once_an_account_exists(self, db: AsyncSession):
        await auth.create_user(_payload(), db, None)

        status = await auth.setup_status(db)
        assert status["needs_setup"] is False

    async def test_first_account_is_the_administrator(self, db: AsyncSession):
        """Otherwise the owner could not add anybody: signup is closed after this."""
        await auth.create_user(_payload(), db, None)

        user = (await db.execute(select(User))).scalars().one()
        assert user.role == UserRole.ADMIN

    async def test_first_account_is_not_forced_to_change_its_password(
        self, db: AsyncSession
    ):
        """The owner chose this password themselves, so a forced change would
        only be an extra screen between them and the console."""
        await auth.create_user(_payload(), db, None)

        user = (await db.execute(select(User))).scalars().one()
        assert user.force_password_change is False

    async def test_the_password_chosen_at_setup_signs_in(self, db: AsyncSession):
        """Proves the account was committed with a usable hash, not just staged."""
        await auth.create_user(_payload(), db, None)

        response = await auth.login(
            auth.LoginRequest(username="owner", password="first-owner-password"), db
        )
        assert response.access_token


class TestDoorClosesAfterSetup:
    async def test_anonymous_signup_is_refused(self, db: AsyncSession):
        await auth.create_user(_payload(), db, None)

        with pytest.raises(HTTPException) as exc:
            await auth.create_user(_payload(username="stranger"), db, None)
        assert exc.value.status_code == 403

    async def test_admin_can_add_an_account(self, db: AsyncSession):
        owner = User(
            username="owner",
            hashed_password=auth.get_password_hash("first-owner-password"),
            role=UserRole.ADMIN,
            auth_provider="local",
        )
        db.add(owner)
        await db.commit()
        await db.refresh(owner)

        await auth.create_user(_payload(username="analyst"), db, owner)

        analyst = (
            await db.execute(select(User).where(User.username == "analyst"))
        ).scalars().one()
        assert analyst.role == UserRole.VIEWER

    async def test_admin_issued_account_must_change_its_password(self, db: AsyncSession):
        """An admin handed out this password, so the user picks their own next."""
        owner = User(
            username="owner",
            hashed_password=auth.get_password_hash("first-owner-password"),
            role=UserRole.ADMIN,
            auth_provider="local",
        )
        db.add(owner)
        await db.commit()
        await db.refresh(owner)

        await auth.create_user(_payload(username="analyst"), db, owner)

        analyst = (
            await db.execute(select(User).where(User.username == "analyst"))
        ).scalars().one()
        assert analyst.force_password_change is True


class TestSetupTokenIsOptIn:
    async def test_no_token_configured_leaves_setup_open(self, db: AsyncSession):
        await auth.create_user(_payload(), db, None)
        assert (await db.execute(select(User))).scalars().one().username == "owner"

    async def test_configured_token_is_required(self, db: AsyncSession, monkeypatch):
        monkeypatch.setattr(auth.settings, "setup_token", "long-random-setup-token", raising=False)

        with pytest.raises(HTTPException) as exc:
            await auth.create_user(_payload(), db, None)
        assert exc.value.status_code == 401

    async def test_configured_token_lets_the_operator_in(
        self, db: AsyncSession, monkeypatch
    ):
        monkeypatch.setattr(auth.settings, "setup_token", "long-random-setup-token", raising=False)

        await auth.create_user(
            _payload(setup_token="long-random-setup-token"), db, None
        )
        assert (await db.execute(select(User))).scalars().one().role == UserRole.ADMIN

    async def test_status_reports_that_a_token_is_needed(
        self, db: AsyncSession, monkeypatch
    ):
        """The setup screen has to know to render the token field."""
        monkeypatch.setattr(auth.settings, "setup_token", "long-random-setup-token", raising=False)

        status = await auth.setup_status(db)
        assert status["token_required"] is True
        assert status["needs_setup"] is True
