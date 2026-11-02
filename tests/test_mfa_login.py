"""Two-step sign-in: a password alone must never produce a session.

Exercised against an in-memory database the way the rest of this suite does —
the routes are called directly, so no Redis and no server are needed.
"""
from __future__ import annotations

import os

import pytest
from fastapi import HTTPException
from jose import jwt
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

# app.core.config reads these at import time; conftest runs too late for that.
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://netpulse:netpulse@localhost:5432/netpulse")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("ENVIRONMENT", "development")

from app.api.routes import auth  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.totp import generate_recovery_codes, hashes_for, totp_code  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.models.user import User, UserRole  # noqa: E402

SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
PASSWORD = "correct-horse-battery-staple"


@pytest.fixture
async def db() -> AsyncSession:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as session:
        yield session
    await engine.dispose()


async def _user(db: AsyncSession, *, totp: bool = True) -> User:
    user = User(
        username="ops",
        email="ops@example.com",
        role=UserRole.ADMIN,
        hashed_password=auth.get_password_hash(PASSWORD),
        auth_provider="local",
        totp_secret=SECRET if totp else None,
        totp_enabled=totp,
        token_version=0,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def _first_step(db: AsyncSession):
    return await auth.login(auth.LoginRequest(username="ops", password=PASSWORD), db)


async def _second_step(db: AsyncSession, ticket: str, code: str):
    return await auth.login_totp(auth.MfaLoginRequest(mfa_token=ticket, code=code), None, None, db)


class TestPasswordAloneIsNotEnough:
    async def test_login_stops_at_the_second_factor(self, db: AsyncSession):
        await _user(db)

        result = await _first_step(db)

        assert result.mfa_required is True
        assert result.access_token is None
        assert result.mfa_token

    async def test_account_without_a_second_factor_signs_in_in_one_step(self, db: AsyncSession):
        await _user(db, totp=False)

        result = await _first_step(db)

        assert result.access_token
        assert result.mfa_required is False


class TestSecondStep:
    async def test_current_code_completes_the_sign_in(self, db: AsyncSession):
        user = await _user(db)
        first = await _first_step(db)

        result = await _second_step(db, first.mfa_token or "", totp_code(SECRET))

        assert result.access_token
        decoded = jwt.decode(
            result.access_token, settings.secret_key, algorithms=[settings.jwt_algorithm]
        )
        assert decoded["ver"] == user.token_version

    async def test_wrong_code_is_refused(self, db: AsyncSession):
        await _user(db)
        first = await _first_step(db)

        with pytest.raises(HTTPException) as caught:
            await _second_step(db, first.mfa_token or "", "000000")
        assert caught.value.status_code == 401

    async def test_garbage_ticket_is_refused(self, db: AsyncSession):
        await _user(db)

        with pytest.raises(HTTPException) as caught:
            await _second_step(db, "not-a-ticket", totp_code(SECRET))
        assert caught.value.status_code == 401

    async def test_ticket_from_a_revoked_version_is_refused(self, db: AsyncSession):
        user = await _user(db)
        first = await _first_step(db)
        # A password change between the two steps bumps this.
        user.token_version = 4
        await db.commit()

        with pytest.raises(HTTPException) as caught:
            await _second_step(db, first.mfa_token or "", totp_code(SECRET))
        assert caught.value.status_code == 401


class TestRecoveryCodes:
    async def test_a_recovery_code_signs_in_once(self, db: AsyncSession):
        user = await _user(db)
        codes = generate_recovery_codes(2)
        user.set_recovery_hashes(hashes_for(codes))
        await db.commit()
        first = await _first_step(db)

        result = await _second_step(db, first.mfa_token or "", codes[0])

        assert result.access_token
        await db.refresh(user)
        assert len(user.recovery_hashes()) == 1

        # The same code must not work twice.
        with pytest.raises(HTTPException):
            await _second_step(db, first.mfa_token or "", codes[0])

    async def test_the_other_code_still_works(self, db: AsyncSession):
        user = await _user(db)
        codes = generate_recovery_codes(2)
        user.set_recovery_hashes(hashes_for(codes))
        await db.commit()
        first = await _first_step(db)

        await _second_step(db, first.mfa_token or "", codes[0])
        second = await _second_step(db, first.mfa_token or "", codes[1])

        assert second.access_token
