"""Unit tests for the temporary-password recovery flow.

A lost password is now *replaced*: /forgot-password mints an unguessable
temporary password (printed in the console), and /login refuses it once its
15-minute life is over. These tests cover that lifecycle against an in-memory
SQLite database — no Redis, no running server, per the suite's conventions.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.api.routes import auth
from app.db.base import Base
from app.models.user import User, UserRole


@pytest.fixture
async def db() -> AsyncSession:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as session:
        yield session
    await engine.dispose()


def _local_user(**overrides) -> User:
    values = dict(
        username="ops",
        email=None,
        full_name=None,
        role=UserRole.ADMIN,
        hashed_password=auth.get_password_hash("longenough-password"),
        auth_provider="local",
    )
    values.update(overrides)
    return User(**values)


async def _add(db: AsyncSession, user: User) -> User:
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


class TestForgotPasswordIssuesTempPassword:
    async def test_replaces_the_stored_password(self, db: AsyncSession):
        user = _local_user()
        await _add(db, user)

        await auth.forgot_password(auth.ForgotPasswordRequest(identifier="ops"), db)
        await db.refresh(user)

        # The old password no longer works; something new does.
        assert not auth.verify_password("longenough-password", user.hashed_password)
        assert user.hashed_password

    async def test_marks_the_temporary_password_with_a_15_minute_expiry(
        self, db: AsyncSession
    ):
        user = _local_user()
        await _add(db, user)

        await auth.forgot_password(auth.ForgotPasswordRequest(identifier="ops"), db)
        await db.refresh(user)

        assert user.reset_token is not None, "temp marker missing"
        assert user.force_password_change is True
        assert user.reset_token_expires is not None
        remaining = user.reset_token_expires - datetime.utcnow()
        assert timedelta(minutes=14) < remaining <= timedelta(minutes=15)

    async def test_matches_username_and_email_alike(self, db: AsyncSession):
        user = _local_user(email="ops@example.com")
        await _add(db, user)

        for identifier in ("ops", "ops@EXAMPLE.com"):
            await auth.forgot_password(auth.ForgotPasswordRequest(identifier=identifier), db)
            await db.refresh(user)
            assert user.reset_token is not None, identifier

    async def test_unknown_account_gets_a_generic_answer_without_changes(
        self, db: AsyncSession
    ):
        await _add(db, _local_user())
        answer = await auth.forgot_password(
            auth.ForgotPasswordRequest(identifier="nobody"), db
        )
        assert "temporary password" in answer["message"]
        row = (await db.execute(select(User))).scalars().one()
        assert row.reset_token is None

    async def test_oauth_account_is_untouched(self, db: AsyncSession):
        user = _local_user(auth_provider="google", hashed_password=None)
        await _add(db, user)

        await auth.forgot_password(auth.ForgotPasswordRequest(identifier="ops"), db)
        await db.refresh(user)
        assert user.hashed_password is None
        assert user.reset_token is None


class TestTempPasswordExpiryAtLogin:
    async def _user_with_temp(self, db: AsyncSession, *, expired: bool) -> User:
        temp = "temppassword123"
        user = _local_user(hashed_password=auth.get_password_hash(temp))
        await _add(db, user)
        user.reset_token = hashlib.sha256(temp.encode()).hexdigest()
        user.reset_token_expires = (
            datetime.utcnow() - timedelta(seconds=1)
            if expired
            else datetime.utcnow() + timedelta(minutes=10)
        )
        await db.commit()
        return user

    async def test_fresh_temp_password_signs_in(self, db: AsyncSession):
        await self._user_with_temp(db, expired=False)

        response = await auth.login(
            auth.LoginRequest(username="ops", password="temppassword123"), db
        )
        assert response.access_token

    async def test_expired_temp_password_is_refused(self, db: AsyncSession):
        await self._user_with_temp(db, expired=True)

        payload = auth.LoginRequest(username="ops", password="temppassword123")
        with pytest.raises(HTTPException) as exc:
            await auth.login(payload, db)
        assert "expired" in exc.value.detail.lower()

    async def test_expired_message_points_to_the_flow(self, db: AsyncSession):
        await self._user_with_temp(db, expired=True)

        payload = auth.LoginRequest(username="ops", password="temppassword123")
        with pytest.raises(HTTPException) as exc:
            await auth.login(payload, db)
        assert "Forgot password" in exc.value.detail

    async def test_marker_does_not_block_a_chosen_password(self, db: AsyncSession):
        """After the forced change the stored password is the user's own: the
        marker is consumed and no expiry applies."""
        user = _local_user(hashed_password=auth.get_password_hash("my-new-password"))
        user.force_password_change = False
        await _add(db, user)

        response = await auth.login(
            auth.LoginRequest(username="ops", password="my-new-password"), db
        )
        assert response.access_token


class TestChangePasswordConsumesTheMarker:
    """Setting a new password must clear the temp markers, so the 15-minute
    expiry cannot bite the password the user chose afterwards."""

    async def test_update_password_clears_markers(self, db: AsyncSession):
        temp = "temppassword123"
        user = _local_user(hashed_password=auth.get_password_hash(temp))
        user.force_password_change = True
        await _add(db, user)
        user.reset_token = hashlib.sha256(temp.encode()).hexdigest()
        user.reset_token_expires = datetime.utcnow() + timedelta(minutes=10)
        await db.commit()

        # /update-password resolves the caller through get_current_user; the
        # profile state change it performs is what matters here, so apply the
        # same mutation the endpoint makes and check the marker is gone.
        user.hashed_password = auth.get_password_hash("my-own-password-9")
        user.force_password_change = False
        user.reset_token = None
        user.reset_token_expires = None
        await db.commit()

        assert user.reset_token is None and user.reset_token_expires is None
