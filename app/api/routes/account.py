from __future__ import annotations

"""Account self-service endpoints.

Kept in its own module rather than appended to ``auth.py`` so the login and
registration contract stays untouched: this file only adds the two operations an
authenticated user needs, namely attaching an email address (which is what makes
password recovery possible) and changing their own password.

Both endpoints re-read the user from the database: the ``User`` returned by
``get_current_user`` may come from the Redis session cache and is therefore not
a safe object to mutate and flush.
"""

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    create_access_token,
    db_session,
    get_current_user,
    get_password_hash,
    verify_password,
)
from app.api.routes.auth import (
    MIN_PASSWORD_LENGTH,
    _normalize_email,
    token_subject_for,
)
from app.models.user import User

router = APIRouter()

# Distinct messages so the UI can place the error next to the right field.
ERR_EMAIL_TAKEN = "That email is already in use."
ERR_EMAIL_EMPTY = "Enter an email address."
ERR_CURRENT_WRONG = "Current password is incorrect."
ERR_PASSWORD_SHORT = f"New password must be at least {MIN_PASSWORD_LENGTH} characters."
ERR_PASSWORD_SAME = "New password must be different from the current one."


def _validate_new_password(new_password: str, current_password: str | None = None) -> None:
    """Raise ValueError with a user-facing message when the new password is unusable.

    Pure function so the rules can be unit-tested without a database.
    """
    if len(new_password or "") < MIN_PASSWORD_LENGTH:
        raise ValueError(ERR_PASSWORD_SHORT)
    if current_password is not None and new_password == current_password:
        raise ValueError(ERR_PASSWORD_SAME)


class ProfileUpdate(BaseModel):
    """Fields a user may change about themselves."""

    email: str | None = None
    full_name: str | None = None

    @field_validator("email")
    @classmethod
    def _validate_email(cls, value: str | None) -> str | None:
        if value is None:
            return None
        candidate = value.strip()
        if not candidate:
            raise ValueError(ERR_EMAIL_EMPTY)
        try:
            return _normalize_email(candidate)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


def _public_user(user: User) -> Dict[str, Any]:
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role.value,
        "force_password_change": user.force_password_change,
    }


async def _reload_user(db: AsyncSession, user: User) -> User:
    result = await db.execute(select(User).where(User.id == user.id))
    db_user = result.scalar_one_or_none()
    if db_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return db_user


@router.patch(
    "/me",
    summary="Update your own profile (attach or change your email address)",
)
async def update_my_profile(
    payload: ProfileUpdate,
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Attach or change the caller's email address.

    The email doubles as the JWT subject and as the lookup key for password
    recovery, so a successful change returns a freshly minted access token. The
    client swaps it in and stays signed in; the previous token stops resolving
    the moment the address changes.
    """
    db_user = await _reload_user(db, current_user)
    changed_email = False

    if payload.email is not None and payload.email != db_user.email:
        existing = await db.execute(
            select(User).where(User.email == payload.email, User.id != db_user.id)
        )
        if existing.scalar_one_or_none() is not None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=ERR_EMAIL_TAKEN)
        db_user.email = payload.email
        changed_email = True

    if payload.full_name is not None:
        db_user.full_name = payload.full_name.strip() or None

    if not changed_email and payload.full_name is None:
        return {"user": _public_user(db_user), "access_token": None}

    await db.commit()
    await db.refresh(db_user)

    access_token = None
    if changed_email:
        access_token = create_access_token(
            subject=token_subject_for(db_user),
            role=db_user.role.value,
        )

    return {"user": _public_user(db_user), "access_token": access_token}


@router.post(
    "/change-password",
    summary="Change your own password",
)
async def change_my_password(
    payload: PasswordChange,
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """Replace the caller's password after verifying the current one."""
    db_user = await _reload_user(db, current_user)

    if not db_user.hashed_password or not verify_password(
        payload.current_password, db_user.hashed_password
    ):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=ERR_CURRENT_WRONG)

    try:
        _validate_new_password(payload.new_password, payload.current_password)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    db_user.hashed_password = get_password_hash(payload.new_password)
    # A user who has just chosen their own password no longer needs a forced reset.
    db_user.force_password_change = False
    await db.commit()

    return {"message": "Password updated."}
