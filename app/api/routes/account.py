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

import logging

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.session_cookie import set_session_cookies
from app.core.totp import (
    DIGITS,
    STEP_SECONDS,
    generate_recovery_codes,
    generate_secret,
    hashes_for,
    match_recovery_code,
    provisioning_uri,
    verify_totp,
)

from app.api.deps import (
    create_access_token,
    db_session,
    get_current_user,
    get_password_hash,
    revoke_sessions,
    verify_password,
)
from app.api.routes.auth import (
    MIN_PASSWORD_LENGTH,
    _normalize_email,
    token_subject_for,
)
from app.models.user import User

router = APIRouter()

logger = logging.getLogger("netpulse.account")

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
    response: Response = None,  # type: ignore[assignment]
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
            token_version=db_user.token_version,
        )

    if access_token and response is not None:
        set_session_cookies(
            response, access_token, max_age=settings.access_token_expire_minutes * 60
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
    response: Response = None,  # type: ignore[assignment]
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
    # Also consumes the temporary-password marker from /forgot-password, so the
    # 15-minute expiry no longer applies to the string that was just replaced.
    db_user.reset_token = None
    db_user.reset_token_expires = None
    await db.commit()

    # Every token minted under the old password dies here. This is the seatbelt
    # for the case the feature exists for: a password changed *because* it
    # leaked, where the attacker may still be holding a live session.
    await revoke_sessions(db, db_user)

    # The caller's own token was invalidated with the rest, so hand back a fresh
    # one carrying the new version — "you stay signed in on this device" is
    # still true, every other device is signed out.
    token = create_access_token(
        subject=token_subject_for(db_user),
        role=db_user.role.value,
        token_version=db_user.token_version,
    )

    # The caller's own token was revoked with the rest, so the cookie is
    # reissued with the fresh one before the next request goes out.
    if response is not None:
        set_session_cookies(
            response, token, max_age=settings.access_token_expire_minutes * 60
        )
    return {"message": "Password updated.", "access_token": token}



# --- Two-factor authentication ---------------------------------------------
# Enrolling, disarming and regenerating recovery codes all require the
# account's password. A walk-up at an unlocked console must not be able to
# add a second factor behind the owner's back, and it certainly must not be
# able to remove the real one.


class MfaPasswordRequest(BaseModel):
    password: str


class MfaCodeRequest(BaseModel):
    code: str


class MfaDisarmRequest(BaseModel):
    password: str
    code: str


def _require_password(db_user: User, password: str) -> None:
    if not db_user.hashed_password or not verify_password(
        password, db_user.hashed_password
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=ERR_CURRENT_WRONG
        )


def _consume_second_factor(user: User, code: str) -> bool:
    """Verify a code, burning a recovery code when one is used."""
    if verify_totp(user.totp_secret or "", code):
        return True
    hashes = user.recovery_hashes()
    index = match_recovery_code(hashes, code)
    if index is None:
        return False
    hashes.pop(index)
    user.set_recovery_hashes(hashes)
    return True


@router.get("/mfa/status", summary="Whether this account uses a second factor")
async def mfa_status(
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    db_user = await _reload_user(db, current_user)
    return {"enabled": bool(db_user.totp_enabled),
            "recovery_codes_remaining": len(db_user.recovery_hashes())}


@router.post("/mfa/setup", summary="Start two-factor enrolment")
async def mfa_setup(
    payload: MfaPasswordRequest,
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Generate a secret and return it for the authenticator app.

    The secret is stored immediately but does not gate sign-in until a code
    proves the app and the server agree — otherwise a mistyped key would lock
    the account out.
    """
    db_user = await _reload_user(db, current_user)
    _require_password(db_user, payload.password)
    if db_user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Two-factor authentication is already enabled. Disable it first to re-enrol.",
        )
    secret = generate_secret()
    db_user.totp_secret = secret
    db_user.totp_enabled = False
    await db.commit()
    account = db_user.email or db_user.username
    return {
        "secret": secret,
        "otpauth_uri": provisioning_uri(secret, account),
        "digits": DIGITS,
        "period": STEP_SECONDS,
    }


@router.post("/mfa/enable", summary="Confirm enrolment and issue recovery codes")
async def mfa_enable(
    payload: MfaCodeRequest,
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    db_user = await _reload_user(db, current_user)
    if not (db_user.totp_secret or "").strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Start enrolment first.",
        )
    if db_user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Two-factor authentication is already enabled.",
        )
    if not verify_totp(db_user.totp_secret or "", payload.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="That code is not valid. Check the clock on the device and try the current code.",
        )
    codes = generate_recovery_codes()
    db_user.set_recovery_hashes(hashes_for(codes))
    db_user.totp_enabled = True
    await db.commit()
    logger.warning(
        "Two-factor authentication enabled for %s; %d recovery codes issued.",
        db_user.username,
        len(codes),
    )
    return {"enabled": True, "recovery_codes": codes}


@router.post("/mfa/disable", summary="Turn the second factor off")
async def mfa_disable(
    payload: MfaDisarmRequest,
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> Dict[str, bool]:
    db_user = await _reload_user(db, current_user)
    _require_password(db_user, payload.password)
    if not db_user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Two-factor authentication is not enabled.",
        )
    if not _consume_second_factor(db_user, payload.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="That code is not valid.",
        )
    db_user.totp_secret = None
    db_user.totp_enabled = False
    db_user.totp_recovery_codes = None
    await db.commit()
    logger.warning("Two-factor authentication disabled for %s.", db_user.username)
    return {"enabled": False}


@router.post("/mfa/recovery-codes", summary="Issue a fresh set of recovery codes")
async def mfa_regenerate_recovery_codes(
    payload: MfaDisarmRequest,
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Replaces every unused code; the previous set stops working."""
    db_user = await _reload_user(db, current_user)
    _require_password(db_user, payload.password)
    if not db_user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Two-factor authentication is not enabled.",
        )
    if not _consume_second_factor(db_user, payload.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="That code is not valid.",
        )
    codes = generate_recovery_codes()
    db_user.set_recovery_hashes(hashes_for(codes))
    await db.commit()
    return {"recovery_codes": codes}
