from __future__ import annotations

import logging
import secrets
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    create_access_token,
    db_session,
    get_current_user,
    get_password_hash,
    verify_password,
)
from app.core.config import settings
from app.models.user import User, UserRole

logger = logging.getLogger("netpulse.auth")

router = APIRouter()

login_attempts: dict[str, list[float]] = defaultdict(list)


async def check_rate_limit(request: Request, max_attempts: int = 5, window_seconds: int = 300):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    login_attempts[client_ip] = [t for t in login_attempts[client_ip] if now - t < window_seconds]
    if len(login_attempts[client_ip]) >= max_attempts:
        raise HTTPException(status_code=429, detail="Too many login attempts. Please try again later.")
    login_attempts[client_ip].append(now)

_reset_tokens: Dict[str, Dict[str, Any]] = {}


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class CreateUserRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: str | None = None


class UserMeResponse(BaseModel):
    id: int
    email: EmailStr
    full_name: str | None = None
    role: UserRole



@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Obtain an access token via email and password",
    dependencies=[Depends(check_rate_limit)],
)
async def login(
    payload: LoginRequest,
    db: AsyncSession = Depends(db_session),
) -> TokenResponse:
    """Authenticate a user and return a JWT access token."""
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    if user.auth_provider != "local" or not user.hashed_password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This account uses Google sign-in. Please use the Google button to log in.",
        )

    if not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    token = create_access_token(
        subject=user.email,
        role=user.role.value,
        expires_delta=access_token_expires,
    )
    return TokenResponse(access_token=token)


@router.get(
    "/me",
    response_model=UserMeResponse,
    summary="Return the current authenticated user's profile",
)
async def read_current_user(
    user: User = Depends(get_current_user),
) -> UserMeResponse:
    return UserMeResponse(
      id=user.id,
      email=user.email,
      full_name=user.full_name,
      role=user.role,
    )


@router.post(
    "/users",
    response_model=Dict[str, Any],
    status_code=status.HTTP_201_CREATED,
    summary="Create a new user (bootstrap / admin use)",
)
async def create_user(
    payload: CreateUserRequest,
    db: AsyncSession = Depends(db_session),
) -> Dict[str, Any]:
    """Create a new local user.

    Bootstrapping rules:
      - If there are no users yet, allow creation without authentication and
        force the first account to be ADMIN.
      - If at least one user exists and allow_open_signup is False, block
        open signups entirely; additional users must be created by an admin
        through a controlled path (e.g. internal tooling or SSO provisioning).
    """
    # Check whether any user exists yet
    existing_any = await db.execute(select(User).limit(1))
    first_user = existing_any.scalar_one_or_none()

    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists",
        )

    # If at least one user exists and open signup is disabled, reject.
    if first_user and not settings.allow_open_signup:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User signup is disabled. Ask an administrator to provision access.",
        )

    user = User(
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=get_password_hash(payload.password),
        role=UserRole.ADMIN if not first_user else UserRole.OPERATOR,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    return {"id": user.id, "email": user.email, "role": user.role.value}


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


@router.post(
    "/forgot-password",
    summary="Request a password reset token",
)
async def forgot_password(
    payload: ForgotPasswordRequest,
    db: AsyncSession = Depends(db_session),
) -> Dict[str, str]:
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if user is None or user.auth_provider != "local":
        return {"message": "If an account with that email exists, a reset link has been generated."}

    token = secrets.token_urlsafe(32)
    _reset_tokens[token] = {
        "email": user.email,
        "expires": datetime.utcnow() + timedelta(hours=1),
    }

    logger.warning(
        "PASSWORD RESET TOKEN for %s: %s  (valid 1 hour)",
        user.email,
        token,
    )

    return {"message": "If an account with that email exists, a reset link has been generated."}


@router.post(
    "/reset-password",
    summary="Reset password using a valid reset token",
)
async def reset_password(
    payload: ResetPasswordRequest,
    db: AsyncSession = Depends(db_session),
) -> Dict[str, str]:
    token_data = _reset_tokens.get(payload.token)
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token.",
        )

    if datetime.utcnow() > token_data["expires"]:
        _reset_tokens.pop(payload.token, None)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset token has expired. Please request a new one.",
        )

    if len(payload.new_password) < 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 6 characters.",
        )

    result = await db.execute(select(User).where(User.email == token_data["email"]))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User not found.",
        )

    user.hashed_password = get_password_hash(payload.new_password)
    await db.commit()

    _reset_tokens.pop(payload.token, None)

    return {"message": "Password has been reset successfully. You can now sign in."}