from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict

import redis.asyncio as aioredis
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

_RATE_LIMIT_KEY_PREFIX = "np:login_attempts:"
_RATE_LIMIT_MAX_ATTEMPTS = 5
_RATE_LIMIT_WINDOW_SECONDS = 300

_RESET_TOKEN_KEY_PREFIX = "np:reset_token:"
_RESET_TOKEN_TTL_SECONDS = 3600


def _build_redis_client() -> aioredis.Redis:
    return aioredis.from_url(settings.redis_url, encoding="utf-8", decode_responses=True)


def _rate_limit_key_for_ip(client_ip: str) -> str:
    return f"{_RATE_LIMIT_KEY_PREFIX}{client_ip}"


def _reset_token_key(token: str) -> str:
    return f"{_RESET_TOKEN_KEY_PREFIX}{token}"


async def _enforce_login_rate_limit(request: Request) -> None:
    """Block the request if the client IP has exceeded the login attempt ceiling.

    Uses a Redis sorted-set sliding window: timestamps are members scored by their
    Unix epoch, so ZREMRANGEBYSCORE + ZCARD runs atomically in a single pipeline.
    """
    client_ip = request.client.host if request.client else "unknown"
    redis_client = _build_redis_client()
    rate_limit_key = _rate_limit_key_for_ip(client_ip)
    current_unix_time = datetime.utcnow().timestamp()
    window_start_time = current_unix_time - _RATE_LIMIT_WINDOW_SECONDS

    async with redis_client.pipeline(transaction=True) as pipeline:
        pipeline.zremrangebyscore(rate_limit_key, "-inf", window_start_time)
        pipeline.zcard(rate_limit_key)
        pipeline.zadd(rate_limit_key, {str(current_unix_time): current_unix_time})
        pipeline.expire(rate_limit_key, _RATE_LIMIT_WINDOW_SECONDS)
        results = await pipeline.execute()

    attempt_count_before_this_request = results[1]
    if attempt_count_before_this_request >= _RATE_LIMIT_MAX_ATTEMPTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again later.",
        )


async def _store_password_reset_token_in_redis(token: str, user_email: str) -> None:
    redis_client = _build_redis_client()
    reset_token_key = _reset_token_key(token)
    await redis_client.hset(reset_token_key, mapping={"email": user_email})
    await redis_client.expire(reset_token_key, _RESET_TOKEN_TTL_SECONDS)


async def _consume_password_reset_token_from_redis(token: str) -> str | None:
    """Return the email for the token and delete it (tokens are single-use)."""
    redis_client = _build_redis_client()
    reset_token_key = _reset_token_key(token)
    token_data = await redis_client.hgetall(reset_token_key)
    if not token_data:
        return None
    await redis_client.delete(reset_token_key)
    return token_data.get("email")


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
    dependencies=[Depends(_enforce_login_rate_limit)],
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
    existing_any = await db.execute(select(User).limit(1))
    first_user = existing_any.scalar_one_or_none()

    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists",
        )

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
    await _store_password_reset_token_in_redis(token=token, user_email=user.email)

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
    if len(payload.new_password) < 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 6 characters.",
        )

    associated_email = await _consume_password_reset_token_from_redis(payload.token)
    if associated_email is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token.",
        )

    result = await db.execute(select(User).where(User.email == associated_email))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User not found.",
        )

    user.hashed_password = get_password_hash(payload.new_password)
    await db.commit()

    return {"message": "Password has been reset successfully. You can now sign in."}

