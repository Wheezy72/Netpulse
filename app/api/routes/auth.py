from __future__ import annotations

import logging
import os
import re
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request, status
from email_validator import EmailNotValidError, validate_email
from jose import jwt
from pydantic import BaseModel, field_validator
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    create_access_token,
    db_session,
    get_current_user,
    get_password_hash,
    optional_current_user,
    subject_for_user,
    verify_password,
    security_scheme,
)
from app.core.config import settings
from app.core.redis import get_redis
from app.models.user import User, UserRole

logger = logging.getLogger("netpulse.auth")

router = APIRouter()

_RATE_LIMIT_KEY_PREFIX = "np:login_attempts:"
_RATE_LIMIT_MAX_ATTEMPTS = 5
_RATE_LIMIT_WINDOW_SECONDS = 300

# Password recovery is unauthenticated and every request mints a fresh secret
# and writes it to the log, so it gets a tighter bucket of its own.
_RESET_RATE_LIMIT_KEY_PREFIX = "np:reset_attempts:"
_RESET_RATE_LIMIT_MAX_ATTEMPTS = 5
_RESET_RATE_LIMIT_WINDOW_SECONDS = 900

# Usernames are shown in the UI and used to sign in, so keep them predictable.
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{3,64}$")


async def _enforce_rate_limit(
    request: Request,
    *,
    key_prefix: str,
    max_attempts: int,
    window_seconds: int,
    message: str,
) -> None:
    """Block the request once the client IP exceeds the attempt ceiling.

    Uses a Redis sorted-set sliding window: timestamps are members scored by
    their Unix epoch, so ZREMRANGEBYSCORE + ZCARD + ZADD run atomically in a
    single pipeline.

    Extracts the real client IP from X-Forwarded-For or X-Real-IP headers to
    properly handle proxied requests.
    """
    # Extract real client IP, handling proxy headers
    client_ip = request.client.host if request.client else "unknown"
    if x_forwarded_for := request.headers.get("X-Forwarded-For"):
        # X-Forwarded-For may contain multiple IPs; use the first (client) one
        client_ip = x_forwarded_for.split(",")[0].strip()
    elif x_real_ip := request.headers.get("X-Real-IP"):
        client_ip = x_real_ip.strip()

    redis_client = get_redis()
    rate_limit_key = f"{key_prefix}{client_ip}"
    current_unix_time = datetime.utcnow().timestamp()
    window_start_time = current_unix_time - window_seconds

    async with redis_client.pipeline(transaction=True) as pipeline:
        pipeline.zremrangebyscore(rate_limit_key, "-inf", window_start_time)
        pipeline.zcard(rate_limit_key)
        pipeline.zadd(rate_limit_key, {str(current_unix_time): current_unix_time})
        pipeline.expire(rate_limit_key, window_seconds)
        results = await pipeline.execute()

    attempt_count_before_this_request = results[1]
    if attempt_count_before_this_request >= max_attempts:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=message,
        )


async def _enforce_login_rate_limit(request: Request) -> None:
    """Ceiling on sign-in attempts per client IP."""
    await _enforce_rate_limit(
        request,
        key_prefix=_RATE_LIMIT_KEY_PREFIX,
        max_attempts=_RATE_LIMIT_MAX_ATTEMPTS,
        window_seconds=_RATE_LIMIT_WINDOW_SECONDS,
        message="Too many login attempts. Please try again later.",
    )


async def _enforce_reset_rate_limit(request: Request) -> None:
    """Ceiling on password-reset requests and token attempts per client IP."""
    await _enforce_rate_limit(
        request,
        key_prefix=_RESET_RATE_LIMIT_KEY_PREFIX,
        max_attempts=_RESET_RATE_LIMIT_MAX_ATTEMPTS,
        window_seconds=_RESET_RATE_LIMIT_WINDOW_SECONDS,
        message="Too many password reset requests. Please try again later.",
    )


def token_subject_for(user: User) -> str:
    """Subject to put in a token for this user.

    The email stays the subject whenever there is one: the WebSocket endpoints
    and any token already in the wild resolve users that way. Accounts created
    without an address fall back to the id form.
    """
    return user.email or subject_for_user(user)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


def _normalize_email(value: str) -> str:
    if not value:
        raise ValueError("Email is required")
    try:
        validated = validate_email(
            value,
            check_deliverability=False,
        )
        return validated.normalized
    except EmailNotValidError as exc:
        # In non-production environments, allow common local/reserved domains
        # (e.g., admin@netpulse.local) to reduce friction in dev/demo setups.
        if settings.environment.lower() != "production":
            normalized = value.strip().lower()
            if "@" in normalized:
                domain = normalized.split("@", 1)[1]
                if domain in {"local", "localhost"} or domain.endswith(".local") or domain.endswith(".localhost"):
                    return normalized
        raise ValueError(str(exc)) from exc


class EmailRequest(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return _normalize_email(value)


class LoginRequest(BaseModel):
    username: str
    password: str
    remember_me: bool = False


class CreateUserRequest(BaseModel):
    """Registration payload.

    An email address is optional: an account can be created with a username
    only and attach an address later from Settings, which is what makes
    password recovery possible for it.
    """

    username: str
    email: str | None = None
    password: str
    full_name: str | None = None
    setup_token: str | None = None
    # Only honoured for an authenticated admin; anyone else is forced to the
    # default viewer role.
    role: str | None = None

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        candidate = (value or "").strip()
        if not USERNAME_PATTERN.match(candidate):
            raise ValueError(
                "Username must be 3-64 characters: letters, digits, dot, dash or underscore."
            )
        return candidate

    @field_validator("email")
    @classmethod
    def validate_optional_email(cls, value: str | None) -> str | None:
        if value is None:
            return None
        candidate = value.strip()
        if not candidate:
            return None
        return _normalize_email(candidate)


class UserMeResponse(BaseModel):
    id: int
    username: str
    email: str | None = None
    full_name: str | None = None
    role: UserRole
    force_password_change: bool


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
    result = await db.execute(select(User).where(User.username == payload.username))
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    # Accounts without a local password hash (e.g. imported OAuth users) cannot
    # sign in locally; a generic message avoids leaking which accounts exist.
    if not user.hashed_password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    if not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    access_token_expires = (
        timedelta(days=30)
        if payload.remember_me
        else timedelta(minutes=settings.access_token_expire_minutes)
    )
    token = create_access_token(
        subject=token_subject_for(user),
        role=user.role.value,
        expires_delta=access_token_expires,
    )
    return TokenResponse(access_token=token)


@router.post(
    "/logout",
    summary="Invalidate the current user's session token",
)
async def logout(
    request: Request,
    db: AsyncSession = Depends(db_session),
) -> Dict[str, str]:
    # Extract token
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        try:
            # Decode token (ignore expiration verification to find remaining TTL)
            payload = jwt.decode(
                token,
                settings.secret_key,
                algorithms=[settings.jwt_algorithm],
                options={"verify_exp": False},
            )
            exp = payload.get("exp", 0)
            current_time = int(datetime.utcnow().timestamp())
            ttl = max(exp - current_time, 0)

            if ttl > 0:
                import hashlib
                digest = hashlib.sha256(token.encode()).hexdigest()[:32]
                redis = get_redis()
                # Blacklist this token digest for the remainder of its lifetime
                await redis.setex(f"np:blacklist:{digest}", ttl, "1")
                # Also clean up the active session cache
                await redis.delete(f"np:session:{digest}")
        except Exception as e:
            logger.exception("Error blacklisting token on logout: %s", e)

    return {"message": "Logged out successfully"}


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
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        force_password_change=user.force_password_change,
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
    caller: User | None = Depends(optional_current_user),
) -> Dict[str, Any]:
    """Create a new local user.

    Bootstrapping rules:
      - If there are no users yet, require a one-time SETUP_TOKEN environment variable
        to be passed in the payload to authorize the creation of the first ADMIN account.
        This prevents race conditions and unauthorized admin creation during initial setup.
      - If at least one user exists and allow_open_signup is False, block
        open signups entirely; additional users must be created by an admin
        through a controlled path (e.g. internal tooling or SSO provisioning).
    """
    existing_any = await db.execute(select(User).limit(1))
    first_user = existing_any.scalar_one_or_none()

    # Only compare the email when one was supplied: `User.email == None` compiles
    # to IS NULL and would match every other account created without an address.
    conditions = [User.username == payload.username]
    if payload.email:
        conditions.append(User.email == payload.email)
    existing = await db.execute(select(User).where(or_(*conditions)))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email or username already exists",
        )

    # First user requires SETUP_TOKEN to prevent unauthorized admin takeover
    if not first_user:
        setup_token_env = os.environ.get("SETUP_TOKEN", "").strip()
        if not setup_token_env:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Initial setup requires SETUP_TOKEN environment variable. Contact your administrator.",
            )
        if not payload.setup_token or payload.setup_token != setup_token_env:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid setup token.",
            )

    if first_user and not settings.allow_open_signup:
        # Closed signup: only an admin may add accounts. Without this, anyone
        # who could reach the port could mint a viewer account for themselves.
        if caller is None or caller.role != UserRole.ADMIN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User signup is disabled. Ask an administrator to provision access.",
            )

    # The first account owns the box. After that everyone is a viewer unless
    # an authenticated admin explicitly asks for admin — and even then only
    # when open signup is closed, so a self-registered account cannot
    # promote itself.
    if not first_user:
        assigned_role = UserRole.ADMIN
    elif payload.role and caller is not None and caller.role == UserRole.ADMIN:
        try:
            assigned_role = UserRole(payload.role.strip().lower())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unknown role. Use 'admin' or 'viewer'.",
            ) from None
    else:
        assigned_role = UserRole.VIEWER

    user = User(
        username=payload.username,
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=get_password_hash(payload.password),
        role=assigned_role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    return {"id": user.id, "email": user.email, "role": user.role.value}


class ForgotPasswordRequest(EmailRequest):
    pass


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


class UpdatePasswordRequest(BaseModel):
    new_password: str


@router.post(
    "/update-password",
    summary="Update your password (used for force password change)",
)
async def update_password(
    payload: UpdatePasswordRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(db_session),
) -> Dict[str, str]:
    # Retrieve the user directly from the database to ensure it's attached and has all fields loaded
    result = await db.execute(select(User).where(User.id == user.id))
    db_user = result.scalar_one_or_none()
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if len(payload.new_password) < 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be at least 6 characters.",
        )

    db_user.hashed_password = get_password_hash(payload.new_password)
    db_user.force_password_change = False
    await db.commit()

    # Invalidate Redis session cache so it updates with the new user profile state on next request
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        import hashlib
        digest = hashlib.sha256(token.encode()).hexdigest()[:32]
        cache_key = f"np:session:{digest}"
        try:
            redis = get_redis()
            await redis.delete(cache_key)
        except Exception:
            pass

    return {"message": "Password updated successfully."}


@router.post(
    "/forgot-password",
    summary="Request a password reset token",
    dependencies=[Depends(_enforce_reset_rate_limit)],
)
async def forgot_password(
    payload: ForgotPasswordRequest,
    db: AsyncSession = Depends(db_session),
) -> Dict[str, str]:
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    # Accounts without a local password or without an address cannot recover by
    # email. Return the same generic message so the response never reveals which
    # accounts exist or which one is missing an address.
    if user is None or user.auth_provider != "local" or not user.email:
        # Return generic message to prevent user enumeration
        return {"message": "If an account with that email exists, a reset link has been generated."}

    token = secrets.token_urlsafe(32)
    import hashlib
    hashed_token = hashlib.sha256(token.encode()).hexdigest()

    user.reset_token = hashed_token
    user.reset_token_expires = datetime.utcnow() + timedelta(hours=1)
    await db.commit()

    # Log the plaintext token to the console so the administrator can copy-paste it
    logger.warning("PASSWORD RESET REQUESTED FOR %s. RESET TOKEN: %s", user.email, token)

    return {"message": "If an account with that email exists, a reset link has been generated."}


@router.post(
    "/reset-password",
    summary="Reset password using a valid reset token",
    dependencies=[Depends(_enforce_reset_rate_limit)],
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

    import hashlib
    hashed_token = hashlib.sha256(payload.token.encode()).hexdigest()

    # Find the user with the matching, unexpired reset token
    result = await db.execute(
        select(User).where(
            User.reset_token == hashed_token,
            User.reset_token_expires > datetime.utcnow()
        )
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token.",
        )

    user.hashed_password = get_password_hash(payload.new_password)
    user.reset_token = None
    user.reset_token_expires = None
    user.force_password_change = False
    await db.commit()

    return {"message": "Password has been reset successfully. You can now sign in."}
