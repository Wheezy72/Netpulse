from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from typing import Annotated, AsyncGenerator, Optional

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.redis import get_redis
from app.db.session import async_session_factory
from app.models.user import User, UserRole

ph = PasswordHasher()
security_scheme = HTTPBearer(auto_error=True)

# Tokens issued before 2026-10 carry the email address as their subject. New
# tokens carry "id:<user id>", which survives an email change and works for
# accounts that have no address yet.
SUBJECT_ID_PREFIX = "id:"


def _token_cache_key(token: str) -> str:
    digest = hashlib.sha256(token.encode()).hexdigest()[:32]
    return f"np:session:{digest}"


async def db_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_factory() as session:
        yield session


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return ph.verify(hashed_password, plain_password)
    except VerifyMismatchError:
        return False
    except Exception:
        # Fallback in case of invalid hashes/malformed passwords
        return False


def get_password_hash(password: str) -> str:
    return ph.hash(password)


def create_access_token(
    subject: str,
    role: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    to_encode = {"sub": subject, "role": role}
    expire = datetime.utcnow() + (
        expires_delta
        if expires_delta is not None
        else timedelta(minutes=settings.access_token_expire_minutes)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.jwt_algorithm)


def subject_for_user(user: User) -> str:
    """Stable token subject for a user record."""
    return f"{SUBJECT_ID_PREFIX}{user.id}"


def parse_subject(subject: str) -> tuple[str, str] | None:
    """Split a token subject into ("id", "<id>") or ("email", "<address>").

    Returns None for anything malformed, which callers treat as unauthenticated.
    """
    if not subject or not isinstance(subject, str):
        return None
    if subject.startswith(SUBJECT_ID_PREFIX):
        raw = subject[len(SUBJECT_ID_PREFIX) :].strip()
        return ("id", raw) if raw.isdigit() else None
    candidate = subject.strip()
    return ("email", candidate.lower()) if candidate else None


async def resolve_user_from_subject(db: AsyncSession, subject: str) -> User | None:
    """Look up the user a token subject refers to, id-first with an email fallback."""
    parsed = parse_subject(subject)
    if parsed is None:
        return None

    kind, value = parsed
    if kind == "id":
        result = await db.execute(select(User).where(User.id == int(value)))
    else:
        # Addresses are stored case-preserving, so compare case-insensitively.
        result = await db.execute(select(User).where(func.lower(User.email) == value))
    return result.scalar_one_or_none()


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Security(security_scheme)],
    db: AsyncSession = Depends(db_session),
) -> User:
    """Validate the bearer token and return the active User.

    Checks the Redis session cache first; falls back to the database on a miss.
    """
    token = credentials.credentials
    redis = get_redis()
    digest = hashlib.sha256(token.encode()).hexdigest()[:32]

    # Check if token is blacklisted
    try:
        if await redis.get(f"np:blacklist:{digest}"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been blacklisted (logged out)",
            )
    except HTTPException:
        raise
    except Exception:
        pass

    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
        )
        subject: str = payload.get("sub") or ""
        if not subject:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        ) from None

    cache_key = _token_cache_key(token)
    try:
        cached = await redis.get(cache_key)
        if cached:
            data = json.loads(cached)
            user = User(
                id=data["id"],
                username=data.get("username"),
                email=data.get("email"),
                full_name=data.get("full_name"),
                role=UserRole(data["role"]),
                is_active=data["is_active"],
                force_password_change=data.get("force_password_change", False),
            )
            if not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Inactive or missing user",
                )
            return user
    except HTTPException:
        raise
    except Exception:
        pass

    user = await resolve_user_from_subject(db, subject)

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Inactive or missing user",
        )

    exp: int = payload.get("exp", 0)
    ttl = max(exp - int(datetime.utcnow().timestamp()), 60)
    try:
        await redis.setex(
            cache_key,
            ttl,
            json.dumps({
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "full_name": user.full_name,
                "role": user.role.value,
                "is_active": user.is_active,
                "force_password_change": user.force_password_change,
            }),
        )
    except Exception:
        pass

    return user


def require_role(*allowed_roles: UserRole):
    """Return a dependency that requires authentication and optionally a specific role."""

    async def _require(user: User = Depends(get_current_user)) -> User:
        if allowed_roles and user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user

    return _require


def require_compliance_role():
    """Read-mostly surface: every signed-in account may use it."""
    return require_role(UserRole.ADMIN, UserRole.VIEWER)


def require_scan_role():
    """Active scanning and recon. Admin only — a viewer observes."""
    return require_role(UserRole.ADMIN)


_optional_security_scheme = HTTPBearer(auto_error=False)


async def optional_current_user(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Security(_optional_security_scheme)
    ] = None,
    db: AsyncSession = Depends(db_session),
) -> User | None:
    """Resolve the caller when a token is present, else ``None``.

    Used by account creation: the first account is authorised by SETUP_TOKEN,
    later ones by an admin's bearer token, and an anonymous request simply
    resolves to ``None`` so the open-signup gate can refuse it.
    """
    if credentials is None:
        return None

    token = credentials.credentials
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
        )
        subject: str = payload.get("sub") or ""
    except JWTError:
        return None

    if not subject:
        return None

    user = await resolve_user_from_subject(db, subject)
    return user if user is not None and user.is_active else None


async def require_admin(
    request: Request,
    user: User = Depends(get_current_user),
) -> User:
    if user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )

    try:
        from app.core.celery_app import celery_app

        celery_app.send_task(
            "app.tasks.write_audit_log",
            kwargs={
                "user_id": user.id,
                "method": request.method,
                "path": request.url.path,
                "ip_address": getattr(request.client, "host", None),
                "details": {
                    "query": dict(request.query_params),
                    "path_params": request.scope.get("path_params", {}),
                },
            },
        )
    except Exception:
        pass

    return user
