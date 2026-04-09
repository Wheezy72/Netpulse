from __future__ import annotations

"""
Shared FastAPI dependencies and security helpers.

Provides:
- db_session: async SQLAlchemy session dependency.
- Password hashing (Argon2id via argon2-cffi / passlib).
- JWT creation and validation with Redis-backed session caching.
- A role-based authorization dependency (require_role) that enforces RBAC.
- Async audit logging via a Celery task (non-blocking).
"""

import hashlib
import json
import threading
from datetime import datetime, timedelta
from typing import Annotated, AsyncGenerator, Optional

import redis.asyncio as aioredis
from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import async_session_factory
from app.models.user import User, UserRole

# Argon2id is the recommended password hashing algorithm (memory-hard, GPU-resistant).
# passlib delegates to argon2-cffi under the hood when "argon2" is selected.
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
security_scheme = HTTPBearer(auto_error=True)

# Shared async Redis client – reused across requests.
# Lock ensures exactly one client is created even under concurrent startup.
_redis_client: aioredis.Redis | None = None
_redis_lock = threading.Lock()


def _get_redis() -> aioredis.Redis:
    global _redis_client
    if _redis_client is None:
        with _redis_lock:
            # Double-checked locking: re-check after acquiring the lock.
            if _redis_client is None:
                _redis_client = aioredis.from_url(
                    settings.redis_url,
                    encoding="utf-8",
                    decode_responses=True,
                )
    return _redis_client


def _token_cache_key(token: str) -> str:
    """Derive a short, stable Redis key from the raw JWT (no sensitive data stored as key)."""
    digest = hashlib.sha256(token.encode()).hexdigest()[:32]
    return f"np:session:{digest}"


async def db_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_factory() as session:
        yield session


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(
    subject: str,
    role: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a signed JWT for the given subject.

    The `role` field is embedded in the token for display; authorisation
    decisions always re-read the role from the Redis cache or database.
    """
    to_encode = {"sub": subject, "role": role}
    expire = datetime.utcnow() + (
        expires_delta
        if expires_delta is not None
        else timedelta(minutes=settings.access_token_expire_minutes)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.jwt_algorithm)


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Security(security_scheme)],
    db: AsyncSession = Depends(db_session),
) -> User:
    """Validate the bearer token and return the associated active User.

    Flow:
    1. Decode and verify the JWT signature / expiry.
    2. Look up the user in the Redis cache (avoids a DB round-trip on every request).
    3. On a cache miss, fetch from PostgreSQL and populate the cache with a TTL.
    """
    token = credentials.credentials
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
        )
        email: str = payload.get("sub")
        if not email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        ) from None

    # --- Redis cache lookup ---
    redis = _get_redis()
    cache_key = _token_cache_key(token)
    try:
        cached = await redis.get(cache_key)
        if cached:
            data = json.loads(cached)
            # Reconstruct a lightweight User-like object from the cache.
            user = User(
                id=data["id"],
                email=data["email"],
                full_name=data.get("full_name"),
                role=UserRole(data["role"]),
                is_active=data["is_active"],
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
        # Cache read failures should never block authentication.
        pass

    # --- Database fallback ---
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Inactive or missing user",
        )

    # Populate the cache; TTL matches the token's remaining lifetime.
    exp: int = payload.get("exp", 0)
    ttl = max(exp - int(datetime.utcnow().timestamp()), 60)
    try:
        await redis.setex(
            cache_key,
            ttl,
            json.dumps({
                "id": user.id,
                "email": user.email,
                "full_name": user.full_name,
                "role": user.role.value,
                "is_active": user.is_active,
            }),
        )
    except Exception:
        pass  # Never block on cache write failures.

    return user


def require_role(*allowed_roles: UserRole):
    """Return a dependency that enforces authentication + (optional) RBAC.

    - If no roles are provided, any authenticated user is allowed.
    - If roles are provided, the current user must have one of those roles.
    """

    async def _require(user: User = Depends(get_current_user)) -> User:
        if allowed_roles and user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user

    return _require


async def require_admin(
    request: Request,
    user: User = Depends(get_current_user),
) -> User:
    if user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )

    # Fire-and-forget audit log via Celery – never blocks the response.
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
        pass  # Never block admin operations on audit failures.

    return user
