from __future__ import annotations

import hashlib
import json
import logging
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
from app.core.redis import get_redis, note_redis_failure, note_redis_success, redis_reachable
from app.core.session_cookie import session_token_from_request
from app.db.session import async_session_factory
from app.models.user import User, UserRole
from app.core.clock import utcnow

logger = logging.getLogger("netpulse.audit")

ph = PasswordHasher()
security_scheme = HTTPBearer(auto_error=False)

# Tokens issued before 2026-10 carry the email address as their subject. New
# tokens carry "id:<user id>", which survives an email change and works for
# accounts that have no address yet.
SUBJECT_ID_PREFIX = "id:"


def _token_cache_key(token: str) -> str:
    digest = hashlib.sha256(token.encode()).hexdigest()[:32]
    return f"np:session:{digest}"


def _extract_token(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None,
) -> str:
    """The caller's token: an explicit bearer header first, else the cookie.

    Bearer wins when both are present so a script can act as a user without
    touching the browser session. The cookie is what the SPA uses; it is
    HttpOnly, so page scripts cannot read it.
    """
    if credentials is not None and credentials.credentials:
        return credentials.credentials.strip()
    return session_token_from_request(request)


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
    token_version: int | None = None,
) -> str:
    to_encode: dict[str, object] = {"sub": subject, "role": role}
    if token_version is not None:
        # The version this token is only valid under. Tokens minted before this
        # existed carry no claim and are treated as version 0.
        to_encode["ver"] = int(token_version)
    expire = utcnow() + (
        expires_delta
        if expires_delta is not None
        else timedelta(minutes=settings.access_token_expire_minutes)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.jwt_algorithm)


async def revoke_sessions(db: AsyncSession, user: User) -> int:
    """Invalidate every token issued for *user* so far.

    Bearer tokens cannot be un-issued, so the account carries a version and a
    token is only accepted when it matches. The new version is also written to
    Redis, because the session cache would otherwise keep serving a stale copy
    of the user (and a still-valid token) until its TTL expired.
    """
    user.token_version = int(getattr(user, "token_version", 0) or 0) + 1
    await db.commit()
    if redis_reachable():
        try:
            await get_redis().set(f"np:tokenver:{user.id}", str(user.token_version))
            note_redis_success()
        except Exception as exc:  # noqa: BLE001 - the database is the truth
            note_redis_failure(exc)
            logger.warning("Could not mark session revocation in Redis for user %s", user.id)
    return int(user.token_version)


async def _token_version_revoked(user_id: int, token_version: int) -> bool:
    """True when a bumped version has already invalidated this token."""
    if user_id <= 0:
        return False
    if not redis_reachable():
        return False
    try:
        stored = await get_redis().get(f"np:tokenver:{user_id}")
        note_redis_success()
    except Exception as exc:  # noqa: BLE001 - fall back to the database check
        note_redis_failure(exc)
        return False
    if stored is None:
        return False
    try:
        return int(stored) != int(token_version)
    except (TypeError, ValueError):
        return False


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
    request: Request,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Security(security_scheme)
    ] = None,
    db: AsyncSession = Depends(db_session),
) -> User:
    """Validate the bearer token and return the active User.

    Checks the Redis session cache first; falls back to the database on a miss.
    """
    token = _extract_token(request, credentials)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        redis = get_redis() if redis_reachable() else None
    except RuntimeError:  # pool not initialised (tests, bare scripts)
        redis = None
    digest = hashlib.sha256(token.encode()).hexdigest()[:32]

    # Check if token is blacklisted
    try:
        if redis is not None and await redis.get(f"np:blacklist:{digest}"):
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

    # A bumped session version invalidates every token issued before it. This is
    # what "sign out everywhere" and a password change rely on.
    token_version = int(payload.get("ver") or 0)
    parsed_subject = parse_subject(subject)
    if parsed_subject is not None and parsed_subject[0] == "id":
        if await _token_version_revoked(int(parsed_subject[1]), token_version):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session has been revoked",
            )

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
                token_version=data.get("token_version", 0),
            )
            if not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Inactive or missing user",
                )
            if int(getattr(user, "token_version", 0) or 0) != token_version:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Session has been revoked",
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

    if int(getattr(user, "token_version", 0) or 0) != token_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been revoked",
        )

    exp: int = payload.get("exp", 0)
    ttl = max(exp - int(utcnow().timestamp()), 60)
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
                "token_version": int(getattr(user, "token_version", 0) or 0),
            }),
        )
    except Exception:
        pass

    return user


async def record_audit(
    user_id: int | None,
    method: str,
    path: str,
    ip_address: str | None = None,
    details: dict | None = None,
) -> None:
    """Write an audit row directly to the database.

    This used to be handed to Celery with a bare ``except: pass``. A no-worker
    install therefore produced no audit trail at all while the code looked as
    if it did. The write is a single insert, so doing it in-process is cheaper
    than the broker round-trip it replaced.
    """
    from app.models.audit_log import AuditLog

    try:
        async with async_session_factory() as session:
            session.add(
                AuditLog(
                    user_id=user_id,
                    method=method,
                    path=path,
                    action=f"{method} {path}",
                    ip_address=ip_address,
                    details=details or {},
                )
            )
            await session.commit()
    except Exception as exc:  # never let auditing break the request
        logger.warning("Could not write audit log for %s %s: %s", method, path, exc)


def require_role(*allowed_roles: UserRole):
    """Return a dependency that requires authentication and optionally a specific role."""

    async def _require(
        user: User = Depends(get_current_user),
        # Annotated as Request (not `Request | None`) so FastAPI injects it;
        # the default keeps direct calls such as `dep(user)` in tests working.
        request: Request = None,  # type: ignore[assignment]
    ) -> User:
        if allowed_roles and user.role not in allowed_roles:
            if request is not None:
                await record_audit(
                    user.id,
                    request.method,
                    request.url.path,
                    getattr(request.client, "host", None),
                    {"role": user.role.value, "denied": True},
                )
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
    request: Request,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Security(_optional_security_scheme)
    ] = None,
    db: AsyncSession = Depends(db_session),
) -> User | None:
    """Resolve the caller when a token is present, else ``None``.

    Used by account creation: the first account is authorised by SETUP_TOKEN
    (when one is configured), later ones by an admin's bearer token, and an
    anonymous request resolves to ``None`` so the closed-signup gate can
    refuse it.
    """
    token = _extract_token(request, credentials)
    if not token:
        return None
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
    if user is None or not user.is_active:
        return None
    if int(getattr(user, "token_version", 0) or 0) != int(payload.get("ver") or 0):
        return None
    return user


async def require_admin(
    request: Request,
    user: User = Depends(get_current_user),
) -> User:
    if user.role != UserRole.ADMIN:
        await record_audit(
            user.id,
            request.method,
            request.url.path,
            getattr(request.client, "host", None),
            {"role": user.role.value, "denied": True},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )

    await record_audit(
        user.id,
        request.method,
        request.url.path,
        getattr(request.client, "host", None),
        {
            "query": dict(request.query_params),
            "path_params": request.scope.get("path_params", {}),
        },
    )

    return user
