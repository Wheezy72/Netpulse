from __future__ import annotations

import json
import logging
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
    require_admin,
    subject_for_user,
    verify_password,
    security_scheme,
)
from app.core.config import settings
from app.core.redis import get_redis
from app.models.user import User, UserRole

logger = logging.getLogger("netpulse.auth")

router = APIRouter()

# Fallback window for the login throttle, used only while Redis is down.
# Per-process and bounded: it must never be the reason a sign-in fails.
_LOCAL_ATTEMPT_LIMIT = 200
_local_attempts: dict[str, list[float]] = {}


def _local_attempt_count(key: str, now: float, window_seconds: int) -> int:
    """Sliding window in process memory: how many attempts came before this one.

    Keeps the brute-force ceiling alive during a Redis outage instead of
    silently removing it, which is what the previous fail-open path did.
    """
    cutoff = now - window_seconds
    attempts = [stamp for stamp in _local_attempts.get(key, []) if stamp > cutoff]
    count_before = len(attempts)
    attempts.append(now)
    _local_attempts[key] = attempts[-_LOCAL_ATTEMPT_LIMIT:]

    if len(_local_attempts) > 2048:
        # Opportunistic sweep so many failing addresses cannot grow the map
        # without bound in a long-running process.
        for stale_key in [k for k, v in _local_attempts.items() if not v or v[-1] <= cutoff]:
            _local_attempts.pop(stale_key, None)
    return count_before


# Password floor for accounts and password changes. Six characters was the
# shortest that let a demo through; on a box that the whole LAN can reach it is
# guessable in an afternoon.
MIN_PASSWORD_LENGTH = 12

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

    Proxy headers are only believed when TRUST_PROXY_HEADERS is on. A direct
    port is otherwise one header away from an unlimited number of buckets.
    """
    client_ip = request.client.host if request.client else "unknown"
    if settings.trust_proxy_headers:
        if x_forwarded_for := request.headers.get("X-Forwarded-For"):
            # The first entry is the original client, written by the proxy.
            client_ip = x_forwarded_for.split(",")[0].strip() or client_ip
        elif x_real_ip := request.headers.get("X-Real-IP"):
            client_ip = x_real_ip.strip() or client_ip

    redis_client = get_redis()
    rate_limit_key = f"{key_prefix}{client_ip}"
    current_unix_time = datetime.utcnow().timestamp()
    window_start_time = current_unix_time - window_seconds

    try:
        async with redis_client.pipeline(transaction=True) as pipeline:
            pipeline.zremrangebyscore(rate_limit_key, "-inf", window_start_time)
            pipeline.zcard(rate_limit_key)
            pipeline.zadd(rate_limit_key, {str(current_unix_time): current_unix_time})
            pipeline.expire(rate_limit_key, window_seconds)
            results = await pipeline.execute()
        attempt_count_before_this_request = results[1]
    except Exception as exc:
        # Redis is a cache, not the source of truth: a hiccup must not turn a
        # sign-in into a 500. Falling back to an in-process window keeps the
        # brute-force ceiling in place while Redis is unavailable, instead of
        # silently disabling it.
        logger.warning("Login throttle unavailable, using local window: %s", exc)
        attempt_count_before_this_request = _local_attempt_count(
            rate_limit_key, current_unix_time, window_seconds
        )

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

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if len(value or "") < MIN_PASSWORD_LENGTH:
            raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
        return value


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
    summary="Create an account (first-run setup or admin)",
)
async def create_user(
    payload: CreateUserRequest,
    db: AsyncSession = Depends(db_session),
    caller: User | None = Depends(optional_current_user),
) -> Dict[str, Any]:
    """Create a local account.

    There are exactly two ways in:

      * An empty instance. The first account is always the administrator. It
        may be created from the setup screen; if SETUP_TOKEN is exported, the
        caller must present it, which keeps an internet-exposed first boot
        from being claimed by a stranger.
      * A populated instance. Public sign-up does not exist: the caller must
        already be an admin, and the account is either a viewer or an admin as
        that admin chose.
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

    if not first_user:
        # SETUP_TOKEN is optional. When it is set the first-run screen asks
        # for it, so a machine reachable from the network cannot be claimed by
        # whoever opens the port first.
        setup_token_env = (settings.setup_token or "").strip()
        if setup_token_env and not (
            payload.setup_token
            and secrets.compare_digest(payload.setup_token, setup_token_env)
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="A valid setup token is required to create the first account.",
            )
    else:
        # Closed signup: only an admin may add accounts. Without this, anyone
        # who could reach the port could mint a viewer account for themselves.
        if caller is None or caller.role != UserRole.ADMIN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Public sign-up is closed. Ask an administrator to add your account.",
            )

    # The first account owns the box. After that everyone is a viewer unless
    # the signed-in admin explicitly asks for admin.
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
        # An admin hands out the initial password, so it is temporary by
        # definition. The first account chose its own password and is not
        # forced through a second screen.
        force_password_change=first_user is not None,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    return {"id": user.id, "email": user.email, "role": user.role.value}


class UserSummary(BaseModel):
    """One account as the admin Users panel shows it.

    Deliberately excludes the password hash and any reset material — the panel
    needs identity and role, nothing else.
    """

    id: int
    username: str
    email: str | None = None
    full_name: str | None = None
    role: str
    created_at: datetime | None = None


@router.get(
    "/users",
    response_model=list[UserSummary],
    summary="List accounts (admin only)",
)
async def list_users(
    db: AsyncSession = Depends(db_session),
    caller: User = Depends(get_current_user),
) -> list[UserSummary]:
    """Every local account, newest last.

    Admin-only: the roster is not secret, but who can see it is a deliberate
    choice, and it keeps viewer accounts from enumerating colleagues.
    """
    if caller.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only an administrator can list accounts.",
        )

    result = await db.execute(select(User).order_by(User.id))
    return [
        UserSummary(
            id=user.id,
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            role=user.role.value,
            created_at=user.created_at,
        )
        for user in result.scalars().all()
    ]


@router.get(
    "/setup-status",
    summary="Whether this instance still needs its first administrator",
)
async def setup_status(db: AsyncSession = Depends(db_session)) -> Dict[str, Any]:
    """Tell the login screen whether to offer first-run setup.

    There is no public sign-up: once an account exists, accounts are added by
    an admin in Settings. The only open door is an empty instance, which must
    be able to name its first administrator.
    """
    existing = await db.execute(select(User.id).limit(1))
    needs_setup = existing.scalar_one_or_none() is None
    return {
        "needs_setup": needs_setup,
        "token_required": bool((settings.setup_token or "").strip()),
    }


async def _revoke_user_sessions(user_id: int) -> int:
    """Drop every cached session belonging to *user_id*, returning the count.

    ``get_current_user`` serves an authenticated user straight from Redis for
    the token's whole lifetime (30 days with "remember me"), so deleting the
    row alone would leave that person signed in until the cache expired.
    Session keys are keyed by token digest, not by user, so the only way to
    find them is to scan the small ``np:session:*`` namespace.
    """
    removed = 0
    try:
        redis = get_redis()
        async for key in redis.scan_iter(match="np:session:*", count=100):
            try:
                raw = await redis.get(key)
                if not raw:
                    continue
                data = json.loads(raw)
            except Exception:
                continue
            if int(data.get("id", -1)) == user_id:
                await redis.delete(key)
                removed += 1
    except Exception as exc:  # pragma: no cover - Redis optional
        logger.warning("Could not revoke cached sessions for user %s: %s", user_id, exc)
    return removed


class UserRoleUpdate(BaseModel):
    """Payload for moving an existing account between the two roles."""

    role: str


@router.patch(
    "/users/{user_id}",
    response_model=UserSummary,
    summary="Change an account's role (admin only)",
)
async def update_user_role(
    user_id: int,
    payload: UserRoleUpdate,
    db: AsyncSession = Depends(db_session),
    caller: User = Depends(require_admin),
) -> UserSummary:
    """Promote or demote an existing account.

    Two guards, matching the delete endpoint:
      * an admin cannot change their own role, so a mis-click cannot leave the
        person who made it locked out mid-session;
      * the last remaining admin cannot be demoted.

    A role change clears that account's cached session: the resolved role is
    held in the Redis session cache (populated at sign-in, valid up to 30 days
    with "remember me"). Clearing it forces the next request to re-read the
    role from the database, so the new permissions apply without waiting for
    the cache to expire.
    """
    try:
        new_role = UserRole(payload.role.strip().lower())
    except (AttributeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unknown role. Use 'admin' or 'viewer'.",
        ) from None

    if user_id == caller.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot change your own role. Ask another admin to do it.",
        )

    target = await db.get(User, user_id)
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No such account.",
        )

    if target.role != new_role and target.role == UserRole.ADMIN:
        admins = await db.execute(select(User.id).where(User.role == UserRole.ADMIN))
        remaining = [row for row in admins.scalars().all() if row != user_id]
        if not remaining:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This is the only admin account. Promote another account first.",
            )

    changed = target.role != new_role
    # Snapshot before commit: the async session expires attributes on commit,
    # and reading them afterwards would trigger a lazy load outside greenlet
    # context.
    summary = UserSummary(
        id=target.id,
        username=target.username,
        email=target.email,
        full_name=target.full_name,
        role=new_role.value,
        created_at=target.created_at,
    )
    target.role = new_role
    await db.commit()

    if changed:
        revoked = await _revoke_user_sessions(user_id)
        logger.info(
            "Admin %s changed %r to %s; %s cached session(s) revoked.",
            caller.username,
            target.username,
            new_role.value,
            revoked,
        )

    return summary


@router.delete(
    "/users/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an account (admin only)",
)
async def delete_user(
    user_id: int,
    db: AsyncSession = Depends(db_session),
    caller: User = Depends(require_admin),
) -> None:
    """Remove an account, keeping its scan history intact.

    Two guards, both about not locking yourself out:
      * an admin cannot delete the account they are signed in with;
      * the last remaining admin cannot be deleted, whatever the session.
    Scan jobs are detached (``requested_by_user_id`` set to NULL) rather than
    cascaded, because the audit trail of who scanned what is worth keeping.
    """
    if user_id == caller.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot delete the account you are signed in with.",
        )

    target = await db.get(User, user_id)
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No such account.",
        )

    if target.role == UserRole.ADMIN:
        admins = await db.execute(select(User.id).where(User.role == UserRole.ADMIN))
        remaining = [row for row in admins.scalars().all() if row != user_id]
        if not remaining:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This is the only admin account. Promote another account first.",
            )

    from sqlalchemy import update as sa_update

    from app.models.scan_job import ScanJob

    await db.execute(
        sa_update(ScanJob)
        .where(ScanJob.requested_by_user_id == user_id)
        .values(requested_by_user_id=None)
    )
    username = target.username
    await db.delete(target)
    await db.commit()

    revoked = await _revoke_user_sessions(user_id)
    logger.info(
        "Admin %s deleted account %r (id=%s); %s cached session(s) revoked.",
        caller.username,
        username,
        user_id,
        revoked,
    )


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

    if len(payload.new_password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"New password must be at least {MIN_PASSWORD_LENGTH} characters.",
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
        return {"message": "If an account with that email exists, a reset code has been issued."}

    token = secrets.token_urlsafe(32)
    import hashlib
    hashed_token = hashlib.sha256(token.encode()).hexdigest()

    user.reset_token = hashed_token
    user.reset_token_expires = datetime.utcnow() + timedelta(hours=1)
    await db.commit()

    # Log the plaintext token to the console so the administrator can copy-paste it
    logger.warning("PASSWORD RESET REQUESTED FOR %s. RESET TOKEN: %s", user.email, token)

    return {"message": "If an account with that email exists, a reset code has been issued."}


@router.post(
    "/reset-password",
    summary="Reset password using a valid reset token",
    dependencies=[Depends(_enforce_reset_rate_limit)],
)
async def reset_password(
    payload: ResetPasswordRequest,
    db: AsyncSession = Depends(db_session),
) -> Dict[str, str]:
    if len(payload.new_password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password must be at least {MIN_PASSWORD_LENGTH} characters.",
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
