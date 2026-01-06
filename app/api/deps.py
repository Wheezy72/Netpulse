from __future__ import annotations

"""
Shared FastAPI dependencies and security helpers.

Provides:
- db_session: async SQLAlchemy session dependency.
- Password hashing helpers.
- JWT creation and validation.
- A simple authentication dependency (require_role) that ensures the
  caller is authenticated; all authenticated users are treated the same.
"""

from datetime import datetime, timedelta
from typing import Annotated, AsyncGenerator, Optional

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import async_session_factory
from app.models.user import User

# Use a password hashing scheme that doesn't rely on the external bcrypt module
# to avoid compatibility issues with newer bcrypt releases.
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
security_scheme = HTTPBearer(auto_error=True)


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

    The `role` field is preserved in the token for backward compatibility
    and potential display purposes, but it is not enforced by the backend.
    All authenticated users are treated equally by the API.
    """
    to_encode = {"sub": subject, "role": role}
    expire = datetime.utcnow() + (
        expires_delta
        if expires_delta is not None
        else timedelta(minutes=settings.access_token_expire_minutes)
    )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode,
        settings.secret_key,
        algorithm=settings.jwt_algorithm,
    )
    return encoded_jwt


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Security(security_scheme)],
    db: AsyncSession = Depends(db_session),
) -> User:
    """Decode the bearer token and return the associated active User."""
    token = credentials.credentials
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
        )
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        ) from None

    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Inactive or missing user",
        )

    return user


def require_role(*_allowed_roles: object):
    """Return a dependency that ensures the caller is authenticated.

    RBAC has been simplified for this personal deployment: all authenticated
    users are treated the same. This helper is kept so existing route
    dependencies continue to work, but it only enforces authentication,
    not per-role permissions.
    """

    async def _require(user: User = Depends(get_current_user)) -> User:
        return user

    return _require