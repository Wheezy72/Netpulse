from __future__ import annotations

from datetime import timedelta
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, status
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

# Authentication and user management endpoints.
# In production you would typically front this with SSO, but a small local
# user table is sufficient for self-hosted or lab deployments.
router = APIRouter()


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
    role: UserRole = UserRole.OPERATOR


class UserMeResponse(BaseModel):
    id: int
    email: EmailStr
    full_name: str | None = None
    role: UserRole



@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Obtain an access token via email and password",
)
async def login(
    payload: LoginRequest,
    db: AsyncSession = Depends(db_session),
) -> TokenResponse:
    """Authenticate a user and return a JWT access token."""
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if user is None or not verify_password(payload.password, user.hashed_password):
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
        role=payload.role if first_user else UserRole.ADMIN,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    return {"id": user.id, "email": user.email, "role": user.role.value}