from __future__ import annotations

import os
from datetime import timedelta

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import create_access_token, db_session
from app.core.config import settings
from app.models.user import User, UserRole

GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

router = APIRouter()


class GoogleTokenRequest(BaseModel):
    code: str
    redirect_uri: str


class GoogleTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    is_new_user: bool = False


class GoogleConfigResponse(BaseModel):
    client_id: str | None = None
    enabled: bool = False


@router.get("/config", response_model=GoogleConfigResponse)
async def google_config() -> GoogleConfigResponse:
    client_id = settings.google_oauth_client_id or os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
    return GoogleConfigResponse(
        client_id=client_id,
        enabled=bool(client_id),
    )


@router.post("/callback", response_model=GoogleTokenResponse)
async def google_callback(
    payload: GoogleTokenRequest,
    db: AsyncSession = Depends(db_session),
) -> GoogleTokenResponse:
    client_id = settings.google_oauth_client_id or os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
    client_secret = settings.google_oauth_client_secret or os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")

    if not client_id or not client_secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Google OAuth is not configured",
        )

    async with httpx.AsyncClient() as client:
        discovery = await client.get(GOOGLE_DISCOVERY_URL)
        discovery_data = discovery.json()
        token_endpoint = discovery_data["token_endpoint"]
        userinfo_endpoint = discovery_data["userinfo_endpoint"]

        token_resp = await client.post(
            token_endpoint,
            data={
                "code": payload.code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": payload.redirect_uri,
                "grant_type": "authorization_code",
            },
        )

        if token_resp.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Failed to exchange authorization code",
            )

        token_data = token_resp.json()
        google_access_token = token_data.get("access_token")

        if not google_access_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No access token received from Google",
            )

        userinfo_resp = await client.get(
            userinfo_endpoint,
            headers={"Authorization": f"Bearer {google_access_token}"},
        )

        if userinfo_resp.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Failed to fetch user info from Google",
            )

        userinfo = userinfo_resp.json()

    if not userinfo.get("email_verified"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google email not verified",
        )

    email = userinfo["email"]
    full_name = userinfo.get("name")

    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    is_new_user = False

    if not user:
        existing_any = await db.execute(select(User).limit(1))
        first_user = existing_any.scalar_one_or_none()

        user = User(
            email=email,
            full_name=full_name,
            hashed_password=None,
            auth_provider="google",
            role=UserRole.ADMIN if not first_user else UserRole.OPERATOR,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        is_new_user = True

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    token = create_access_token(
        subject=user.email,
        role=user.role.value,
        expires_delta=access_token_expires,
    )

    return GoogleTokenResponse(
        access_token=token,
        is_new_user=is_new_user,
    )
