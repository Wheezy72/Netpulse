from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.api.deps import require_compliance_role, require_scan_role
from app.models.user import User, UserRole


def _user(role: UserRole) -> User:
    return User(id=1, email="operator@example.com", role=role, is_active=True)


@pytest.mark.asyncio
async def test_compliance_role_allows_auditor() -> None:
    dep = require_compliance_role()
    user = _user(UserRole.AUDITOR)
    assert await dep(user) == user


@pytest.mark.asyncio
async def test_scan_role_rejects_auditor() -> None:
    dep = require_scan_role()
    user = _user(UserRole.AUDITOR)
    with pytest.raises(HTTPException):
        await dep(user)
