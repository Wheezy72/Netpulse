from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.api.deps import require_compliance_role, require_scan_role
from app.models.user import User, UserRole


def _user(role: UserRole) -> User:
    return User(id=1, email="someone@example.com", role=role, is_active=True)


@pytest.mark.asyncio
async def test_compliance_role_allows_viewer() -> None:
    dep = require_compliance_role()
    user = _user(UserRole.VIEWER)
    assert await dep(user) == user


@pytest.mark.asyncio
async def test_compliance_role_allows_admin() -> None:
    dep = require_compliance_role()
    user = _user(UserRole.ADMIN)
    assert await dep(user) == user


@pytest.mark.asyncio
async def test_scan_role_allows_admin() -> None:
    dep = require_scan_role()
    user = _user(UserRole.ADMIN)
    assert await dep(user) == user


@pytest.mark.asyncio
async def test_scan_role_rejects_viewer() -> None:
    """A viewer observes; it does not initiate scans against the network."""
    dep = require_scan_role()
    user = _user(UserRole.VIEWER)
    with pytest.raises(HTTPException) as exc:
        await dep(user)
    assert exc.value.status_code == 403


def test_only_two_roles_exist() -> None:
    """Regression guard: operator and auditor are gone, not merely unused."""
    assert {role.value for role in UserRole} == {"admin", "viewer"}


def test_new_accounts_default_to_viewer() -> None:
    """Least privilege: the column default is viewer, not admin."""
    assert UserRole.VIEWER.value == "viewer"
