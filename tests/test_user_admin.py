"""Guards on admin account deletion.

Every rule here exists to stop an admin from locking themselves out of the
instance, so each one is pinned by a test rather than left to the UI.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.api.routes import auth as auth_routes
from app.models.user import User, UserRole


class _Result:
    def __init__(self, values: list[int]) -> None:
        self._values = values

    def scalars(self) -> "_Result":
        return self

    def all(self) -> list[int]:
        return self._values


class _FakeSession:
    """Just enough AsyncSession for the delete path."""

    def __init__(self, target: User | None, admin_ids: list[int] | None = None) -> None:
        self.target = target
        self.admin_ids = admin_ids or []
        self.deleted: User | None = None
        self.committed = False
        self.executed: list[object] = []

    async def get(self, _model, _pk):  # noqa: ANN001, ANN201 - duck-typed
        return self.target

    async def execute(self, statement):  # noqa: ANN001, ANN201
        self.executed.append(statement)
        return _Result(self.admin_ids)

    async def delete(self, obj) -> None:  # noqa: ANN001
        self.deleted = obj

    async def commit(self) -> None:
        self.committed = True


class _Caller:
    id = 1
    username = "admin"
    role = UserRole.ADMIN


def _user(user_id: int, role: UserRole, username: str) -> User:
    return User(id=user_id, username=username, role=role, hashed_password="x", is_active=True)


@pytest.fixture(autouse=True)
def _no_redis(monkeypatch: pytest.MonkeyPatch) -> None:
    """Session revocation talks to Redis; the guards under test do not."""
    async def _skip(_user_id: int) -> int:
        return 0

    monkeypatch.setattr(auth_routes, "_revoke_user_sessions", _skip)


@pytest.mark.asyncio
async def test_refuses_to_delete_your_own_account() -> None:
    with pytest.raises(HTTPException) as exc:
        await auth_routes.delete_user(_Caller.id, db=_FakeSession(None), caller=_Caller())
    assert exc.value.status_code == 400
    assert "signed in" in exc.value.detail


@pytest.mark.asyncio
async def test_unknown_account_is_404() -> None:
    with pytest.raises(HTTPException) as exc:
        await auth_routes.delete_user(99, db=_FakeSession(None), caller=_Caller())
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_last_admin_cannot_be_deleted() -> None:
    target = _user(2, UserRole.ADMIN, "second-admin")
    session = _FakeSession(target, admin_ids=[2])
    with pytest.raises(HTTPException) as exc:
        await auth_routes.delete_user(2, db=session, caller=_Caller())
    assert exc.value.status_code == 409
    assert session.deleted is None


@pytest.mark.asyncio
async def test_second_admin_can_be_deleted_when_another_remains() -> None:
    target = _user(2, UserRole.ADMIN, "second-admin")
    session = _FakeSession(target, admin_ids=[1, 2])
    await auth_routes.delete_user(2, db=session, caller=_Caller())
    assert session.deleted is target
    assert session.committed is True


@pytest.mark.asyncio
async def test_viewer_account_is_detached_from_scan_history_before_delete() -> None:
    target = _user(5, UserRole.VIEWER, "viewer1")
    session = _FakeSession(target)
    await auth_routes.delete_user(5, db=session, caller=_Caller())
    assert session.deleted is target
    # The UPDATE detaching scan jobs precedes the DELETE, otherwise the FK
    # constraint refuses the delete outright.
    assert session.executed, "the scan-job detach statement was skipped"
    assert "UPDATE scan_jobs" in str(session.executed[0])


@pytest.mark.asyncio
async def test_admin_can_promote_a_viewer() -> None:
    target = _user(5, UserRole.VIEWER, "viewer1")
    session = _FakeSession(target)
    result = await auth_routes.update_user_role(
        5, auth_routes.UserRoleUpdate(role="admin"), db=session, caller=_Caller()
    )
    assert target.role == UserRole.ADMIN
    assert result.role == "admin"
    assert session.committed is True


@pytest.mark.asyncio
async def test_admin_can_demote_a_second_admin() -> None:
    target = _user(2, UserRole.ADMIN, "second-admin")
    session = _FakeSession(target, admin_ids=[1, 2])
    result = await auth_routes.update_user_role(
        2, auth_routes.UserRoleUpdate(role="viewer"), db=session, caller=_Caller()
    )
    assert target.role == UserRole.VIEWER
    assert result.role == "viewer"


@pytest.mark.asyncio
async def test_last_admin_cannot_be_demoted() -> None:
    target = _user(2, UserRole.ADMIN, "second-admin")
    session = _FakeSession(target, admin_ids=[2])
    with pytest.raises(HTTPException) as exc:
        await auth_routes.update_user_role(
            2, auth_routes.UserRoleUpdate(role="viewer"), db=session, caller=_Caller()
        )
    assert exc.value.status_code == 409
    assert target.role == UserRole.ADMIN
    assert session.committed is False


@pytest.mark.asyncio
async def test_admin_cannot_change_their_own_role() -> None:
    session = _FakeSession(_user(1, UserRole.ADMIN, "admin"), admin_ids=[1])
    with pytest.raises(HTTPException) as exc:
        await auth_routes.update_user_role(
            1, auth_routes.UserRoleUpdate(role="viewer"), db=session, caller=_Caller()
        )
    assert exc.value.status_code == 400
    assert "own role" in exc.value.detail


@pytest.mark.asyncio
async def test_unknown_role_is_rejected() -> None:
    session = _FakeSession(_user(5, UserRole.VIEWER, "viewer1"))
    with pytest.raises(HTTPException) as exc:
        await auth_routes.update_user_role(
            5, auth_routes.UserRoleUpdate(role="operator"), db=session, caller=_Caller()
        )
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_role_change_revokes_cached_sessions(monkeypatch: pytest.MonkeyPatch) -> None:
    revoked: list[int] = []

    async def _capture(user_id: int) -> int:
        revoked.append(user_id)
        return 1

    monkeypatch.setattr(auth_routes, "_revoke_user_sessions", _capture)
    target = _user(5, UserRole.VIEWER, "viewer1")
    await auth_routes.update_user_role(
        5, auth_routes.UserRoleUpdate(role="admin"), db=_FakeSession(target), caller=_Caller()
    )
    assert revoked == [5]


def test_delete_route_is_registered() -> None:
    routes = {
        (getattr(route, "path", ""), tuple(sorted(getattr(route, "methods", []) or [])))
        for route in auth_routes.router.routes
    }
    assert ("/users/{user_id}", ("DELETE",)) in routes
    assert ("/users/{user_id}", ("PATCH",)) in routes
    assert ("/users", ("GET",)) in routes
