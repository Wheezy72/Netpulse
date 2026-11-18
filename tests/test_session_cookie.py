from __future__ import annotations

from types import SimpleNamespace

from fastapi import Depends, FastAPI, Response, WebSocket
from fastapi.testclient import TestClient

from app.core.session_cookie import (
    CSRF_COOKIE,
    CSRF_HEADER,
    SESSION_COOKIE,
    clear_session_cookies,
    csrf_problem,
    require_csrf,
    set_session_cookies,
)


def _request(method: str, *, headers=None, cookies=None) -> SimpleNamespace:
    return SimpleNamespace(
        method=method,
        headers=headers or {},
        cookies=cookies or {},
        url=SimpleNamespace(scheme="http"),
    )


def _response_headers(response: Response) -> str:
    parts = []
    for key, value in response.raw_headers:
        if isinstance(key, bytes):
            key = key.decode()
        if isinstance(value, bytes):
            value = value.decode()
        parts.append(f"{key}: {value}")
    return "\n".join(parts)


def test_session_cookie_is_httponly_and_csrf_is_readable():
    response = Response()
    csrf = set_session_cookies(response, "token-value", max_age=3600)

    raw = _response_headers(response)
    assert f"{SESSION_COOKIE}=token-value" in raw
    assert "HttpOnly" in raw
    assert "SameSite=lax" in raw
    assert f"{CSRF_COOKIE}={csrf}" in raw


def test_secure_flag_follows_the_forwarded_scheme(monkeypatch):
    from app.core import session_cookie

    monkeypatch.setattr(session_cookie.settings, "cookie_secure", None, raising=False)
    https_request = _request("POST", headers={"X-Forwarded-Proto": "https"})
    response = Response()
    set_session_cookies(response, "t", max_age=60, request=https_request)
    assert "Secure" in _response_headers(response)

    plain = Response()
    set_session_cookies(plain, "t", max_age=60, request=_request("POST"))
    assert "Secure" not in _response_headers(plain)


def test_clear_removes_both_cookies():
    response = Response()
    clear_session_cookies(response)
    raw = _response_headers(response)
    assert SESSION_COOKIE in raw and CSRF_COOKIE in raw
    assert raw.count("Max-Age=0") >= 2


def test_safe_methods_need_no_csrf():
    request = _request("GET", cookies={SESSION_COOKIE: "t"})
    assert csrf_problem(request) is None


def test_bearer_requests_are_not_cookie_authenticated():
    request = _request(
        "POST",
        headers={"Authorization": "Bearer abc"},
        cookies={SESSION_COOKIE: "t"},
    )
    assert csrf_problem(request) is None


def test_cookie_write_without_token_is_refused():
    request = _request("POST", cookies={SESSION_COOKIE: "t"})
    assert csrf_problem(request) is not None


def test_cookie_write_with_matching_token_is_allowed():
    request = _request(
        "PATCH",
        headers={CSRF_HEADER: "abc123"},
        cookies={SESSION_COOKIE: "t", CSRF_COOKIE: "abc123"},
    )
    assert csrf_problem(request) is None


def test_cookie_write_with_wrong_token_is_refused():
    request = _request(
        "DELETE",
        headers={CSRF_HEADER: "nope"},
        cookies={SESSION_COOKIE: "t", CSRF_COOKIE: "abc123"},
    )
    assert csrf_problem(request) is not None


def test_anonymous_write_is_not_blocked_here():
    # Login and first-run setup arrive before any cookie exists; refusing them
    # here would make the console impossible to sign into.
    assert csrf_problem(_request("POST")) is None


def test_websocket_route_is_not_killed_by_the_csrf_guard():
    """The guard rides on the whole API router, WebSocket routes included.

    FastAPI injects no ``Request`` on a socket scope, so a guard that demanded
    one raised ``TypeError`` before the endpoint ran and every handshake — the
    SSH console included — answered HTTP 500. A socket must reach its handler.
    """
    socket_routes = FastAPI()

    @socket_routes.websocket("/socket")
    async def socket(websocket: WebSocket) -> None:  # noqa: ANN001
        await websocket.accept()
        await websocket.send_text("reached")
        await websocket.close()

    guarded = FastAPI()
    guarded.include_router(socket_routes.router, dependencies=[Depends(require_csrf)])

    with TestClient(guarded) as client:
        with client.websocket_connect("/socket") as websocket:
            assert websocket.receive_text() == "reached"


def _guarded_app() -> FastAPI:
    """A router carrying the guard the way ``app/main.py`` attaches it."""
    routes = FastAPI()

    @routes.post("/write")
    async def write() -> dict:
        return {"ok": True}

    guarded = FastAPI()
    guarded.include_router(routes.router, dependencies=[Depends(require_csrf)])
    return guarded


def test_cookie_write_through_the_router_still_needs_the_header():
    """The socket fix must not have made the guard miss HTTP requests.

    Annotating ``request`` as ``Request | None`` would make FastAPI treat it as
    a query parameter, leaving it ``None`` on every write and skipping the
    check — so the guard is exercised through a router, not called directly.
    """
    with TestClient(_guarded_app()) as client:
        client.cookies.set(SESSION_COOKIE, "t")
        client.cookies.set(CSRF_COOKIE, "abc123")
        assert client.post("/write").status_code == 403
        assert client.post("/write", headers={CSRF_HEADER: "abc123"}).status_code == 200


def test_writes_without_a_session_cookie_are_not_refused():
    # Bearer clients and sign-in arrive with no cookie to abuse.
    with TestClient(_guarded_app()) as client:
        assert client.post("/write").status_code == 200
