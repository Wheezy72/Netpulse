from __future__ import annotations

from types import SimpleNamespace

from fastapi import Response

from app.core.session_cookie import (
    CSRF_COOKIE,
    CSRF_HEADER,
    SESSION_COOKIE,
    clear_session_cookies,
    csrf_problem,
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
