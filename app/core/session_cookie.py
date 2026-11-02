"""Session cookies and the CSRF check that comes with them.

The browser used to hold its access token in localStorage, where any script that
managed to run on the page could read it and keep it. A cookie marked ``HttpOnly``
is invisible to JavaScript, so an injected script can act *during* the visit but
cannot walk away with a thirty-day credential.

A cookie is sent automatically, which is exactly why it needs a CSRF defence: a
double-submit token pairs a random value in a readable cookie with the same
value in a request header, and a cross-site page can set neither.

Bearer tokens keep working untouched. They are what tests, scripts and the CLI
use, and a cross-site page cannot attach an Authorization header, so requests
carrying one skip the CSRF check.
"""
from __future__ import annotations

import secrets

from fastapi import HTTPException, Request, Response, status

from app.core.config import settings

SESSION_COOKIE = "np_session"
CSRF_COOKIE = "np_csrf"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})

# Long enough to outlive any token the cookie can hold, so the pair is cleared
# together rather than one of them lingering.
CSRF_COOKIE_MAX_AGE = 60 * 60 * 24 * 30


def _secure(request: Request | None) -> bool:
    """Whether to mark the cookies ``Secure``.

    ``COOKIE_SECURE`` wins when set. Otherwise the request decides: behind a
    TLS-terminating proxy the scheme the app sees is plain http, so the
    forwarded header is consulted before giving up. Defaulting to False keeps a
    LAN install on http working — a ``Secure`` cookie on a plain-http console
    is silently dropped, and sign-in would fail with no error anywhere.
    """
    if settings.cookie_secure is not None:
        return bool(settings.cookie_secure)
    if request is None:
        return False
    forwarded = (request.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower()
    if forwarded:
        return forwarded == "https"
    return request.url.scheme == "https"


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def set_session_cookies(
    response: Response,
    token: str,
    *,
    max_age: int,
    request: Request | None = None,
) -> str:
    """Issue the session and CSRF cookies, returning the CSRF value.

    ``SameSite=Lax`` keeps the cookie off cross-site subrequests while still
    surviving a normal top-level navigation back into the app.
    """
    secure = _secure(request)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=max_age,
        httponly=True,
        samesite="lax",
        secure=secure,
        path="/",
    )
    csrf = new_csrf_token()
    response.set_cookie(
        CSRF_COOKIE,
        csrf,
        max_age=max(CSRF_COOKIE_MAX_AGE, max_age),
        # Readable on purpose: the client copies it into the request header.
        httponly=False,
        samesite="lax",
        secure=secure,
        path="/",
    )
    return csrf


def clear_session_cookies(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")


def session_token_from_request(request: Request) -> str:
    try:
        return (request.cookies.get(SESSION_COOKIE) or "").strip()
    except Exception:  # noqa: BLE001 - a missing cookie jar is simply no token
        return ""


def csrf_problem(request: Request) -> str | None:
    """None when the request may proceed, else why it may not."""
    if request.method.upper() in SAFE_METHODS:
        return None

    # Bearer clients are not cookie-authenticated, and a cross-site page cannot
    # set an Authorization header, so CSRF does not apply to them.
    authorization = request.headers.get("Authorization") or ""
    if authorization.lower().startswith("bearer "):
        return None

    if not request.cookies.get(SESSION_COOKIE):
        return None

    expected = request.cookies.get(CSRF_COOKIE) or ""
    provided = request.headers.get(CSRF_HEADER) or ""
    if expected and provided and secrets.compare_digest(expected, provided):
        return None
    return "CSRF token missing or invalid"


def require_csrf(request: Request) -> None:
    """Router-level dependency: refuse cookie-authenticated writes without a token."""
    problem = csrf_problem(request)
    if problem:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=problem)
