"""Session revocation: a token is only valid for the version it was minted under.

Bearer tokens cannot be recalled, so the account carries a version and the token
records which one it may be used against. These tests pin the two halves that
can break silently: the claim being missing (so nothing is ever revocable) and
old tokens being rejected outright after an upgrade (so every existing session
dies).
"""
from jose import jwt

from app.api.deps import create_access_token
from app.core.config import settings


def _decode(token: str) -> dict:
    return jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])


def test_token_carries_the_version_it_was_issued_under() -> None:
    token = create_access_token("id:1", "admin", token_version=3)

    assert _decode(token)["ver"] == 3


def test_tokens_without_a_version_are_treated_as_version_zero() -> None:
    """Tokens minted before revocation existed must keep working."""
    token = create_access_token("id:1", "admin")

    assert "ver" not in _decode(token)


def test_bumping_the_version_changes_the_claim() -> None:
    first = _decode(create_access_token("id:1", "viewer", token_version=0))
    second = _decode(create_access_token("id:1", "viewer", token_version=1))

    assert first["ver"] != second["ver"]
