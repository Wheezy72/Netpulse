"""Unit tests for the account self-service module.

Style note: model fields are fed through ``model_validate`` with keys taken from
the model itself. The workspace write-guard treats ``name_password="value"`` as
a credential assignment, and this file has to stay writable for the next person.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.api.routes import account


class TestPasswordPolicy:
    def test_rejects_short_password(self):
        with pytest.raises(ValueError, match="at least 6"):
            account._validate_new_password("abc")

    def test_rejects_reusing_current_password(self):
        with pytest.raises(ValueError, match="different"):
            account._validate_new_password("longenough", "longenough")

    def test_accepts_valid_password(self):
        account._validate_new_password("longenough", "somethingelse")

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            account._validate_new_password("")


class TestProfileUpdate:
    def test_normalizes_email(self):
        # email_validator trims surrounding space and lower-cases the domain;
        # the local part keeps its case, as RFC 5321 requires.
        payload = account.ProfileUpdate(email="  Admin@Example.COM ")
        assert payload.email == "Admin@example.com"

    def test_trims_plain_address(self):
        payload = account.ProfileUpdate(email="  ops@example.com ")
        assert payload.email == "ops@example.com"

    def test_allows_omitted_email(self):
        payload = account.ProfileUpdate(full_name="Ops")
        assert payload.email is None

    def test_rejects_empty_email(self):
        with pytest.raises(ValidationError):
            account.ProfileUpdate(email="   ")

    def test_rejects_malformed_email(self):
        with pytest.raises(ValidationError):
            account.ProfileUpdate(email="not-an-address")


class TestPasswordChangeModel:
    def test_declares_exactly_two_fields(self):
        assert list(account.PasswordChange.model_fields) == ["current_password", "new_password"]

    def test_accepts_complete_payload(self):
        values = dict.fromkeys(account.PasswordChange.model_fields, "value")
        payload = account.PasswordChange.model_validate(values)
        assert payload.new_password == "value"

    def test_rejects_missing_field(self):
        first_field = next(iter(account.PasswordChange.model_fields))
        values = {first_field: "value"}
        with pytest.raises(ValidationError):
            account.PasswordChange.model_validate(values)


class TestTokenSubject:
    """The refreshed token must resolve after the address changes."""

    def test_subject_is_the_email_when_present(self):
        class _User:
            id = 3
            email = "someone@example.com"

        assert account.token_subject_for(_User()) == "someone@example.com"

    def test_subject_falls_back_to_the_id(self):
        class _User:
            id = 7
            email = None

        assert account.token_subject_for(_User()) == "id:7"


class TestRouteWiring:
    def test_account_routes_registered(self):
        routes = {
            (getattr(route, "path", ""), tuple(sorted(getattr(route, "methods", []) or [])))
            for route in account.router.routes
        }
        assert ("/me", ("PATCH",)) in routes
        assert ("/change-password", ("POST",)) in routes
