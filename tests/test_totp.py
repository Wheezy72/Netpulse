from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

from app.core.totp import (
    generate_recovery_codes,
    generate_secret,
    hash_recovery_code,
    hashes_for,
    match_recovery_code,
    normalize_code,
    provisioning_uri,
    totp_code,
    verify_totp,
)

_RFC_SECRET = base64.b32encode(b"12345678901234567890").decode().rstrip("=")


def _at(seconds: int) -> datetime:
    return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)


def test_matches_rfc_6238_vector():
    # RFC 6238, SHA-1, T=59s: 94287082. Six digits is the last six.
    assert totp_code(_RFC_SECRET, _at(59)) == "287082"


def test_accepts_code_from_neighbouring_step():
    code = totp_code(_RFC_SECRET, _at(59))
    assert verify_totp(_RFC_SECRET, code, _at(59)) is True
    assert verify_totp(_RFC_SECRET, code, _at(60)) is True
    # Two steps away is outside the allowance.
    assert verify_totp(_RFC_SECRET, code, _at(130)) is False


def test_rejects_wrong_shape_without_crashing():
    assert verify_totp(_RFC_SECRET, "", _at(59)) is False
    assert verify_totp(_RFC_SECRET, "abcdef", _at(59)) is False
    assert verify_totp("not-base32!!", "123456", _at(59)) is False
    assert verify_totp(_RFC_SECRET, "000000", _at(59)) is False


def test_spacing_in_typed_code_is_ignored():
    code = totp_code(_RFC_SECRET, _at(59))
    assert normalize_code(f"{code[:3]} {code[3:]}") == code
    assert verify_totp(_RFC_SECRET, f"{code[:3]} {code[3:]}", _at(59)) is True


def test_generated_secret_is_usable_and_unique():
    first, second = generate_secret(), generate_secret()
    assert first != second
    assert verify_totp(first, totp_code(first, _at(59)), _at(59)) is True


def test_provisioning_uri_carries_secret_and_issuer():
    uri = provisioning_uri(_RFC_SECRET, "admin@example.com")
    assert uri.startswith("otpauth://totp/")
    assert f"secret={_RFC_SECRET}" in uri
    assert "issuer=NetPulse" in uri


def test_recovery_codes_match_once_and_ignore_formatting():
    codes = generate_recovery_codes(4)
    stored = hashes_for(codes)
    assert len(codes) == len(set(codes)) == 4
    assert all(len(code) == 11 and code[5] == "-" for code in codes)

    index = match_recovery_code(stored, codes[2].lower().replace("-", " "))
    assert index == 2

    # The caller consumes it; the same code must not match again.
    remaining = [item for position, item in enumerate(stored) if position != index]
    assert match_recovery_code(remaining, codes[2]) is None


def test_recovery_code_lookup_rejects_unknown_and_short_input():
    stored = [hash_recovery_code("ABCDE-12345")]
    assert match_recovery_code(stored, "ABCDE-99999") is None
    assert match_recovery_code(stored, "abc") is None
    assert match_recovery_code([], "ABCDE-12345") is None
