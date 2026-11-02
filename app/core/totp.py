"""Time-based one-time passwords and single-use recovery codes.

Implemented against RFC 4226/6238 directly rather than pulled from a package:
the algorithm is thirty lines of HMAC, and a two-factor scheme is the wrong
place to inherit a dependency's password-handling assumptions. Every comparison
here is constant-time.

The second factor protects the case the rest of this app cannot fix by
configuration: a password that leaked. A stolen password alone must not open a
console that can rewrite firewall rules.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
from datetime import datetime
from typing import Iterable, Sequence
from urllib.parse import quote, urlencode

from app.core.clock import utcnow

STEP_SECONDS = 30
DIGITS = 6
SECRET_BYTES = 20
# One thirty-second step either side, which is the usual allowance for a phone
# and a server whose clocks disagree slightly.
DRIFT_STEPS = 1
RECOVERY_CODE_COUNT = 8


def generate_secret() -> str:
    """A fresh base32 secret (160 bits, the size RFC 4226 recommends)."""
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode("ascii").rstrip("=")


def _decode_secret(secret: str) -> bytes:
    """Base32-decode a stored secret, tolerating padding and spacing."""
    cleaned = (secret or "").strip().replace(" ", "").replace("-", "").upper()
    cleaned += "=" * (-len(cleaned) % 8)
    try:
        return base64.b32decode(cleaned, casefold=True)
    except Exception:  # noqa: BLE001 - a corrupt secret simply never matches
        return b""


def _hotp(key: bytes, counter: int) -> str:
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10**DIGITS)).zfill(DIGITS)


def normalize_code(code: str | None) -> str:
    """Digits only, so "123 456" and "123-456" both work.

    Authenticator apps group the digits differently depending on the platform,
    and asking someone to retype what their phone shows without the space is a
    support ticket waiting to happen.
    """
    return "".join(ch for ch in (code or "") if ch.isdigit())


def totp_code(secret: str, at: datetime | None = None) -> str:
    """The code *secret* produces for the step containing *at*."""
    key = _decode_secret(secret)
    if not key:
        return ""
    moment = at or utcnow()
    return _hotp(key, int(moment.timestamp()) // STEP_SECONDS)


def verify_totp(
    secret: str,
    code: str | None,
    at: datetime | None = None,
    drift: int = DRIFT_STEPS,
) -> bool:
    """True when *code* is the one this secret produces near *at*.

    A wrong-length or non-numeric code is rejected before any HMAC work, and
    the comparison itself is constant-time.
    """
    key = _decode_secret(secret)
    candidate = normalize_code(code)
    if not key or len(candidate) != DIGITS:
        return False
    moment = at or utcnow()
    counter = int(moment.timestamp()) // STEP_SECONDS
    matched = False
    for offset in range(-drift, drift + 1):
        if hmac.compare_digest(_hotp(key, counter + offset), candidate):
            matched = True
    return matched


def provisioning_uri(secret: str, account: str, issuer: str = "NetPulse") -> str:
    """The ``otpauth://`` URL an authenticator app expects.

    Returned as text rather than a QR image: the browser has no QR encoder in
    this build, and the same string can be typed, pasted or scanned later.
    """
    label = quote(f"{issuer}:{account}", safe="")
    query = urlencode(
        {
            "secret": secret,
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": DIGITS,
            "period": STEP_SECONDS,
        }
    )
    return f"otpauth://totp/{label}?{query}"


def normalize_recovery_code(code: str | None) -> str:
    return "".join(ch for ch in (code or "").upper() if ch.isalnum())


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    """One-time codes, shown once, stored only as hashes.

    Grouped in fives because that is how people copy them onto paper; the
    grouping carries no meaning and is stripped before hashing.
    """
    codes: list[str] = []
    for _ in range(count):
        raw = secrets.token_hex(5).upper()
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def hash_recovery_code(code: str | None) -> str:
    return hashlib.sha256(normalize_recovery_code(code).encode("utf-8")).hexdigest()


def match_recovery_code(stored_hashes: Sequence[str] | None, code: str | None) -> int | None:
    """Index of the matching stored hash, or None.

    Returns the index rather than a boolean so the caller can consume exactly
    the code that was used — a recovery code is single-use.
    """
    candidate = hash_recovery_code(code)
    if len(normalize_recovery_code(code)) < 6:
        return None
    for index, stored in enumerate(stored_hashes or []):
        if hmac.compare_digest(str(stored), candidate):
            return index
    return None


def hashes_for(codes: Iterable[str]) -> list[str]:
    return [hash_recovery_code(code) for code in codes]
