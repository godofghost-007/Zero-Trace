"""TOTP helpers and at-rest protection for MFA secrets.

The implementation follows RFC 6238 (TOTP) and RFC 4226 (HOTP). It deliberately
keeps the dependency surface small: the HMAC/truncation logic uses the standard
library and the stored secret is encrypted with Fernet from ``cryptography``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from struct import pack
from urllib.parse import quote

from cryptography.fernet import Fernet, InvalidToken

TOTP_STEP_SECONDS = 30
TOTP_DIGITS = 6
TOTP_WINDOW = 1


class MfaError(ValueError):
    """Raised when an MFA secret or code is invalid."""


def generate_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _pad(value: str) -> str:
    return value + "=" * ((8 - len(value) % 8) % 8)


def _secret_bytes(secret: str) -> bytes:
    try:
        return base64.b32decode(_pad(secret.upper()), casefold=True)
    except Exception as error:
        raise MfaError("MFA secret is invalid.") from error


def totp(secret: str, *, at: int | None = None, step: int = TOTP_STEP_SECONDS) -> str:
    counter = int((time.time() if at is None else at) // step)
    digest = hmac.new(
        _secret_bytes(secret), pack(">Q", counter), hashlib.sha1
    ).digest()
    offset = digest[-1] & 0x0F
    value = (
        (digest[offset] & 0x7F) << 24
        | (digest[offset + 1] & 0xFF) << 16
        | (digest[offset + 2] & 0xFF) << 8
        | (digest[offset + 3] & 0xFF)
    )
    return str(value % (10**TOTP_DIGITS)).zfill(TOTP_DIGITS)


def verify_totp(
    secret: str,
    code: object,
    *,
    at: int | None = None,
    window: int = TOTP_WINDOW,
) -> bool:
    if not isinstance(code, str):
        return False
    normalized = code.replace(" ", "").strip()
    if len(normalized) != TOTP_DIGITS or not normalized.isdigit():
        return False
    now = int(time.time() if at is None else at)
    for offset in range(-window, window + 1):
        candidate = totp(secret, at=now + offset * TOTP_STEP_SECONDS)
        if hmac.compare_digest(candidate, normalized):
            return True
    return False


def provisioning_uri(secret: str, *, email: str, issuer: str = "ZeroTrace") -> str:
    label = quote(f"{issuer}:{email}", safe=":")
    return (
        f"otpauth://totp/{label}?secret={secret}"
        f"&issuer={quote(issuer, safe='')}"
        f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP_SECONDS}"
    )


def _fernet(key: str) -> Fernet:
    normalized = key.strip()
    if not normalized:
        raise MfaError("MFA encryption key is not configured.")
    try:
        return Fernet(normalized.encode("ascii"))
    except (ValueError, TypeError) as error:
        raise MfaError("MFA encryption key is invalid.") from error


def encrypt_secret(secret: str, key: str) -> str:
    return _fernet(key).encrypt(secret.encode("ascii")).decode("ascii")


def decrypt_secret(value: str, key: str) -> str:
    try:
        return _fernet(key).decrypt(value.encode("ascii")).decode("ascii")
    except InvalidToken as error:
        raise MfaError("MFA secret could not be decrypted.") from error


def generate_key() -> str:
    return Fernet.generate_key().decode("ascii")
