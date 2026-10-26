import base64
import binascii
from dataclasses import dataclass
import hashlib
import hmac
import os
from pathlib import Path
from typing import BinaryIO

from .settings import env_or_file


PASSWORD_HASH_VERSION = "scrypt-v1"
MIN_SECRET_BYTES = 32
DEFAULT_MAX_REQUEST_BYTES = 1_048_576
ROLE_RANK = {"viewer": 1, "operator": 2, "admin": 3}


@dataclass(frozen=True)
class AuthConfig:
    auth_secret: bytes
    session_secret: bytes
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES

    @classmethod
    def from_env(cls) -> "AuthConfig":
        auth_secret = _required_secret("ZEROTRACE_AUTH_SECRET")
        session_secret = _required_secret("ZEROTRACE_SESSION_SECRET")
        raw_limit = os.environ.get(
            "ZEROTRACE_MAX_REQUEST_BYTES", str(DEFAULT_MAX_REQUEST_BYTES)
        )
        try:
            max_request_bytes = int(raw_limit)
        except ValueError as error:
            raise ValueError("ZEROTRACE_MAX_REQUEST_BYTES must be an integer") from error
        if not 0 < max_request_bytes <= 10 * DEFAULT_MAX_REQUEST_BYTES:
            raise ValueError("ZEROTRACE_MAX_REQUEST_BYTES is outside the allowed range")
        return cls(auth_secret, session_secret, max_request_bytes)

    def api_key_digest(self, api_key: str) -> str:
        return hmac.new(
            self.auth_secret, api_key.encode("utf-8"), hashlib.sha256
        ).hexdigest()


@dataclass(frozen=True)
class Principal:
    subject: str
    role: str


class AuthorizationError(Exception):
    def __init__(self, message: str, status_code: int) -> None:
        super().__init__(message)
        self.status_code = status_code


def hash_password(password: str) -> str:
    if not password or len(password) > 1024:
        raise ValueError("password must be between 1 and 1024 characters")
    salt = os.urandom(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    )
    return "$".join(
        (
            PASSWORD_HASH_VERSION,
            _encode(salt),
            _encode(digest),
        )
    )


def verify_password(password: str, encoded_hash: str) -> bool:
    try:
        version, encoded_salt, encoded_digest = encoded_hash.split("$")
        if version != PASSWORD_HASH_VERSION:
            return False
        salt = _decode(encoded_salt)
        expected = _decode(encoded_digest)
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=2**14,
            r=8,
            p=1,
            dklen=len(expected),
        )
    except (binascii.Error, TypeError, ValueError):
        return False
    return hmac.compare_digest(actual, expected)


def verify_api_key(api_key: str, expected_digest: str, config: AuthConfig) -> bool:
    if not api_key or len(api_key) > 512:
        return False
    actual_digest = config.api_key_digest(api_key)
    return hmac.compare_digest(actual_digest, expected_digest)


def require_role(principal: Principal | None, required_role: str) -> Principal:
    if principal is None:
        raise AuthorizationError("Authentication required", 401)
    if principal.role not in ROLE_RANK or required_role not in ROLE_RANK:
        raise AuthorizationError("Authorization denied", 403)
    if ROLE_RANK[principal.role] < ROLE_RANK[required_role]:
        raise AuthorizationError("Authorization denied", 403)
    return principal


def csrf_token(session_id: str, secret: bytes) -> str:
    if not session_id or len(secret) < MIN_SECRET_BYTES:
        raise ValueError("session ID and strong secret are required")
    return hmac.new(secret, session_id.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_csrf_token(session_id: str, token: str, secret: bytes) -> bool:
    if not token:
        return False
    try:
        expected = csrf_token(session_id, secret)
    except ValueError:
        return False
    return hmac.compare_digest(expected, token)


def enforce_request_size(
    body: BinaryIO, content_length: int | None, maximum: int
) -> None:
    if content_length is None:
        raise ValueError("Content-Length is required")
    if content_length < 0 or content_length > maximum:
        raise ValueError("request body exceeds the configured limit")
    if not 0 < maximum <= 10 * DEFAULT_MAX_REQUEST_BYTES:
        raise ValueError("request limit is outside the allowed range")


def build_session_cookie(session_token: str, max_age: int = 28_800) -> str:
    if not session_token or any(character in session_token for character in "\r\n;"):
        raise ValueError("session token contains invalid characters")
    if max_age <= 0:
        raise ValueError("session cookie lifetime must be positive")
    return (
        f"zt_session={session_token}; Max-Age={max_age}; Path=/; "
        "HttpOnly; Secure; SameSite=Lax"
    )


def open_private_audit_file(path: str | Path) -> BinaryIO:
    audit_path = Path(path)
    if audit_path.exists() and (audit_path.is_symlink() or not audit_path.is_file()):
        raise ValueError("audit path must be a regular non-symlink file")
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(audit_path, flags | no_follow, 0o600)
    try:
        os.chmod(audit_path, 0o600)
    except OSError:
        os.close(descriptor)
        raise
    return os.fdopen(descriptor, "ab", buffering=0)


def security_headers() -> dict[str, str]:
    return {
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "no-store",
    }


def _required_secret(name: str) -> bytes:
    value = env_or_file(name)
    secret = value.encode("utf-8")
    if len(secret) < MIN_SECRET_BYTES:
        raise ValueError(f"{name} must contain at least {MIN_SECRET_BYTES} bytes")
    return secret


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))
