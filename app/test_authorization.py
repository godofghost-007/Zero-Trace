from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import os
import re
from secrets import compare_digest

from .recon import PROFILES
from .security import AuthorizationError, Principal, require_role


TEST_AUTHORIZATION_CODE = "ZEROTRACE-TEST-ONLY"
_TEST_ENVIRONMENTS = frozenset({"test", "development"})
_LOCAL_HOSTS = frozenset({"localhost", "host.docker.internal"})
_TEST_LABEL = re.compile(r"^[a-z0-9-]+$")


@dataclass(frozen=True)
class TestAuthorization:
    target: str
    profile_id: str
    expires_at: datetime
    reason: str


class TestOnlyAuthorizationRegistry:
    """Explicit synthetic authorization for demonstrations and disposable labs."""

    def __init__(
        self,
        *,
        environment: str | None = None,
        code: str | None = None,
        lifetime: timedelta = timedelta(minutes=10),
    ) -> None:
        self.environment = environment or os.environ.get("ZEROTRACE_ENV", "")
        self.code = code or os.environ.get(
            "ZEROTRACE_TEST_AUTH_CODE", TEST_AUTHORIZATION_CODE
        )
        if self.environment not in _TEST_ENVIRONMENTS:
            raise ValueError("test authorization is disabled outside test environments")
        if not 1 <= lifetime.total_seconds() <= 15 * 60:
            raise ValueError("test authorization lifetime is outside the allowed range")
        self.lifetime = lifetime

    def authorize(
        self,
        principal: Principal,
        *,
        code: str,
        target: str,
        profile_id: str,
        now: datetime | None = None,
    ) -> TestAuthorization:
        require_role(principal, "admin")
        if not compare_digest(code, self.code):
            raise AuthorizationError("test authorization denied", 403)
        if profile_id not in PROFILES:
            raise AuthorizationError("test authorization denied", 403)
        normalized = _normalize_test_target(target)
        timestamp = _utc(now)
        return TestAuthorization(
            normalized,
            profile_id,
            timestamp + self.lifetime,
            "synthetic test authorization",
        )


def _normalize_test_target(value: str) -> str:
    candidate = value.strip().lower().rstrip(".")
    if (
        not candidate
        or "/" in candidate
        or "?" in candidate
        or "#" in candidate
        or ":" in candidate
        or "@" in candidate
    ):
        raise AuthorizationError("test authorization denied", 403)
    if candidate in _LOCAL_HOSTS:
        return candidate
    labels = candidate.split(".")
    if len(labels) < 2 or labels[-1] != "test":
        raise AuthorizationError("test authorization denied", 403)
    if any(not label or not _TEST_LABEL.fullmatch(label) for label in labels):
        raise AuthorizationError("test authorization denied", 403)
    return candidate


def _utc(value: datetime | None) -> datetime:
    timestamp = value or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        raise ValueError("timestamp must include timezone information")
    return timestamp.astimezone(timezone.utc)
