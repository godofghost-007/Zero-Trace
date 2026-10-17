from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import secrets
from typing import Protocol
import re
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener


class AuthorizationVerificationError(ValueError):
    """Raised when target authorization cannot be verified."""


class DnsTxtResolver(Protocol):
    def txt_records(self, name: str) -> tuple[str, ...]:
        ...


class SystemDnsTxtResolver:
    def txt_records(self, name: str) -> tuple[str, ...]:
        try:
            import dns.resolver

            answers = dns.resolver.resolve(name, "TXT", raise_on_no_answer=False)
            return tuple(
                b"".join(part if isinstance(part, bytes) else part.encode("utf-8") for part in answer.strings)
                .decode("utf-8", errors="strict")
                for answer in answers
            )
        except Exception as error:
            raise AuthorizationVerificationError(
                "authorization could not be verified"
            ) from error


class DohTxtResolver:
    def __init__(self, endpoint: str, *, timeout_seconds: int = 5) -> None:
        if endpoint not in {
            "https://cloudflare-dns.com/dns-query",
            "https://dns.google/resolve",
        }:
            raise ValueError("DoH endpoint is not allowlisted")
        if not 1 <= timeout_seconds <= 10:
            raise ValueError("DoH timeout is outside the allowed range")
        self.endpoint = endpoint
        self.timeout_seconds = timeout_seconds
        self._opener = build_opener(_NoRedirectHandler)

    def txt_records(self, name: str) -> tuple[str, ...]:
        query = urlencode({"name": name, "type": "TXT"})
        request = Request(
            f"{self.endpoint}?{query}",
            headers={"Accept": "application/dns-json"},
            method="GET",
        )
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                if response.status != 200:
                    raise AuthorizationVerificationError(
                        "authorization could not be verified"
                    )
                payload = json.loads(response.read(64 * 1024))
            answers = payload.get("Answer", [])
            return tuple(
                _decode_dns_json_txt(answer["data"])
                for answer in answers
                if answer.get("type") == 16 and isinstance(answer.get("data"), str)
            )
        except AuthorizationVerificationError:
            raise
        except Exception as error:
            raise AuthorizationVerificationError(
                "authorization could not be verified"
            ) from error


@dataclass(frozen=True)
class AuthorizationChallenge:
    challenge_id: str
    domain: str
    owner_id: str
    token: str
    record_name: str
    expires_at: datetime


@dataclass(frozen=True)
class TargetAuthorization:
    authorization_id: str
    target: str
    owner_id: str
    profile_ids: tuple[str, ...]
    environment: str
    verified_at: datetime
    expires_at: datetime


class AuthorizationRegistry:
    def __init__(
        self,
        resolver: DnsTxtResolver,
        *,
        challenge_lifetime: timedelta = timedelta(minutes=15),
    ) -> None:
        if not timedelta(minutes=1) <= challenge_lifetime <= timedelta(hours=1):
            raise ValueError("challenge lifetime is outside the allowed range")
        self.resolver = resolver
        self.challenge_lifetime = challenge_lifetime
        self._challenges: dict[str, AuthorizationChallenge] = {}
        self._used: set[str] = set()
        self._authorizations: dict[str, TargetAuthorization] = {}

    def create_challenge(
        self, domain: str, owner_id: str, *, now: datetime | None = None
    ) -> AuthorizationChallenge:
        normalized = _normalize_domain(domain)
        if not owner_id or len(owner_id) > 255:
            raise AuthorizationVerificationError("authorization could not be created")
        timestamp = _utc(now)
        token = secrets.token_urlsafe(32)
        challenge = AuthorizationChallenge(
            challenge_id=secrets.token_urlsafe(18),
            domain=normalized,
            owner_id=owner_id,
            token=token,
            record_name=f"_zerotrace-challenge.{normalized}",
            expires_at=timestamp + self.challenge_lifetime,
        )
        self._challenges[challenge.challenge_id] = challenge
        return challenge

    def verify_challenge(
        self,
        challenge_id: str,
        *,
        owner_id: str,
        profile_ids: tuple[str, ...],
        now: datetime | None = None,
        authorization_lifetime: timedelta = timedelta(hours=1),
    ) -> TargetAuthorization:
        challenge = self._challenges.get(challenge_id)
        timestamp = _utc(now)
        if (
            challenge is None
            or challenge_id in self._used
            or challenge.owner_id != owner_id
            or timestamp >= challenge.expires_at
            or not 1 <= len(profile_ids) <= 4
            or not timedelta(minutes=1) <= authorization_lifetime <= timedelta(days=7)
        ):
            raise AuthorizationVerificationError("authorization could not be verified")
        try:
            records = self.resolver.txt_records(challenge.record_name)
        except Exception as error:
            raise AuthorizationVerificationError(
                "authorization could not be verified"
            ) from error
        if challenge.token not in records:
            raise AuthorizationVerificationError("authorization could not be verified")
        self._used.add(challenge_id)
        authorization = TargetAuthorization(
            authorization_id=secrets.token_urlsafe(18),
            target=challenge.domain,
            owner_id=owner_id,
            profile_ids=profile_ids,
            environment="isolated_lab",
            verified_at=timestamp,
            expires_at=timestamp + authorization_lifetime,
        )
        self._authorizations[authorization.authorization_id] = authorization
        return authorization

    def authorize(
        self,
        authorization_id: str,
        *,
        owner_id: str,
        target: str,
        profile_id: str,
        now: datetime | None = None,
    ) -> TargetAuthorization:
        authorization = self._authorizations.get(authorization_id)
        if (
            authorization is None
            or authorization.owner_id != owner_id
            or authorization.target != _normalize_domain(target)
            or profile_id not in authorization.profile_ids
            or _utc(now) >= authorization.expires_at
        ):
            raise AuthorizationVerificationError("authorization denied")
        return authorization


def _normalize_domain(value: str) -> str:
    if not isinstance(value, str) or len(value) > 253:
        raise AuthorizationVerificationError("authorization could not be created")
    candidate = value.strip().rstrip(".").lower()
    if (
        not candidate
        or "/" in candidate
        or "?" in candidate
        or "#" in candidate
        or "@" in candidate
        or ":" in candidate
        or any(not re.fullmatch(r"[a-z0-9-]+", label) for label in candidate.split("."))
        or any(label.startswith("-") or label.endswith("-") for label in candidate.split("."))
    ):
        raise AuthorizationVerificationError("authorization could not be created")
    try:
        ip_parts = candidate.split(".")
        if len(ip_parts) == 4 and all(part.isdigit() for part in ip_parts):
            raise AuthorizationVerificationError("authorization could not be created")
    except AttributeError as error:
        raise AuthorizationVerificationError("authorization could not be created") from error
    return candidate


def _utc(value: datetime | None) -> datetime:
    timestamp = value or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        raise AuthorizationVerificationError("authorization time must include timezone")
    return timestamp.astimezone(timezone.utc)


def _decode_dns_json_txt(value: str) -> str:
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    return value.replace('\\"', '"')


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, msg, headers, newurl):
        raise AuthorizationVerificationError("authorization could not be verified")
