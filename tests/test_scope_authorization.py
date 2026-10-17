import unittest
from datetime import datetime, timedelta, timezone

from app.recon_authorization import (
    AuthorizationRegistry,
    AuthorizationVerificationError,
    DohTxtResolver,
    DnsTxtResolver,
    SystemDnsTxtResolver,
)


class FakeResolver(DnsTxtResolver):
    def __init__(self, records: dict[str, tuple[str, ...]]) -> None:
        self.records = records

    def txt_records(self, name: str) -> tuple[str, ...]:
        return self.records.get(name, ())


class ScopeAuthorizationTests(unittest.TestCase):
    def test_production_resolvers_have_bounded_configuration(self) -> None:
        self.assertIsInstance(SystemDnsTxtResolver(), SystemDnsTxtResolver)
        with self.assertRaises(ValueError):
            DohTxtResolver("https://untrusted.example/dns-query")
        with self.assertRaises(ValueError):
            DohTxtResolver("https://dns.google/resolve", timeout_seconds=11)

    def test_challenge_verification_is_single_use_and_exact_domain(self) -> None:
        now = datetime(2026, 10, 17, tzinfo=timezone.utc)
        registry = AuthorizationRegistry(
            FakeResolver({}), challenge_lifetime=timedelta(minutes=10)
        )
        challenge = registry.create_challenge("Example.com.", "operator-1", now=now)
        resolver = registry.resolver
        resolver.records[challenge.record_name] = (challenge.token,)

        authorization = registry.verify_challenge(
            challenge.challenge_id,
            owner_id="operator-1",
            profile_ids=("service_inventory_v1",),
            now=now + timedelta(minutes=1),
        )
        self.assertEqual(authorization.target, "example.com")
        with self.assertRaises(AuthorizationVerificationError):
            registry.verify_challenge(
                challenge.challenge_id,
                owner_id="operator-1",
                profile_ids=("service_inventory_v1",),
                now=now + timedelta(minutes=2),
            )

    def test_malformed_domain_and_wrong_owner_are_rejected(self) -> None:
        registry = AuthorizationRegistry(FakeResolver({}))
        with self.assertRaises(AuthorizationVerificationError):
            registry.create_challenge("https://example.com/login", "operator-1")
        challenge = registry.create_challenge("example.com", "operator-1")
        with self.assertRaises(AuthorizationVerificationError):
            registry.verify_challenge(
                challenge.challenge_id,
                owner_id="operator-2",
                profile_ids=("service_inventory_v1",),
            )

    def test_expired_challenge_and_wrong_record_do_not_authorize(self) -> None:
        now = datetime(2026, 10, 17, tzinfo=timezone.utc)
        registry = AuthorizationRegistry(
            FakeResolver({}), challenge_lifetime=timedelta(minutes=1)
        )
        challenge = registry.create_challenge("example.com", "operator-1", now=now)
        with self.assertRaises(AuthorizationVerificationError):
            registry.verify_challenge(
                challenge.challenge_id,
                owner_id="operator-1",
                profile_ids=("service_inventory_v1",),
                now=now + timedelta(minutes=2),
            )
        challenge = registry.create_challenge("example.org", "operator-1", now=now)
        registry.resolver.records[challenge.record_name] = ("wrong-token",)
        with self.assertRaises(AuthorizationVerificationError):
            registry.verify_challenge(
                challenge.challenge_id,
                owner_id="operator-1",
                profile_ids=("service_inventory_v1",),
                now=now,
            )
