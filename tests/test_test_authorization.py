import os
from datetime import datetime, timezone
import unittest
from unittest.mock import patch

from app.security import AuthorizationError, Principal
from app.test_authorization import (
    TEST_AUTHORIZATION_CODE,
    TestOnlyAuthorizationRegistry,
)


class TestOnlyAuthorizationTests(unittest.TestCase):
    def test_admin_can_authorize_synthetic_target_with_default_code(self) -> None:
        registry = TestOnlyAuthorizationRegistry(environment="test")

        authorization = registry.authorize(
            Principal("admin-1", "admin"),
            code=TEST_AUTHORIZATION_CODE,
            target="lab.example.test.",
            profile_id="synthetic_inventory_v1",
            now=datetime(2026, 10, 17, tzinfo=timezone.utc),
        )

        self.assertEqual(authorization.target, "lab.example.test")
        self.assertEqual(authorization.reason, "synthetic test authorization")

    def test_production_environment_cannot_enable_test_authorization(self) -> None:
        with self.assertRaises(ValueError):
            TestOnlyAuthorizationRegistry(environment="production")

    def test_non_admin_and_public_targets_are_rejected(self) -> None:
        registry = TestOnlyAuthorizationRegistry(environment="development")
        with self.assertRaises(AuthorizationError):
            registry.authorize(
                Principal("operator-1", "operator"),
                code=TEST_AUTHORIZATION_CODE,
                target="lab.example.test",
                profile_id="synthetic_inventory_v1",
            )
        with self.assertRaises(AuthorizationError):
            registry.authorize(
                Principal("admin-1", "admin"),
                code=TEST_AUTHORIZATION_CODE,
                target="example.com",
                profile_id="service_inventory_v1",
            )
        with self.assertRaises(AuthorizationError):
            registry.authorize(
                Principal("admin-1", "admin"),
                code=TEST_AUTHORIZATION_CODE,
                target="lab.example.test",
                profile_id="unapproved_profile",
            )

    def test_code_can_be_overridden_by_environment_without_being_logged(self) -> None:
        with patch.dict(os.environ, {"ZEROTRACE_TEST_AUTH_CODE": "local-only-code"}):
            registry = TestOnlyAuthorizationRegistry(environment="test")
        with self.assertRaises(AuthorizationError):
            registry.authorize(
                Principal("admin-1", "admin"),
                code=TEST_AUTHORIZATION_CODE,
                target="lab.example.test",
                profile_id="synthetic_inventory_v1",
            )
