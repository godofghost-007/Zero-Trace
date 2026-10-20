import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.security import (
    AuthConfig,
    AuthorizationError,
    Principal,
    build_session_cookie,
    csrf_token,
    enforce_request_size,
    hash_password,
    open_private_audit_file,
    require_role,
    security_headers,
    verify_api_key,
    verify_csrf_token,
    verify_password,
)


class AuthenticationTests(unittest.TestCase):
    def test_password_hash_is_salted_and_verifiable(self) -> None:
        password_hash = hash_password("correct horse battery staple")

        self.assertNotEqual(password_hash, "correct horse battery staple")
        self.assertTrue(verify_password("correct horse battery staple", password_hash))
        self.assertFalse(verify_password("wrong password", password_hash))

    def test_api_key_verification_uses_secret_digest(self) -> None:
        with patch.dict(
            os.environ,
            {
                "ZEROTRACE_AUTH_SECRET": "a" * 32,
                "ZEROTRACE_SESSION_SECRET": "s" * 32,
            },
            clear=True,
        ):
            config = AuthConfig.from_env()

        api_key = "ztk_demo_secret_value"
        digest = config.api_key_digest(api_key)

        self.assertTrue(verify_api_key(api_key, digest, config))
        self.assertFalse(verify_api_key("ztk_wrong", digest, config))
        self.assertNotIn(api_key, digest)

    def test_weak_auth_secret_is_rejected(self) -> None:
        with patch.dict(os.environ, {"ZEROTRACE_AUTH_SECRET": "short"}, clear=True):
            with self.assertRaises(ValueError):
                AuthConfig.from_env()


class AuthorizationTests(unittest.TestCase):
    def test_missing_principal_is_unauthenticated(self) -> None:
        with self.assertRaises(AuthorizationError) as context:
            require_role(None, "viewer")

        self.assertEqual(context.exception.status_code, 401)

    def test_viewer_cannot_perform_operator_action(self) -> None:
        with self.assertRaises(AuthorizationError) as context:
            require_role(Principal("user-1", "viewer"), "operator")

        self.assertEqual(context.exception.status_code, 403)

    def test_admin_can_perform_operator_action(self) -> None:
        require_role(Principal("admin-1", "admin"), "operator")


class BoundarySecurityTests(unittest.TestCase):
    def test_csrf_token_is_bound_to_session_and_secret(self) -> None:
        secret = b"s" * 32
        token = csrf_token("session-1", secret)

        self.assertTrue(verify_csrf_token("session-1", token, secret))
        self.assertFalse(verify_csrf_token("session-2", token, secret))
        self.assertFalse(verify_csrf_token("session-1", token, b"x" * 32))

    def test_request_size_is_rejected_before_body_is_read(self) -> None:
        body = io.BytesIO(b"oversized")

        with self.assertRaises(ValueError):
            enforce_request_size(body, content_length=9, maximum=8)

        self.assertEqual(body.tell(), 0)

    def test_session_cookie_is_secure_and_bounded(self) -> None:
        cookie = build_session_cookie("opaque-session-token")

        self.assertIn("HttpOnly", cookie)
        self.assertIn("Secure", cookie)
        self.assertIn("SameSite=Lax", cookie)
        self.assertIn("Max-Age=28800", cookie)

    def test_security_headers_disable_browser_sniffing_and_framing(self) -> None:
        headers = security_headers()

        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["Content-Security-Policy"], "default-src 'self'")

    def test_audit_file_is_owner_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.log"
            with open_private_audit_file(path) as audit_file:
                audit_file.write(b"event\n")

            self.assertEqual(path.read_bytes(), b"event\n")
            if os.name != "nt":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            else:
                self.assertTrue(path.is_file())
