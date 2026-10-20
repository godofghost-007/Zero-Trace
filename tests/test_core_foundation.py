import os
import unittest
from unittest.mock import patch

from app.__main__ import HealthHandler, main
from app.errors import ConfigurationError
from app.health import HealthReport, dependency_status
from app.settings import Settings


class SettingsTests(unittest.TestCase):
    def test_missing_database_url_fails_with_named_configuration_error(self) -> None:
        with patch.dict(os.environ, {"ZEROTRACE_ENV": "test"}, clear=True):
            with self.assertRaisesRegex(ConfigurationError, "DATABASE_URL"):
                Settings.from_env()

    def test_settings_reads_required_values_without_exposing_secrets(self) -> None:
        with patch.dict(
            os.environ,
            {
                "ZEROTRACE_ENV": "test",
                "DATABASE_URL": "postgresql://user:secret@example.test/db",
            },
            clear=True,
        ):
            settings = Settings.from_env()

        self.assertEqual(settings.environment, "test")
        self.assertEqual(settings.database_url, "postgresql://user:secret@example.test/db")
        self.assertNotIn("secret", repr(settings))


class HealthTests(unittest.TestCase):
    def test_liveness_is_healthy_without_dependencies(self) -> None:
        report = HealthReport.liveness()

        self.assertEqual(report.status, "healthy")
        self.assertEqual(report.checks, {})

    def test_readiness_is_degraded_when_dependency_is_unavailable(self) -> None:
        report = dependency_status({"postgres": False})

        self.assertEqual(report.status, "degraded")
        self.assertEqual(report.checks, {"postgres": "unavailable"})

    def test_health_handler_accepts_query_strings(self) -> None:
        handler = HealthHandler.__new__(HealthHandler)
        handler.path = "/health?debug=true"
        handler._respond = lambda report: None
        handler.send_error = lambda code, message: (_ for _ in ()).throw(AssertionError("unexpected 404"))

        handler.do_GET()

    def test_readiness_uses_database_probe(self) -> None:
        with patch("app.__main__.psycopg.connect") as connect:
            connection = connect.return_value.__enter__.return_value
            cursor = connection.cursor.return_value.__enter__.return_value
            cursor.fetchone.return_value = (1,)
            HealthHandler.database_url = "postgres://example/test"
            report = HealthHandler._readiness()

        self.assertEqual(report.status, "healthy")
        self.assertEqual(report.checks, {"postgres": "available"})

    def test_main_uses_documented_default_port(self) -> None:
        with patch.dict(
            os.environ,
            {"ZEROTRACE_ENV": "test", "DATABASE_URL": "postgres://example/test"},
            clear=True,
        ):
            with patch("app.__main__.HTTPServer") as mock_http_server:
                main()

        mock_http_server.assert_called_once()
        self.assertEqual(mock_http_server.call_args.args[0], ("127.0.0.1", 8765))
        self.assertIs(mock_http_server.call_args.args[1], HealthHandler)
