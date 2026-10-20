import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
from urllib.parse import urlsplit

import psycopg

from .health import HealthReport
from .logging_config import configure_logging
from .security import security_headers
from .settings import Settings


class HealthHandler(BaseHTTPRequestHandler):
    database_url = ""

    def do_GET(self) -> None:
        request_path = urlsplit(self.path).path

        if request_path == "/health":
            report = HealthReport.liveness()
            self._respond(report)
            return
        if request_path == "/ready":
            self._respond(self._readiness())
            return
        self.send_error(404, "Not found")

    def _respond(self, report: HealthReport) -> None:
        body = json.dumps({"status": report.status, "checks": dict(report.checks)}).encode()
        self.send_response(200 if report.status == "healthy" else 503)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def end_headers(self) -> None:
        for name, value in security_headers().items():
            self.send_header(name, value)
        super().end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return

    @classmethod
    def _readiness(cls) -> HealthReport:
        if not cls.database_url:
            return HealthReport(status="degraded", checks={"postgres": "unknown"})
        try:
            with psycopg.connect(cls.database_url, connect_timeout=2) as connection:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    cursor.fetchone()
        except psycopg.Error:
            return HealthReport(status="degraded", checks={"postgres": "unavailable"})
        return HealthReport(status="healthy", checks={"postgres": "available"})


def main() -> None:
    settings = Settings.from_env()
    configure_logging(settings.log_level)
    HealthHandler.database_url = settings.database_url
    host = os.environ.get("ZEROTRACE_HOST", "127.0.0.1")
    port = int(os.environ.get("ZEROTRACE_PORT", "8765"))
    HTTPServer((host, port), HealthHandler).serve_forever()


if __name__ == "__main__":
    main()
