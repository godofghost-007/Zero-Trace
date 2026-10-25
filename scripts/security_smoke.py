"""Security smoke checks for the BFF configuration and response surface.

These are configuration and header checks, not a penetration test. They are
meant to catch regressions in the boundaries that are easy to break: metrics
authorization, unauthenticated API access, loopback-only engine URLs, and
security headers.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile

from cryptography.fernet import Fernet

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FRONTEND = PROJECT_ROOT / "frontend"
if str(FRONTEND) not in sys.path:
    sys.path.insert(0, str(FRONTEND))


def _check(name: str, passed: bool, detail: str = "") -> dict[str, object]:
    return {"check": name, "passed": bool(passed), "detail": detail}


def main() -> int:
    from backend import create_app
    from backend.extensions import db
    from backend.services.engine import validate_base_url, validate_api_key

    metrics_token = "security-smoke-metrics-token"
    temp = tempfile.TemporaryDirectory(
        prefix="zerotrace-security-", ignore_cleanup_errors=True
    )
    app = create_app(
        {
            "ENVIRONMENT": "development",
            "SECRET_KEY": "security-smoke-secret-key-at-least-32-bytes",
            "AUTH_REQUIRED": True,
            "DEMO_MODE": True,
            "AUTO_CREATE_SCHEMA": True,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{Path(temp.name) / 'security.db'}",
            "DATA_DIR": Path(temp.name),
            "AUDIT_DB_PATH": Path(temp.name) / "audit.sqlite",
            "FRONTEND_DIST": Path(temp.name) / "dist",
            "METRICS_ENABLED": True,
            "METRICS_TOKEN": metrics_token,
            "AUTH_MFA_ENCRYPTION_KEY": Fernet.generate_key().decode(),
            "LOG_LEVEL": "ERROR",
        }
    )
    client = app.test_client()
    checks: list[dict[str, object]] = []
    try:
        health = client.get("/api/v1/health")
        checks.append(_check("health_is_public", health.status_code == 200))
        for header in (
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
            "Content-Security-Policy",
            "X-Request-ID",
        ):
            checks.append(
                _check(
                    f"header_{header.lower().replace('-', '_')}",
                    header in health.headers,
                )
            )
        checks.append(
            _check(
                "api_cache_control_no_store",
                health.headers.get("Cache-Control") == "no-store",
            )
        )

        engine_status = client.get("/api/v1/engine/status")
        checks.append(
            _check(
                "engine_status_requires_auth",
                engine_status.status_code == 401,
                str(engine_status.status_code),
            )
        )

        guard_chat = client.post(
            "/api/v1/guard/chat",
            json={"messages": [{"role": "user", "content": "hello"}]},
        )
        checks.append(
            _check(
                "guard_chat_requires_auth",
                guard_chat.status_code == 401,
                str(guard_chat.status_code),
            )
        )

        metrics_denied = client.get("/api/v1/metrics")
        checks.append(
            _check(
                "metrics_requires_token",
                metrics_denied.status_code == 401,
                str(metrics_denied.status_code),
            )
        )
        metrics_allowed = client.get(
            "/api/v1/metrics",
            headers={"Authorization": f"Bearer {metrics_token}"},
        )
        checks.append(
            _check(
                "metrics_accepts_token",
                metrics_allowed.status_code == 200
                and "text/plain" in metrics_allowed.content_type,
                str(metrics_allowed.status_code),
            )
        )

        engine_metrics_denied = client.get("/api/v1/engine/metrics")
        checks.append(
            _check(
                "engine_metrics_requires_token",
                engine_metrics_denied.status_code == 401,
                str(engine_metrics_denied.status_code),
            )
        )

        checks.append(
            _check(
                "engine_url_rejects_public_host",
                _raises(
                    lambda: validate_base_url("http://example.com:8765"),
                    ValueError,
                ),
            )
        )
        checks.append(
            _check(
                "engine_url_accepts_loopback",
                validate_base_url("http://127.0.0.1:8765")
                == "http://127.0.0.1:8765",
            )
        )
        checks.append(
            _check(
                "engine_key_rejects_short_value",
                _raises(lambda: validate_api_key("short"), ValueError),
            )
        )

        not_found = client.get("/api/v1/does-not-exist")
        body = not_found.get_json(silent=True) or {}
        checks.append(
            _check(
                "error_envelope_has_no_traceback",
                not_found.status_code in {401, 404}
                and "traceback" not in str(body).lower(),
                str(not_found.status_code),
            )
        )
    finally:
        with app.app_context():
            db.session.remove()
            db.engine.dispose()
        temp.cleanup()

    report = {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "passed": all(item["passed"] for item in checks),
        "limitations": [
            "Configuration and header checks only, not a penetration test.",
            "No live TLS proxy or Caddy assertion was exercised.",
            "No authenticated role/CSRF workflow was exercised.",
        ],
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    output = PROJECT_ROOT / "tasks" / "evidence" / "security-smoke.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0 if report["passed"] else 1


def _raises(call, error_type) -> bool:
    try:
        call()
    except error_type:
        return True
    except Exception:
        return False
    return False


if __name__ == "__main__":
    raise SystemExit(main())
