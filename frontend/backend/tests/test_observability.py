import logging

import pytest
from cryptography.fernet import Fernet
from flask import Flask

from backend import create_app, validate_runtime_config
from backend.observability import JsonFormatter


def _app(tmp_path, **overrides):
    data_dir = tmp_path / "data"
    config = {
        "TESTING": True,
        "DATA_DIR": data_dir,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{data_dir / 'test.db'}",
        "AUDIT_DB_PATH": data_dir / "guard-audit.sqlite",
        "FRONTEND_DIST": tmp_path / "no-frontend",
        "REDIS_URL": "",
        "AUTO_CREATE_SCHEMA": True,
        "DEMO_MODE": True,
        "AUTH_REQUIRED": False,
        "METRICS_ENABLED": True,
        "METRICS_TOKEN": "metrics-secret",
    }
    config.update(overrides)
    return create_app(config)


def test_request_and_trace_ids_are_returned(tmp_path):
    app = _app(tmp_path)
    client = app.test_client()
    trace_id = "a" * 32
    span_id = "b" * 16
    response = client.get(
        "/api/v1/health",
        headers={
            "X-Request-ID": "request-123",
            "traceparent": f"00-{trace_id}-{span_id}-01",
        },
    )
    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == "request-123"
    assert response.headers["X-Trace-ID"] == trace_id


def test_invalid_request_id_is_replaced(tmp_path):
    app = _app(tmp_path)
    client = app.test_client()
    response = client.get(
        "/api/v1/health", headers={"X-Request-ID": "bad id with spaces"}
    )
    assert response.headers["X-Request-ID"] != "bad id with spaces"
    assert len(response.headers["X-Request-ID"]) >= 32


def test_metrics_require_the_configured_token(tmp_path):
    app = _app(tmp_path)
    client = app.test_client()
    assert client.get("/api/v1/metrics").status_code == 401
    response = client.get(
        "/api/v1/metrics",
        headers={"Authorization": "Bearer metrics-secret"},
    )
    assert response.status_code == 200
    assert "zerotrace_http_requests_total" in response.get_data(as_text=True)


def test_metrics_are_disabled_by_default(tmp_path):
    app = _app(tmp_path, METRICS_ENABLED=False)
    client = app.test_client()
    response = client.get(
        "/api/v1/metrics",
        headers={"Authorization": "Bearer metrics-secret"},
    )
    assert response.status_code == 404


def test_production_metrics_require_a_token():
    app = Flask(__name__)
    app.config.update({
        "ENVIRONMENT": "production",
        "SECRET_KEY": "x" * 64,
        "SQLALCHEMY_DATABASE_URI": "postgresql://user:pass@db.example/zt",
        "AUTO_CREATE_SCHEMA": False,
        "DEMO_MODE": False,
        "AUTH_REQUIRED": True,
        "AUTH_COOKIE_SECURE": True,
        "AUTH_MFA_ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "METRICS_ENABLED": True,
        "METRICS_TOKEN": "",
    })
    with pytest.raises(RuntimeError, match="ZEROTRACE_METRICS_TOKEN"):
        validate_runtime_config(app)


def test_json_formatter_includes_request_correlation():
    record = logging.LogRecord(
        "zerotrace.test",
        logging.INFO,
        __file__,
        1,
        "request_completed",
        (),
        None,
    )
    record.request_id = "req-1"
    record.trace_id = "trace-1"
    record.status = 200
    rendered = JsonFormatter().format(record)
    assert '"request_id":"req-1"' in rendered
    assert '"trace_id":"trace-1"' in rendered
    assert '"status":200' in rendered
