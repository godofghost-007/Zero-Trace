from unittest.mock import Mock, patch

import pytest
from cryptography.fernet import Fernet
from flask import Flask

from backend import create_app, validate_runtime_config
from backend.services.guard_proxy import (
    GuardProxyClient,
    GuardProxyError,
    GuardProxySettings,
    validate_guard_base_url,
)


@pytest.fixture()
def app(tmp_path):
    data_dir = tmp_path / "data"
    application = create_app({
        "TESTING": True,
        "DATA_DIR": data_dir,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{data_dir / 'test.db'}",
        "AUDIT_DB_PATH": data_dir / "guard-audit.sqlite",
        "FRONTEND_DIST": tmp_path / "no-frontend",
        "REDIS_URL": "",
        "AUTO_CREATE_SCHEMA": True,
        "DEMO_MODE": True,
        "AUTH_REQUIRED": False,
    })
    yield application
    with application.app_context():
        from backend.extensions import db

        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def test_guard_route_is_disabled_by_default(client):
    response = client.post(
        "/api/v1/guard/chat",
        json={"messages": [{"role": "user", "content": "hello"}]},
    )
    assert response.status_code == 503
    assert response.json["error"]["code"] == "guard_disabled"


def test_guard_route_forwards_only_allowed_fields(client, monkeypatch):
    calls = []

    class FakeClient:
        def chat(self, payload):
            calls.append(payload)
            return (
                {"choices": [{"message": {"role": "assistant", "content": "ok"}}]},
                {"X-ZeroTrace-PII-Redacted": "true"},
            )

    monkeypatch.setattr("backend.guard_api._client", lambda: FakeClient())
    response = client.post(
        "/api/v1/guard/chat",
        json={
            "model": "test-model",
            "messages": [{"role": "user", "content": "hello"}],
            "temperature": 0.2,
            "top_p": 0.9,
            "max_tokens": 100,
            "stream": False,
        },
    )
    assert response.status_code == 200
    assert response.headers["X-ZeroTrace-PII-Redacted"] == "true"
    assert calls == [{
        "model": "test-model",
        "messages": [{"role": "user", "content": "hello"}],
        "temperature": 0.2,
        "top_p": 0.9,
        "max_tokens": 100,
    }]


def test_guard_route_allows_same_host_origin(client, monkeypatch):
    class FakeClient:
        def chat(self, payload):
            return {"choices": []}, {}

    monkeypatch.setattr("backend.guard_api._client", lambda: FakeClient())
    response = client.post(
        "/api/v1/guard/chat",
        json={"messages": [{"role": "user", "content": "hello"}]},
        headers={"Origin": "http://localhost:3000"},
    )
    assert response.status_code == 200


def test_guard_route_rejects_foreign_origin(client):
    response = client.post(
        "/api/v1/guard/chat",
        json={"messages": [{"role": "user", "content": "hello"}]},
        headers={"Origin": "https://example.com"},
    )
    assert response.status_code == 403
    assert response.json["error"]["code"] == "origin_denied"


@pytest.mark.parametrize(
    "payload",
    [
        {"messages": [{"role": "user", "content": "hello"}], "stream": True},
        {"messages": []},
        {"messages": [{"role": "tool", "content": "hello"}]},
        {"messages": [{"role": "user", "content": ""}]},
        {"messages": [{"role": "user", "content": "hello"}], "upstream": "https://evil.example"},
        {"messages": [{"role": "user", "content": "hello"}], "temperature": 3},
        {"messages": [{"role": "user", "content": "hello"}], "max_tokens": 0},
    ],
)
def test_guard_route_rejects_unsafe_or_invalid_payloads(client, payload):
    response = client.post("/api/v1/guard/chat", json=payload)
    assert response.status_code == 400
    assert response.json["error"]["code"] == "invalid_request"


def test_guard_base_url_must_be_loopback():
    assert (
        validate_guard_base_url("http://127.0.0.1:8766/")
        == "http://127.0.0.1:8766"
    )
    for value in (
        "http://example.com:8766",
        "http://127.0.0.1:8766/v1",
        "http://user:pass@127.0.0.1:8766",
        "http://127.0.0.1:8766?x=1",
        "ftp://127.0.0.1:8766",
    ):
        with pytest.raises(ValueError):
            validate_guard_base_url(value)


def test_production_guard_config_requires_a_loopback_url():
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
        "GUARD_PROXY_ENABLED": True,
        "GUARD_PROXY_URL": "http://example.com:8766",
        "GUARD_BFF_API_KEY": "a" * 32,
    })
    with pytest.raises(RuntimeError, match="loopback"):
        validate_runtime_config(app)


def test_guard_client_sends_the_bff_key_and_propagates_redaction():
    response = Mock(
        status_code=200,
        content=b'{"choices": []}',
        headers={"X-ZeroTrace-PII-Redacted": "true"},
    )
    response.json.return_value = {"choices": []}
    client = GuardProxyClient(
        GuardProxySettings(
            enabled=True,
            base_url="http://127.0.0.1:8766",
            api_key="test-guard-key-123456",
        )
    )
    with patch(
        "backend.services.guard_proxy.requests.post", return_value=response
    ) as post:
        result, headers = client.chat({"messages": []})
    assert result == {"choices": []}
    assert headers == {"X-ZeroTrace-PII-Redacted": "true"}
    assert post.call_args.kwargs["headers"]["X-API-Key"] == (
        "test-guard-key-123456"
    )
    assert post.call_args.kwargs["allow_redirects"] is False


def test_guard_client_rejects_redirects():
    response = Mock(status_code=302, content=b"", headers={})
    client = GuardProxyClient(
        GuardProxySettings(
            enabled=True,
            base_url="http://127.0.0.1:8766",
            api_key="test-guard-key-123456",
        )
    )
    with patch(
        "backend.services.guard_proxy.requests.post", return_value=response
    ), pytest.raises(GuardProxyError, match="redirect"):
        client.chat({"messages": []})

