from io import BytesIO
from urllib.error import HTTPError

import pytest

from backend import create_app
from backend.services.engine import EngineClient, EngineError


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
        "METRICS_ENABLED": True,
        "METRICS_TOKEN": "test-metrics-token",
    })
    yield application
    with application.app_context():
        from backend.extensions import db
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def test_engine_settings_hide_the_api_key_and_reject_non_loopback(client, app):
    current = client.get("/api/v1/settings/engine")
    assert current.status_code == 200
    assert current.json["mode"] == "demo"
    assert current.json["apiKeyConfigured"] is True
    assert "apiKey" not in current.json

    rejected = client.put(
        "/api/v1/settings/engine",
        json={"baseUrl": "http://example.com:8765", "mode": "live"},
    )
    assert rejected.status_code == 400
    assert "loopback" in rejected.json["error"]["message"].lower()

    saved = client.put(
        "/api/v1/settings/engine",
        json={"baseUrl": "http://127.0.0.1:9999", "mode": "live"},
    )
    assert saved.status_code == 200
    assert saved.json["baseUrl"] == "http://127.0.0.1:9999"
    assert saved.json["mode"] == "live"
    assert "apiKey" not in saved.json

    stored = app.config["DATA_DIR"] / "engine-settings.json"
    assert stored.exists()
    content = stored.read_text("utf-8")
    assert "sk-zerotrace" in content
    assert "apiKeyHint" not in content


def test_scope_and_scan_creation_require_explicit_authorization(client):
    scope = client.post(
        "/api/v1/engine/scopes",
        json={
            "scopeId": "scope-lab",
            "targets": ["lab.example.test"],
            "profiles": ["tls_metadata_v1"],
        },
    )
    assert scope.status_code == 400
    assert scope.json["error"]["code"] == "authorization_required"

    scan = client.post(
        "/api/v1/engine/scans",
        json={
            "scopeId": "scope-lab",
            "target": "lab.example.test",
            "profileId": "tls_metadata_v1",
        },
    )
    assert scan.status_code == 400
    assert scan.json["error"]["code"] == "authorization_required"


def test_engine_proxy_forwards_only_allowed_fields(client, monkeypatch):
    calls = []

    def fake_request(self, method, path, payload=None, *, timeout=10.0):
        calls.append((method, path, payload))
        return {"scanId": "scan-1", "state": "queued"}

    monkeypatch.setattr(
        "backend.engine_api.EngineClient.request", fake_request
    )
    response = client.post(
        "/api/v1/engine/scans",
        json={
            "authorized": True,
            "scopeId": "scope-lab",
            "target": "lab.example.test",
            "profileId": "tls_metadata_v1",
        },
    )
    assert response.status_code == 202
    assert response.json == {"scanId": "scan-1", "state": "queued"}
    assert calls == [(
        "POST",
        "/api/v1/recon/scans",
        {
            "scopeId": "scope-lab",
            "target": "lab.example.test",
            "profileId": "tls_metadata_v1",
        },
    )]


def test_engine_client_forwards_authenticated_identity(client, monkeypatch):
    captured = {}

    def fake_init(self, base_url, api_key, *, default_headers=None):
        captured.update(default_headers or {})
        self.base_url = base_url
        self.api_key = api_key
        self.default_headers = dict(default_headers or {})

    monkeypatch.setattr(EngineClient, "__init__", fake_init)
    monkeypatch.setattr(
        EngineClient,
        "request",
        lambda self, *args, **kwargs: {"state": "ready"},
    )
    response = client.get("/api/v1/engine/status")
    assert response.status_code == 200
    assert captured["X-ZeroTrace-Subject"] == "local-demo"
    assert captured["X-ZeroTrace-Role"] == "admin"
    assert captured["traceparent"].startswith("00-")


def test_engine_intel_ingest_only_allows_kev(client, monkeypatch):
    calls = []

    def fake_request(self, method, path, payload=None, **kwargs):
        calls.append((method, path, payload, kwargs))
        return {
            "ingestionId": "ing-1",
            "state": "completed",
            "factCount": 1748,
        }

    monkeypatch.setattr(
        "backend.engine_api.EngineClient.request", fake_request
    )

    rejected = client.post(
        "/api/v1/engine/intel/ingest", json={"source": "nvd"}
    )
    assert rejected.status_code == 400
    assert calls == []

    accepted = client.post(
        "/api/v1/engine/intel/ingest", json={"source": "kev"}
    )
    assert accepted.status_code == 202
    assert accepted.json["factCount"] == 1748
    assert calls[0][0:3] == (
        "POST",
        "/api/v1/intel/ingestions",
        {"source": "kev"},
    )
    assert calls[0][3]["extra_headers"]["Idempotency-Key"]


def test_engine_scans_forwards_the_persisted_scan_list(client, monkeypatch):
    calls = []

    def fake_request(self, method, path, payload=None, **kwargs):
        calls.append((method, path, payload))
        return {
            "items": [
                {
                    "scanId": "scan-1",
                    "scopeId": "scope-1",
                    "target": "lab.example.test",
                    "profileId": "synthetic_inventory_v1",
                    "state": "completed",
                }
            ]
        }

    monkeypatch.setattr(
        "backend.engine_api.EngineClient.request", fake_request
    )
    response = client.get("/api/v1/engine/scans")
    assert response.status_code == 200
    assert response.json["items"][0]["scanId"] == "scan-1"
    assert calls == [("GET", "/api/v1/recon/scans", None)]


def test_engine_readiness_forwards_the_engine_result(client, monkeypatch):
    calls = []

    def fake_request(self, method, path, payload=None, **kwargs):
        calls.append((method, path, payload))
        return {
            "score": None,
            "band": None,
            "coverage": 33.33,
            "unknownComponents": ["VUI", "AIET"],
            "components": [],
            "inputs": {},
            "readiness": "incomplete",
        }

    monkeypatch.setattr(
        "backend.engine_api.EngineClient.request", fake_request
    )
    response = client.get("/api/v1/engine/readiness")
    assert response.status_code == 200
    assert response.json["readiness"] == "incomplete"
    assert calls == [("GET", "/api/v1/engine/readiness", None)]


def test_engine_client_preserves_authorization_denials(monkeypatch):
    class ForbiddenOpener:
        def open(self, request, timeout):
            raise HTTPError(
                request.full_url,
                403,
                "Forbidden",
                {},
                BytesIO(b'{"error":{"message":"Authorization denied"}}'),
            )

    monkeypatch.setattr("backend.services.engine._OPENER", ForbiddenOpener())
    engine = EngineClient("http://127.0.0.1:8765", "sk-test")
    with pytest.raises(EngineError) as error:
        engine.request("POST", "/api/v1/recon/authorizations", {})
    assert error.value.status_code == 403
    assert "authorization denied" in str(error.value).lower()


def test_engine_test_reports_a_safe_failure(client, monkeypatch):
    def failing_request(self, method, path, payload=None, *, timeout=10.0):
        raise EngineError("Live engine is unreachable.", 502)

    monkeypatch.setattr(
        "backend.engine_api.EngineClient.request", failing_request
    )
    response = client.post("/api/v1/engine/test", json={})
    assert response.status_code == 200
    assert response.json["ok"] is False
    assert "unreachable" in response.json["message"].lower()


def test_engine_schedule_requires_acknowledgement_and_bounded_interval(client):
    missing = client.post(
        "/api/v1/engine/schedules",
        json={
            "scopeId": "scope-lab",
            "target": "lab.example.test",
            "profileId": "synthetic_inventory_v1",
            "intervalSeconds": 300,
        },
    )
    assert missing.status_code == 400
    assert missing.json["error"]["code"] == "authorization_required"

    too_short = client.post(
        "/api/v1/engine/schedules",
        json={
            "authorized": True,
            "scopeId": "scope-lab",
            "target": "lab.example.test",
            "profileId": "synthetic_inventory_v1",
            "intervalSeconds": 299,
        },
    )
    assert too_short.status_code == 400


def test_engine_schedule_forwards_only_allowed_fields(client, monkeypatch):
    calls = []

    def fake_request(self, method, path, payload=None, **kwargs):
        calls.append((method, path, payload))
        return {
            "scheduleId": "schedule-1",
            "target": "lab.example.test",
            "enabled": True,
        }

    monkeypatch.setattr(
        "backend.engine_api.EngineClient.request", fake_request
    )
    response = client.post(
        "/api/v1/engine/schedules",
        json={
            "authorized": True,
            "scopeId": "scope-lab",
            "target": "lab.example.test",
            "profileId": "synthetic_inventory_v1",
            "intervalSeconds": 600,
        },
    )
    assert response.status_code == 201
    assert response.json["scheduleId"] == "schedule-1"
    assert calls == [
        (
            "POST",
            "/api/v1/recon/schedules",
            {
                "scopeId": "scope-lab",
                "target": "lab.example.test",
                "profileId": "synthetic_inventory_v1",
                "intervalSeconds": 600,
            },
        )
    ]


def test_engine_schedule_list_run_and_disable(client, monkeypatch):
    calls = []

    def fake_request(self, method, path, payload=None, **kwargs):
        calls.append((method, path, payload))
        return {"items": [], "scheduleId": "schedule-1", "enabled": False}

    monkeypatch.setattr(
        "backend.engine_api.EngineClient.request", fake_request
    )
    assert client.get("/api/v1/engine/schedules").status_code == 200
    assert (
        client.post("/api/v1/engine/schedules/schedule-1/run").status_code
        == 200
    )
    assert (
        client.delete("/api/v1/engine/schedules/schedule-1").status_code
        == 200
    )
    assert calls == [
        ("GET", "/api/v1/recon/schedules", None),
        ("POST", "/api/v1/recon/schedules/schedule-1/run", None),
        ("DELETE", "/api/v1/recon/schedules/schedule-1", None),
    ]


def test_engine_metrics_requires_token_and_proxies_text(client, monkeypatch):
    def fake_metrics(self, *, timeout=5.0):
        return "zerotrace_test_total 1\n"

    monkeypatch.setattr(
        "backend.engine_api.EngineClient.metrics", fake_metrics
    )
    denied = client.get("/api/v1/engine/metrics")
    assert denied.status_code == 401
    allowed = client.get(
        "/api/v1/engine/metrics",
        headers={"Authorization": "Bearer test-metrics-token"},
    )
    assert allowed.status_code == 200
    assert allowed.mimetype == "text/plain"
    assert b"zerotrace_test_total 1" in allowed.data


def test_engine_endpoints_reject_non_json_and_foreign_origins(client):
    plain = client.post(
        "/api/v1/engine/scopes",
        data="scopeId=scope-lab",
        content_type="text/plain",
    )
    assert plain.status_code == 415

    foreign = client.post(
        "/api/v1/engine/scopes",
        json={"authorized": True},
        headers={"Origin": "https://example.com"},
    )
    assert foreign.status_code == 403
    assert foreign.json["error"]["code"] == "origin_denied"
