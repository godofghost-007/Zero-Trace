import pytest

from backend import create_app
from backend.services.engine import EngineError


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
