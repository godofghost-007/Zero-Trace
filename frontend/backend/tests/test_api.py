import sqlite3

import pytest

from backend import create_app


@pytest.fixture()
def app(tmp_path):
    data_dir = tmp_path / "data"
    app = create_app({
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
    yield app
    with app.app_context():
        from backend.extensions import db
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def test_health_and_initial_state_are_served(client):
    health = client.get("/api/v1/health")
    assert health.status_code == 200
    assert health.json["service"] == "zerotrace-flask"
    state = client.get("/api/v1/demo/state").json
    assert state["stage"] == 0
    assert state["asset"] is None
    assert state["finding"] is None
    assert state["readiness"]["score"] is None
    assert state["readiness"]["aei"] is None
    assert state["backend"]["database"] == "sqlite"


def test_scenario_requires_order_and_persists_cross_engine_ids(client):
    guard_first = client.post("/api/v1/demo/steps/guard")
    assert guard_first.status_code == 409

    recon = client.post("/api/v1/demo/steps/recon")
    assert recon.status_code == 200
    assert recon.json["stage"] == 1
    assert recon.json["asset"]["id"] == "asset_zt_001"
    assert recon.json["readiness"]["score"] is None
    scan = client.get("/api/v1/recon/scans").json["items"][0]
    assert scan["partial"] is True
    assert scan["status"] == "completed_with_warnings"

    intel = client.post("/api/v1/demo/steps/intel")
    assert intel.status_code == 200
    assert intel.json["stage"] == 2
    assert intel.json["finding"]["id"] == "finding_zt_001"
    assert intel.json["readiness"]["score"] is None

    guard = client.post("/api/v1/demo/steps/guard")
    assert guard.status_code == 200
    assert guard.json["stage"] == 3
    assert guard.json["audit"][0]["assetId"] == "asset_zt_001"
    assert guard.json["audit"][0]["findingId"] == "finding_zt_001"
    assert guard.json["audit"][0]["eventId"] == "EVT-DEMO-1046"
    assert guard.json["readiness"]["score"] == 78
    assert guard.json["backend"]["audit"]["valid"] is True
    event_types = {item["type"] for item in guard.json["events"]}
    assert {"asset_created", "vuln_matched", "attack_blocked", "score_snapshot"} <= event_types
    assert all(item["status"] == "pending" for item in guard.json["events"])


def test_repeated_step_is_idempotent_and_reset_is_demo_only(client):
    first = client.post("/api/v1/demo/steps/recon").json
    second = client.post("/api/v1/demo/steps/recon").json
    assert second["stage"] == 1
    assert [item["id"] for item in second["events"]] == [item["id"] for item in first["events"]]

    reset = client.post("/api/v1/demo/reset")
    assert reset.status_code == 200
    assert reset.json["stage"] == 0
    assert reset.json["asset"] is None
    assert reset.json["events"] == []
    assert reset.json["audit"] == []


def test_audit_verification_detects_row_tampering(client, app):
    for step in ("recon", "intel", "guard"):
        assert client.post(f"/api/v1/demo/steps/{step}").status_code == 200
    db_path = app.config["AUDIT_DB_PATH"]
    with sqlite3.connect(db_path) as connection:
        connection.execute("UPDATE audit_entries SET row_hash = ? WHERE sequence = 1", ("f" * 64,))
    result = client.get("/api/v1/guard/audit/verify")
    assert result.status_code == 200
    assert result.json["valid"] is False
    assert result.json["broken_at"] == 1


def test_read_apis_expose_shared_records_and_pending_outbox(client):
    client.post("/api/v1/demo/steps/recon")
    client.post("/api/v1/demo/steps/intel")
    assert client.get("/api/v1/assets").json["items"][0]["id"] == "asset_zt_001"
    assert client.get("/api/v1/matches").json["items"][0]["findingId"] == "finding_zt_001"
    proposal = client.get("/api/v1/patch-proposals").json["items"][0]
    assert proposal["executionAllowed"] is False
    assert proposal["reviewRequired"] is True
    events = client.get("/api/v1/events").json
    assert events["pending"] == len(events["items"])
    assert events["bus"]["state"] == "not_configured"
    asset_event = next(item for item in events["items"] if item["type"] == "asset_created")
    assert asset_event["scopeId"] == "scope_demo_lab_01"
    assert asset_event["target"] == "portal.zt-lab.test"
