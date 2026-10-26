import pytest
from cryptography.fernet import Fernet

from backend import create_app
from backend.auth import create_user
from backend.extensions import db
from backend.mfa import generate_key, totp


def test_production_config_rejects_local_demo_defaults():
    with pytest.raises(RuntimeError) as error:
        create_app({
            "ENVIRONMENT": "production",
            "SECRET_KEY": "local-demo-only-not-for-production",
            "SQLALCHEMY_DATABASE_URI": "sqlite:///unsafe.db",
            "AUTO_CREATE_SCHEMA": True,
            "DEMO_MODE": True,
            "AUTH_REQUIRED": True,
            "AUTH_COOKIE_SECURE": False,
            "ENGINE_URL": "http://127.0.0.1:8765",
            "ENGINE_API_KEY": "e" * 32,
        })
    message = str(error.value)
    assert "FLASK_SECRET_KEY" in message
    assert "DATABASE_URL" in message
    assert "AUTO_CREATE_SCHEMA" in message
    assert "ZEROTRACE_COOKIE_SECURE" in message


def test_production_config_rejects_missing_engine_key():
    with pytest.raises(RuntimeError) as error:
        create_app({
            "ENVIRONMENT": "production",
            "SECRET_KEY": "x" * 64,
            "SQLALCHEMY_DATABASE_URI": "postgresql://user:pass@db.example/zt",
            "AUTO_CREATE_SCHEMA": False,
            "DEMO_MODE": False,
            "AUTH_REQUIRED": True,
            "AUTH_COOKIE_SECURE": True,
            "AUTH_MFA_ENCRYPTION_KEY": Fernet.generate_key().decode(),
            "ENGINE_URL": "http://127.0.0.1:8765",
            "ENGINE_API_KEY": "",
        })
    assert "ZEROTRACE_ENGINE_API_KEY" in str(error.value)


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
        "AUTH_REQUIRED": True,
        "AUTH_SESSION_TTL_SECONDS": 3600,
        "AUTH_COOKIE_SECURE": False,
        "AUTH_MFA_ENCRYPTION_KEY": generate_key(),
        "AUTH_MAX_LOGIN_ATTEMPTS": 10,
    })
    with application.app_context():
        create_user(
            email="admin@zerotrace.local",
            password="correct horse battery staple",
            role="admin",
            tenant_id="tenant_test",
        )
        create_user(
            email="viewer@zerotrace.local",
            password="correct horse battery staple",
            role="viewer",
            tenant_id="tenant_test",
        )
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def login(client, email="admin@zerotrace.local", password="correct horse battery staple"):
    response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert response.status_code == 200, response.json
    return response


def csrf_for(response):
    return response.json["csrfToken"]


def test_mfa_enrollment_requires_a_second_factor_before_api_access(app, client):
    response = login(client)
    csrf = csrf_for(response)
    enroll = client.post(
        "/api/v1/auth/mfa/enroll", headers={"X-CSRF-Token": csrf}
    )
    assert enroll.status_code == 200, enroll.json
    secret = enroll.json["secret"]
    assert enroll.json["otpauthUri"].startswith("otpauth://totp/")

    activate = client.post(
        "/api/v1/auth/mfa/activate",
        json={"code": totp(secret)},
        headers={"X-CSRF-Token": csrf},
    )
    assert activate.status_code == 200, activate.json
    assert activate.json["mfaEnabled"] is True
    client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf})

    pending = login(client)
    assert pending.json["mfaRequired"] is True
    assert pending.json["mfaVerified"] is False
    pending_csrf = csrf_for(pending)
    assert client.get("/api/v1/auth/session").status_code == 200
    blocked = client.get("/api/v1/demo/state")
    assert blocked.status_code == 401
    assert blocked.json["error"]["code"] == "mfa_required"

    verified = client.post(
        "/api/v1/auth/mfa/verify",
        json={"code": totp(secret)},
        headers={"X-CSRF-Token": pending_csrf},
    )
    assert verified.status_code == 200, verified.json
    assert client.get("/api/v1/demo/state").status_code == 200

    # A full sign-in can also submit the code in the same request.
    second = app.test_client()
    combined = second.post(
        "/api/v1/auth/login",
        json={
            "email": "admin@zerotrace.local",
            "password": "correct horse battery staple",
            "mfaCode": totp(secret),
        },
    )
    assert combined.status_code == 200
    assert combined.json["mfaRequired"] is False


def test_password_reset_is_one_time_and_revokes_sessions(app, client):
    csrf = csrf_for(login(client))
    viewer = client.get("/api/v1/auth/users")
    viewer_id = next(
        item["id"]
        for item in viewer.json["items"]
        if item["email"] == "viewer@zerotrace.local"
    )
    issued = client.post(
        f"/api/v1/auth/users/{viewer_id}/password-reset",
        headers={"X-CSRF-Token": csrf},
    )
    assert issued.status_code == 200, issued.json
    token = issued.json["token"]

    reset = app.test_client().post(
        "/api/v1/auth/password-reset",
        json={"token": token, "password": "a different long password"},
    )
    assert reset.status_code == 200, reset.json

    replay = app.test_client().post(
        "/api/v1/auth/password-reset",
        json={"token": token, "password": "another long password"},
    )
    assert replay.status_code == 400
    assert replay.json["error"]["code"] == "invalid_reset_token"

    old = app.test_client().post(
        "/api/v1/auth/login",
        json={
            "email": "viewer@zerotrace.local",
            "password": "correct horse battery staple",
        },
    )
    assert old.status_code == 401
    new = login(
        app.test_client(),
        email="viewer@zerotrace.local",
        password="a different long password",
    )
    assert new.json["user"]["role"] == "viewer"


def test_session_inventory_and_revocation_are_tenant_scoped(app, client):
    first = login(client)
    second_client = app.test_client()
    second = login(second_client)
    sessions = client.get("/api/v1/auth/sessions")
    assert sessions.status_code == 200
    assert len(sessions.json["items"]) == 2
    current_id = sessions.json["currentSessionId"]
    other = next(
        item for item in sessions.json["items"] if item["id"] != current_id
    )

    revoked = client.post(
        f"/api/v1/auth/sessions/{other['id']}/revoke",
        headers={"X-CSRF-Token": csrf_for(first)},
    )
    assert revoked.status_code == 200
    assert second_client.get("/api/v1/auth/session").status_code == 401
    assert client.get("/api/v1/auth/session").status_code == 200
    assert second.json["csrfToken"]


def test_admin_can_reset_mfa_and_disable_the_account(app, client):
    csrf = csrf_for(login(client))
    viewer = client.get("/api/v1/auth/users")
    viewer_id = next(
        item["id"]
        for item in viewer.json["items"]
        if item["email"] == "viewer@zerotrace.local"
    )
    reset = client.post(
        f"/api/v1/auth/users/{viewer_id}/mfa/reset",
        headers={"X-CSRF-Token": csrf},
    )
    assert reset.status_code == 200
    disabled = client.patch(
        f"/api/v1/auth/users/{viewer_id}",
        json={"active": False},
        headers={"X-CSRF-Token": csrf},
    )
    assert disabled.status_code == 200
    denied = app.test_client().post(
        "/api/v1/auth/login",
        json={
            "email": "viewer@zerotrace.local",
            "password": "correct horse battery staple",
        },
    )
    assert denied.status_code == 401
