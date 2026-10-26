from datetime import UTC, datetime, timedelta

from backend import create_app
from backend.auth import create_user
from backend.extensions import db
from backend.mfa import totp
from backend.models import AuthSession


def _make_app(tmp_path, **overrides):
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
        "AUTH_REQUIRED": True,
        "AUTH_SESSION_TTL_SECONDS": 3600,
        "AUTH_IDLE_TIMEOUT_SECONDS": 1800,
        "AUTH_COOKIE_SECURE": False,
    }
    config.update(overrides)
    return create_app(config)


def _login(client, email, password):
    response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert response.status_code == 200, response.get_data(as_text=True)
    return response


def test_tenant_wide_mfa_requires_enrollment_before_console_access(tmp_path):
    app = _make_app(tmp_path, AUTH_MFA_REQUIRED=True)
    email = "policy-user@zerotrace.local"
    password = "correct horse battery staple"
    with app.app_context():
        create_user(email=email, password=password, role="operator", tenant_id="tenant_test")

    client = app.test_client()
    login = _login(client, email, password)
    assert login.json["mfaRequired"] is True
    assert login.json["mfaEnrollmentRequired"] is True
    assert login.json["mfaVerified"] is False
    csrf = login.json["csrfToken"]

    blocked = client.get("/api/v1/demo/state")
    assert blocked.status_code == 401
    assert blocked.json["error"]["code"] == "mfa_required"

    enrollment = client.post(
        "/api/v1/auth/mfa/enroll",
        headers={"X-CSRF-Token": csrf},
    )
    assert enrollment.status_code == 200
    secret = enrollment.json["secret"]

    activation = client.post(
        "/api/v1/auth/mfa/activate",
        json={"code": totp(secret)},
        headers={"X-CSRF-Token": csrf},
    )
    assert activation.status_code == 200
    assert activation.json["mfaEnabled"] is True

    assert client.get("/api/v1/demo/state").status_code == 200
    session = client.get("/api/v1/auth/session")
    assert session.status_code == 200
    assert session.json["mfaVerified"] is True
    assert session.json["mfaEnrollmentRequired"] is False

    with app.app_context():
        db.session.remove()
        db.drop_all()


def test_idle_session_is_revoked(tmp_path):
    app = _make_app(tmp_path, AUTH_IDLE_TIMEOUT_SECONDS=60)
    email = "idle-user@zerotrace.local"
    password = "correct horse battery staple"
    with app.app_context():
        create_user(email=email, password=password, role="operator", tenant_id="tenant_test")

    client = app.test_client()
    _login(client, email, password)
    assert client.get("/api/v1/demo/state").status_code == 200

    with app.app_context():
        session = AuthSession.query.one()
        session.last_seen_at = datetime.now(UTC) - timedelta(seconds=61)
        db.session.commit()

    expired = client.get("/api/v1/auth/session")
    assert expired.status_code == 401
    with app.app_context():
        session = AuthSession.query.one()
        assert session.revoked_at is not None
        db.session.remove()
        db.drop_all()
