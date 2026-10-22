import pytest

from backend import create_app
from backend.auth import create_user
from backend.extensions import db


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
    assert response.status_code == 200
    return response.json["csrfToken"]


def test_session_is_required_and_csrf_is_enforced(client):
    assert client.get("/api/v1/demo/state").status_code == 401
    assert client.post(
        "/api/v1/auth/login",
        json={"email": "admin@zerotrace.local", "password": "wrong password"},
    ).status_code == 401

    csrf = login(client)
    session = client.get("/api/v1/auth/session")
    assert session.status_code == 200
    assert session.json["user"]["role"] == "admin"
    assert client.get("/api/v1/demo/state").status_code == 200

    missing = client.post("/api/v1/demo/steps/recon", json={})
    assert missing.status_code == 403
    assert missing.json["error"]["code"] == "csrf_failed"

    accepted = client.post(
        "/api/v1/demo/steps/recon",
        json={},
        headers={"X-CSRF-Token": csrf},
    )
    assert accepted.status_code == 200
    assert accepted.json["stage"] == 1


def test_origin_and_role_boundaries_are_enforced(app, client):
    csrf = login(client)
    denied = client.post(
        "/api/v1/demo/steps/recon",
        json={},
        headers={"X-CSRF-Token": csrf, "Origin": "https://attacker.example"},
    )
    assert denied.status_code == 403
    assert denied.json["error"]["code"] == "origin_denied"

    viewer = app.test_client()
    denied_login = viewer.post(
        "/api/v1/auth/login",
        json={
            "email": "viewer@zerotrace.local",
            "password": "correct horse battery staple",
        },
        headers={"Origin": "https://attacker.example"},
    )
    assert denied_login.status_code == 403
    assert denied_login.json["error"]["code"] == "origin_denied"

    viewer_csrf = login(viewer, "viewer@zerotrace.local")
    assert viewer.get("/api/v1/demo/state").status_code == 200
    assert viewer.get("/api/v1/settings/engine").status_code == 200
    forbidden = viewer.post(
        "/api/v1/demo/steps/recon",
        json={},
        headers={"X-CSRF-Token": viewer_csrf},
    )
    assert forbidden.status_code == 403

    users = viewer.get("/api/v1/auth/users")
    assert users.status_code == 403


def test_admin_can_create_users_and_logout_revokes_session(app, client):
    csrf = login(client)
    created = client.post(
        "/api/v1/auth/users",
        json={
            "email": "operator@zerotrace.local",
            "password": "another strong password",
            "role": "operator",
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 201
    assert created.json["tenantId"] == "tenant_test"

    operator = app.test_client()
    operator_csrf = login(
        operator,
        "operator@zerotrace.local",
        "another strong password",
    )
    changed = operator.post(
        "/api/v1/demo/steps/recon",
        json={},
        headers={"X-CSRF-Token": operator_csrf},
    )
    assert changed.status_code == 200

    revoked = client.post(
        f"/api/v1/auth/users/{created.json['id']}/revoke",
        json={},
        headers={"X-CSRF-Token": csrf},
    )
    assert revoked.status_code == 200
    assert revoked.json["revoked"] == 1
    assert operator.get("/api/v1/demo/state").status_code == 401

    assert client.post(
        "/api/v1/auth/logout", json={}, headers={"X-CSRF-Token": csrf}
    ).status_code == 200
    assert client.get("/api/v1/auth/session").status_code == 401


def test_admin_cannot_create_cross_tenant_user(app, client):
    csrf = login(client)
    denied = client.post(
        "/api/v1/auth/users",
        json={
            "email": "other@zerotrace.local",
            "password": "another strong password",
            "role": "viewer",
            "tenantId": "tenant_other",
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert denied.status_code == 403
    assert denied.json["error"]["code"] == "forbidden"


def test_cli_revoke_disables_user_and_enable_restores_access(app):
    from backend.models import UserAccount

    runner = app.test_cli_runner()
    disabled = runner.invoke(args=["revoke-user", "viewer@zerotrace.local"])
    assert disabled.exit_code == 0
    assert "disabled" in disabled.output
    with app.app_context():
        assert UserAccount.query.filter_by(email="viewer@zerotrace.local").one().active is False

    viewer = app.test_client()
    assert viewer.post(
        "/api/v1/auth/login",
        json={
            "email": "viewer@zerotrace.local",
            "password": "correct horse battery staple",
        },
    ).status_code == 401

    enabled = runner.invoke(args=["enable-user", "viewer@zerotrace.local"])
    assert enabled.exit_code == 0
    assert "enabled" in enabled.output
    assert login(viewer, "viewer@zerotrace.local")


def test_cli_set_password_revokes_sessions(app):
    runner = app.test_cli_runner()
    viewer = app.test_client()
    assert login(viewer, "viewer@zerotrace.local")
    changed = runner.invoke(
        args=[
            "set-password",
            "viewer@zerotrace.local",
            "--password",
            "a new strong password",
        ]
    )
    assert changed.exit_code == 0
    assert "revoked 1 session" in changed.output
    assert viewer.get("/api/v1/demo/state").status_code == 401
    assert viewer.post(
        "/api/v1/auth/login",
        json={
            "email": "viewer@zerotrace.local",
            "password": "correct horse battery staple",
        },
    ).status_code == 401
    assert login(viewer, "viewer@zerotrace.local", "a new strong password")


def test_login_is_rate_limited(client):
    for _ in range(5):
        assert client.post(
            "/api/v1/auth/login",
            json={"email": "admin@zerotrace.local", "password": "wrong password"},
        ).status_code == 401
    limited = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@zerotrace.local", "password": "correct horse battery staple"},
    )
    assert limited.status_code == 429
