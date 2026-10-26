from datetime import UTC, datetime, timedelta

from backend import create_app
from backend.auth import create_user
from backend.extensions import db
from backend.models import (
    AuthAuditEvent,
    AuthSession,
    OidcIdentity,
    PasswordResetToken,
    UserAccount,
)


def _make_app(tmp_path):
    data_dir = tmp_path / "data"
    return create_app({
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


def _login(client, email, password):
    response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert response.status_code == 200, response.get_data(as_text=True)
    return response.json["csrfToken"]


def test_admin_can_export_and_erase_a_user(tmp_path):
    app = _make_app(tmp_path)
    admin_email = "privacy-admin@zerotrace.local"
    target_email = "privacy-target@zerotrace.local"
    password = "correct horse battery staple"
    with app.app_context():
        admin = create_user(
            email=admin_email, password=password, role="admin", tenant_id="tenant_test"
        )
        target = create_user(
            email=target_email, password=password, role="viewer", tenant_id="tenant_test"
        )
        target_id = target.id
        admin_id = admin.id
        now = datetime.now(UTC)
        db.session.add(
            OidcIdentity(
                id="oid_privacy_test",
                issuer="https://idp.example.test",
                subject="subject-123",
                user_id=target_id,
                tenant_id="tenant_test",
                email=target_email,
                created_at=now,
            )
        )
        db.session.add(
            PasswordResetToken(
                id="prt_privacy_test",
                token_hash="a" * 64,
                user_id=target_id,
                tenant_id="tenant_test",
                created_at=now,
                expires_at=now + timedelta(minutes=30),
            )
        )
        db.session.commit()

    admin_client = app.test_client()
    admin_csrf = _login(admin_client, admin_email, password)
    target_client = app.test_client()
    target_csrf = _login(target_client, target_email, password)

    exported = admin_client.get(f"/api/v1/auth/users/{target_id}/export")
    assert exported.status_code == 200
    assert exported.headers["Content-Disposition"].startswith("attachment;")
    body = exported.get_json()
    assert body["user"]["email"] == target_email
    assert body["sessions"]
    assert body["oidcIdentities"][0]["subject"] == "subject-123"
    assert body["passwordResetTokens"][0]["id"] == "prt_privacy_test"
    serialized = exported.get_data(as_text=True)
    assert "password_hash" not in serialized
    assert "token_hash" not in serialized
    assert "mfa_secret" not in serialized

    self_erase = admin_client.delete(
        f"/api/v1/auth/users/{admin_id}",
        headers={"X-CSRF-Token": admin_csrf},
    )
    assert self_erase.status_code == 409
    assert self_erase.json["error"]["code"] == "cannot_erase_self"

    forbidden = target_client.delete(
        f"/api/v1/auth/users/{admin_id}",
        headers={"X-CSRF-Token": target_csrf},
    )
    assert forbidden.status_code == 403

    erased = admin_client.delete(
        f"/api/v1/auth/users/{target_id}",
        headers={"X-CSRF-Token": admin_csrf},
    )
    assert erased.status_code == 200
    assert erased.json["erasedUserId"] == target_id

    assert target_client.get("/api/v1/demo/state").status_code == 401
    with app.app_context():
        assert db.session.get(UserAccount, target_id) is None
        assert AuthSession.query.filter_by(user_id=target_id).count() == 0
        assert OidcIdentity.query.filter_by(user_id=target_id).count() == 0
        assert PasswordResetToken.query.filter_by(user_id=target_id).count() == 0
        event = AuthAuditEvent.query.filter_by(event_type="user_erasure").first()
        assert event is not None
        assert event.detail == "account_erased"
        assert target_id not in event.detail
        db.session.remove()
        db.drop_all()
