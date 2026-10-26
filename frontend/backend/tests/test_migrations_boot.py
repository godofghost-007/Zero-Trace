import os
import sys
from pathlib import Path
from uuid import uuid4

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend import create_app  # noqa: E402
from backend.extensions import db  # noqa: E402
from backend.models import AuthSession, UserAccount  # noqa: E402
from scripts.run_migrations import apply  # noqa: E402


def _postgres_url() -> str:
    value = os.environ.get("ZEROTRACE_TEST_DATABASE_URL", "").strip()
    if not value:
        pytest.skip("ZEROTRACE_TEST_DATABASE_URL is not configured")
    if value.startswith("postgresql+psycopg://"):
        return value
    if value.startswith("postgresql://"):
        return value.replace("postgresql://", "postgresql+psycopg://", 1)
    pytest.skip("ZEROTRACE_TEST_DATABASE_URL must be a PostgreSQL URL")
    return ""


def test_bff_boots_from_versioned_migrations_without_create_all(tmp_path):
    database_url = _postgres_url()
    apply(database_url)

    email = f"bootstrap-{uuid4().hex}@zerotrace.local"
    password = "Migrations-only-correct-horse-42!"
    application = create_app({
        "TESTING": True,
        "DATA_DIR": tmp_path / "data",
        "SQLALCHEMY_DATABASE_URI": database_url,
        "AUDIT_DB_PATH": tmp_path / "guard-audit.sqlite",
        "FRONTEND_DIST": tmp_path / "no-frontend",
        "REDIS_URL": "",
        "AUTO_CREATE_SCHEMA": False,
        "DEMO_MODE": False,
        "AUTH_REQUIRED": True,
        "AUTH_COOKIE_SECURE": False,
        "AUTH_BOOTSTRAP_EMAIL": email,
        "AUTH_BOOTSTRAP_PASSWORD": password,
        "AUTH_BOOTSTRAP_ROLE": "admin",
        "AUTH_BOOTSTRAP_TENANT": "tenant_test",
    })

    try:
        client = application.test_client()
        assert client.get("/api/v1/health").status_code == 200
        login = client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password},
        )
        assert login.status_code == 200, login.get_data(as_text=True)
        assert login.json["user"]["role"] == "admin"
    finally:
        with application.app_context():
            user = UserAccount.query.filter_by(email=email).first()
            if user is not None:
                AuthSession.query.filter_by(user_id=user.id).delete()
                db.session.delete(user)
                db.session.commit()
            db.session.remove()
