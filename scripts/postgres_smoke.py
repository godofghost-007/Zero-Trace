"""Exercise the Flask BFF against a disposable PostgreSQL database.

This is the local proof that the SQLite demo path is not the only tested path.
It creates a uniquely named database, runs authentication plus the full demo
scenario, verifies the audit chain and readiness state, then drops the database.

Run after ``docker compose --profile core up -d postgres``:

    python -m scripts.postgres_smoke
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"
for path in (ROOT, FRONTEND):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import psycopg  # noqa: E402

from backend import create_app  # noqa: E402
from backend.auth import create_user  # noqa: E402
from backend.extensions import db  # noqa: E402

DEFAULT_URL = "postgresql://zerotrace:zerotrace-dev-only@127.0.0.1:5432/zerotrace"


def _urls(raw: str, database: str) -> tuple[str, str, str]:
    plain = raw.replace("postgresql+psycopg://", "postgresql://", 1)
    parts = urlsplit(plain)
    admin = urlunsplit(parts._replace(path="/zerotrace"))
    smoke = urlunsplit(parts._replace(path=f"/{database}"))
    sqlalchemy = smoke.replace("postgresql://", "postgresql+psycopg://", 1)
    return admin, smoke, sqlalchemy


def _progress(message: str) -> None:
    print(f"[postgres-smoke] {message}", file=sys.stderr, flush=True)


def run(raw_url: str) -> dict[str, object]:
    database = f"zerotrace_smoke_{secrets.token_hex(5)}"
    admin_url, _, sqlalchemy_url = _urls(raw_url, database)
    _progress(f"creating disposable database {database}")
    with psycopg.connect(admin_url, autocommit=True) as connection:
        connection.execute(f'CREATE DATABASE "{database}"')
    temporary = tempfile.TemporaryDirectory(prefix="zerotrace-pg-")
    data_dir = Path(temporary.name)
    _progress("creating the Flask application")
    app = create_app({
        "TESTING": True,
        "DATA_DIR": data_dir,
        "SQLALCHEMY_DATABASE_URI": sqlalchemy_url,
        "AUDIT_DB_PATH": data_dir / "guard-audit.sqlite",
        "FRONTEND_DIST": data_dir / "no-frontend",
        "REDIS_URL": "",
        "AUTO_CREATE_SCHEMA": True,
        "DEMO_MODE": True,
        "AUTH_REQUIRED": True,
        "AUTH_SESSION_TTL_SECONDS": 3600,
        "AUTH_COOKIE_SECURE": False,
        "SQLALCHEMY_ENGINE_OPTIONS": {"pool_pre_ping": True},
    })
    checks: dict[str, object] = {}
    _progress("application created")
    try:
        with app.app_context():
            create_user(
                email="pg-admin@zerotrace.local",
                password="postgres smoke password",
                role="admin",
                tenant_id="tenant_pg",
            )
        _progress("test administrator created")
        client = app.test_client()
        login = client.post(
            "/api/v1/auth/login",
            json={
                "email": "pg-admin@zerotrace.local",
                "password": "postgres smoke password",
            },
        )
        checks["login"] = login.status_code
        csrf = login.json["csrfToken"]
        headers = {"X-CSRF-Token": csrf}
        _progress("login completed")

        state = client.get("/api/v1/demo/state")
        checks["state"] = state.status_code
        checks["database"] = state.json["backend"]["database"]
        assert checks["database"] == "postgresql"
        _progress("state read completed")
        for step in ("recon", "intel", "guard"):
            response = client.post(
                f"/api/v1/demo/steps/{step}", json={}, headers=headers
            )
            checks[f"step_{step}"] = response.status_code
            assert response.status_code == 200, response.json
            _progress(f"{step} step completed")
        final = response.json
        checks["stage"] = final["stage"]
        checks["readiness"] = final["readiness"]["score"]
        checks["audit_valid"] = final["backend"]["audit"]["valid"]
        checks["events"] = len(final["events"])
        checks["ready"] = client.get("/api/v1/ready").status_code
        checks["assets"] = len(client.get("/api/v1/assets").json["items"])
        checks["matches"] = len(client.get("/api/v1/matches").json["items"])
        checks["summary"] = client.get("/api/v1/dashboard/summary").status_code
        checks["time"] = datetime.now(timezone.utc).isoformat()
        assert checks["audit_valid"] is True
        assert checks["stage"] == 3
        assert checks["ready"] == 200
        return {"ok": True, "database": database, "checks": checks}
    finally:
        with app.app_context():
            db.session.remove()
            db.engine.dispose()
        _progress(f"dropping disposable database {database}")
        with psycopg.connect(admin_url, autocommit=True) as connection:
            connection.execute(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)')
        temporary.cleanup()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--url",
        default=os.environ.get("ZEROTRACE_POSTGRES_URL", DEFAULT_URL),
    )
    args = parser.parse_args(argv)
    try:
        result = run(args.url)
    except Exception as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
