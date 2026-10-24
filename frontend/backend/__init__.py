import time
from pathlib import Path
from uuid import uuid4

from cryptography.fernet import Fernet
from flask import Flask, g, jsonify, request, send_from_directory
from sqlalchemy.exc import OperationalError
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import Config
from .extensions import db


def validate_runtime_config(app: Flask) -> None:
    """Fail fast when a production configuration is unsafe."""

    if app.config.get("ENVIRONMENT") not in {"production", "prod"}:
        return
    problems: list[str] = []
    secret = str(app.config.get("SECRET_KEY", ""))
    if len(secret) < 32 or secret == "local-demo-only-not-for-production":
        problems.append("FLASK_SECRET_KEY must be a unique value of at least 32 characters")
    database = str(app.config.get("SQLALCHEMY_DATABASE_URI", ""))
    if not database.startswith(("postgresql://", "postgresql+psycopg://")):
        problems.append("DATABASE_URL must point to PostgreSQL in production")
    if app.config.get("AUTO_CREATE_SCHEMA", True):
        problems.append("AUTO_CREATE_SCHEMA must be false in production")
    if app.config.get("DEMO_MODE", True):
        problems.append("DEMO_MODE must be false in production")
    if not app.config.get("AUTH_REQUIRED", True):
        problems.append("AUTH_REQUIRED must be true in production")
    if not app.config.get("AUTH_COOKIE_SECURE", False):
        problems.append("ZEROTRACE_COOKIE_SECURE must be true in production")
    key = str(app.config.get("AUTH_MFA_ENCRYPTION_KEY", "")).strip()
    if not key:
        problems.append("ZEROTRACE_MFA_ENCRYPTION_KEY is required in production")
    else:
        try:
            Fernet(key.encode("ascii"))
        except (ValueError, TypeError):
            problems.append("ZEROTRACE_MFA_ENCRYPTION_KEY is not a valid Fernet key")
    if app.config.get("AUTH_OIDC_ENABLED"):
        for name in (
            "AUTH_OIDC_ISSUER",
            "AUTH_OIDC_CLIENT_ID",
            "AUTH_OIDC_CLIENT_SECRET",
        ):
            if not str(app.config.get(name, "")).strip():
                problems.append(f"{name} is required when OIDC is enabled")
    if problems:
        raise RuntimeError(
            "Unsafe production configuration: " + "; ".join(problems)
        )


def _create_schema_safely() -> None:
    """Create tables even when multiple Gunicorn workers boot together."""

    last_error: Exception | None = None
    for attempt in range(5):
        try:
            db.create_all()
            return
        except OperationalError as error:
            db.session.rollback()
            last_error = error
            if "already exists" not in str(error).lower() or attempt == 4:
                raise
            time.sleep(0.2 * (attempt + 1))
    assert last_error is not None
    raise last_error


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, static_folder=None)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    validate_runtime_config(app)
    if app.config.get("TRUST_PROXY"):
        app.wsgi_app = ProxyFix(
            app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1
        )

    Path(app.config["DATA_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(app.config["AUDIT_DB_PATH"]).parent.mkdir(parents=True, exist_ok=True)
    db.init_app(app)

    from .api import api
    from .auth import auth, bootstrap_admin, configure_oidc, install_auth_guards
    from .cli import register_cli
    from .engine_api import engine_api

    app.register_blueprint(auth, url_prefix="/api/v1")
    app.register_blueprint(api, url_prefix="/api/v1")
    app.register_blueprint(engine_api, url_prefix="/api/v1")
    configure_oidc(app)
    register_cli(app)

    @app.before_request
    def assign_request_id() -> None:
        inbound = request.headers.get("X-Request-ID", "")
        g.request_id = inbound[:96] if inbound and len(inbound) <= 96 else str(uuid4())

    install_auth_guards(app)

    @app.after_request
    def attach_request_id(response):
        response.headers["X-Request-ID"] = getattr(g, "request_id", str(uuid4()))
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; font-src 'self' data:; connect-src 'self'; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(HTTPException)
    def handle_http_error(error: HTTPException):
        return jsonify({
            "error": {"code": error.name.lower().replace(" ", "_"), "message": error.description},
            "request_id": getattr(g, "request_id", None),
        }), error.code or 500

    @app.errorhandler(Exception)
    def handle_unexpected_error(error: Exception):
        app.logger.exception("Unhandled API/application error request_id=%s", getattr(g, "request_id", "unknown"))
        return jsonify({
            "error": {"code": "internal_error", "message": "The local demo API encountered an error."},
            "request_id": getattr(g, "request_id", None),
        }), 500

    frontend = Path(app.config["FRONTEND_DIST"])

    @app.get("/", defaults={"path": ""})
    @app.get("/<path:path>")
    def serve_frontend(path: str):
        if path.startswith("api/"):
            return jsonify({"error": {"code": "not_found", "message": "API route not found."}}), 404
        candidate = frontend / path
        if path and candidate.is_file():
            return send_from_directory(frontend, path)
        index = frontend / "index.html"
        if index.is_file():
            return send_from_directory(frontend, "index.html")
        return jsonify({"service": "ZeroTrace Flask API", "ui": "Run the Vite development server on port 3000."}), 200

    if app.config.get("AUTO_CREATE_SCHEMA", True):
        with app.app_context():
            _create_schema_safely()
            from .services.migrations import (
                migrate_identity_columns,
                migrate_legacy_event_outbox,
            )
            from .services.scenario import initialize_demo_state

            migrate_identity_columns()
            migrate_legacy_event_outbox()

            initialize_demo_state()
        bootstrap_admin(app)

    return app
