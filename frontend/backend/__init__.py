from pathlib import Path
from uuid import uuid4

from flask import Flask, g, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException

from .config import Config
from .extensions import db


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, static_folder=None)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    Path(app.config["DATA_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(app.config["AUDIT_DB_PATH"]).parent.mkdir(parents=True, exist_ok=True)
    db.init_app(app)

    from .api import api
    from .auth import auth, bootstrap_admin, install_auth_guards
    from .cli import register_cli
    from .engine_api import engine_api

    app.register_blueprint(auth, url_prefix="/api/v1")
    app.register_blueprint(api, url_prefix="/api/v1")
    app.register_blueprint(engine_api, url_prefix="/api/v1")
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
            db.create_all()
            from .services.migrations import migrate_legacy_event_outbox
            from .services.scenario import initialize_demo_state

            migrate_legacy_event_outbox()

            initialize_demo_state()
        bootstrap_admin(app)

    return app
