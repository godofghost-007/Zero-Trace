"""Production-shaped authentication and role enforcement for the BFF.

The browser holds an opaque session cookie. Only a SHA-256 digest of that
token is stored, so a database read cannot mint a usable cookie. Every
state-changing request also needs a per-session CSRF token. Roles are ordered
``viewer < operator < admin`` and are enforced centrally before a route runs.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import wraps
import hashlib
import hmac
import re
import secrets
import threading
import time
from urllib.parse import urlsplit
from uuid import uuid4

from flask import Blueprint, current_app, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db
from .models import AuthSession, UserAccount

auth = Blueprint("auth", __name__)

ROLE_RANK = {"viewer": 1, "operator": 2, "admin": 3}
ALLOWED_ROLES = frozenset(ROLE_RANK)
EMAIL_PATTERN = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,63}$")
SESSION_COOKIE = "zt_session"
PUBLIC_ENDPOINTS = {
    ("GET", "/api/v1/health"),
    ("GET", "/api/v1/ready"),
    ("POST", "/api/v1/auth/login"),
}
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
LOGIN_ATTEMPTS: dict[str, deque[float]] = defaultdict(deque)
LOGIN_LOCK = threading.Lock()


class AuthError(ValueError):
    def __init__(self, message: str, status: int = 400, code: str = "auth_error") -> None:
        super().__init__(message)
        self.status = status
        self.code = code


@dataclass(frozen=True)
class AuthPrincipal:
    subject: str
    email: str
    role: str
    tenant_id: str


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _normalize_email(value: object) -> str:
    if not isinstance(value, str):
        raise AuthError("A valid email address is required.")
    email = value.strip().lower()
    if len(email) > 254 or not EMAIL_PATTERN.fullmatch(email):
        raise AuthError("A valid email address is required.")
    return email


def _validate_password(value: object) -> str:
    if not isinstance(value, str) or not 12 <= len(value) <= 256:
        raise AuthError("Password must be between 12 and 256 characters.")
    if any(ord(character) < 32 for character in value):
        raise AuthError("Password must not contain control characters.")
    return value


def _validate_role(value: object) -> str:
    if not isinstance(value, str) or value not in ALLOWED_ROLES:
        raise AuthError("Role must be viewer, operator, or admin.")
    return value


def _tenant(value: object | None) -> str:
    if value is None or value == "":
        return "tenant_local"
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
        raise AuthError("Tenant identifier is invalid.")
    return value


def create_user(
    *,
    email: str,
    password: str,
    role: str = "viewer",
    tenant_id: str = "tenant_local",
    active: bool = True,
) -> UserAccount:
    normalized_email = _normalize_email(email)
    normalized_role = _validate_role(role)
    normalized_tenant = _tenant(tenant_id)
    if db.session.query(UserAccount.id).filter_by(email=normalized_email).first():
        raise AuthError("A user with that email already exists.", 409, "user_exists")
    user = UserAccount(
        id=f"usr_{uuid4().hex}",
        tenant_id=normalized_tenant,
        email=normalized_email,
        password_hash=generate_password_hash(_validate_password(password)),
        role=normalized_role,
        active=active,
    )
    db.session.add(user)
    db.session.commit()
    return user


def bootstrap_admin(app) -> None:
    email = app.config.get("AUTH_BOOTSTRAP_EMAIL", "")
    password = app.config.get("AUTH_BOOTSTRAP_PASSWORD", "")
    if not email and not password:
        return
    if not email or not password:
        app.logger.warning("bootstrap user skipped: both email and password are required")
        return
    with app.app_context():
        try:
            normalized_email = _normalize_email(email)
        except AuthError as error:
            app.logger.warning("bootstrap user skipped: %s", error)
            return
        if db.session.query(UserAccount.id).filter_by(email=normalized_email).first():
            return
        try:
            create_user(
                email=email,
                password=password,
                role=app.config.get("AUTH_BOOTSTRAP_ROLE", "admin"),
                tenant_id=app.config.get("AUTH_BOOTSTRAP_TENANT", "tenant_local"),
                active=True,
            )
            app.logger.warning("bootstrap user created for %s", normalized_email)
        except AuthError as error:
            app.logger.warning("bootstrap user skipped: %s", error)


def _error(code: str, message: str, status: int):
    return jsonify({
        "error": {"code": code, "message": message},
        "request_id": getattr(g, "request_id", None),
    }), status


def _load_principal() -> bool:
    token = request.cookies.get(SESSION_COOKIE, "")
    g.auth_session = None
    g.principal = None
    if not token or len(token) > 256:
        return False
    session = AuthSession.query.filter_by(token_hash=_hash_token(token)).first()
    if session is None or session.revoked_at is not None:
        return False
    now = _now()
    if _aware(session.expires_at) <= now:
        return False
    user = db.session.get(UserAccount, session.user_id)
    if user is None or not user.active or user.tenant_id != session.tenant_id:
        return False
    if session.last_seen_at is None or (_aware(session.last_seen_at) + timedelta(seconds=60)) <= now:
        session.last_seen_at = now
        db.session.commit()
    g.auth_session = session
    g.principal = AuthPrincipal(
        subject=user.id,
        email=user.email,
        role=user.role,
        tenant_id=user.tenant_id,
    )
    return True


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _origin_allowed() -> bool:
    origin = request.headers.get("Origin")
    if not origin:
        return True
    try:
        origin_parts = urlsplit(origin)
        request_host = urlsplit(f"//{request.host}").hostname
    except ValueError:
        return False
    if origin_parts.scheme not in {"http", "https"}:
        return False
    origin_host = (origin_parts.hostname or "").lower()
    if origin_host == (request_host or "").lower():
        return True
    return origin_host in {"127.0.0.1", "localhost", "::1"}


def _rate_limited(key: str) -> bool:
    limit = max(1, int(current_app.config.get("AUTH_MAX_LOGIN_ATTEMPTS", 5)))
    window = max(30, int(current_app.config.get("AUTH_LOGIN_WINDOW_SECONDS", 300)))
    current = time.monotonic()
    with LOGIN_LOCK:
        if len(LOGIN_ATTEMPTS) > 10_000:
            LOGIN_ATTEMPTS.clear()
        attempts = LOGIN_ATTEMPTS[key]
        while attempts and current - attempts[0] >= window:
            attempts.popleft()
        return len(attempts) >= limit


def _record_failure(key: str) -> None:
    with LOGIN_LOCK:
        LOGIN_ATTEMPTS[key].append(time.monotonic())


def _clear_failures(key: str) -> None:
    with LOGIN_LOCK:
        LOGIN_ATTEMPTS.pop(key, None)


def _required_role_for(method: str, path: str) -> str | None:
    if path == "/api/v1/auth/logout":
        return None
    if path.startswith("/api/v1/auth/users"):
        return "admin"
    if path == "/api/v1/settings/engine":
        return "admin" if method in MUTATING_METHODS else None
    if method in MUTATING_METHODS:
        return "operator"
    return None


def install_auth_guards(app) -> None:
    @app.before_request
    def authenticate_request():
        if not request.path.startswith("/api/"):
            return None
        public = (request.method, request.path) in PUBLIC_ENDPOINTS
        if not app.config.get("AUTH_REQUIRED", True):
            g.auth_session = None
            g.principal = AuthPrincipal(
                "local-demo", "local@example.invalid", "admin", "tenant_local"
            )
            return None
        if request.path == "/api/v1/auth/login" and request.method == "POST":
            if not _origin_allowed():
                return _error("origin_denied", "Request origin is not allowed.", 403)
            return None
        if public and request.path != "/api/v1/auth/login":
            return None
        if not public:
            _load_principal()
            if g.principal is None:
                return _error("authentication_required", "Sign in to continue.", 401)
            if request.method in MUTATING_METHODS:
                if not _origin_allowed():
                    return _error("origin_denied", "Request origin is not allowed.", 403)
                csrf = request.headers.get("X-CSRF-Token", "")
                expected = g.auth_session.csrf_token if g.auth_session else ""
                if not csrf or not expected or not hmac.compare_digest(csrf, expected):
                    return _error("csrf_failed", "A valid CSRF token is required.", 403)
            required = _required_role_for(request.method, request.path)
            if required is not None and ROLE_RANK[g.principal.role] < ROLE_RANK[required]:
                return _error("forbidden", "Your role does not permit this action.", 403)
        return None


def role_required(required: str):
    def decorator(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            principal = getattr(g, "principal", None)
            if principal is None:
                return _error("authentication_required", "Sign in to continue.", 401)
            if ROLE_RANK[principal.role] < ROLE_RANK[required]:
                return _error("forbidden", "Your role does not permit this action.", 403)
            return function(*args, **kwargs)
        return wrapped
    return decorator


def _public_user(user: UserAccount) -> dict[str, object]:
    return {
        "id": user.id,
        "email": user.email,
        "role": user.role,
        "tenantId": user.tenant_id,
        "active": user.active,
        "createdAt": user.created_at.isoformat() if user.created_at else None,
        "lastLoginAt": user.last_login_at.isoformat() if user.last_login_at else None,
    }


@auth.post("/auth/login")
def login():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _error("invalid_request", "A JSON object is required.", 400)
    if set(payload) - {"email", "password"}:
        return _error("invalid_request", "Only email and password are accepted.", 400)
    try:
        email = _normalize_email(payload.get("email"))
        password = payload.get("password")
    except AuthError as error:
        return _error(error.code, str(error), error.status)
    key = f"{request.remote_addr or 'unknown'}:{email}"
    if _rate_limited(key):
        return _error("rate_limited", "Too many sign-in attempts. Try again later.", 429)
    user = UserAccount.query.filter_by(email=email).first()
    if user is None or not user.active or not isinstance(password, str) or not check_password_hash(user.password_hash, password):
        _record_failure(key)
        return _error("invalid_credentials", "Invalid email or password.", 401)
    _clear_failures(key)
    now = _now()
    ttl = max(300, int(current_app.config.get("AUTH_SESSION_TTL_SECONDS", 28800)))
    raw_token = secrets.token_urlsafe(48)
    session = AuthSession(
        id=f"ses_{uuid4().hex}",
        token_hash=_hash_token(raw_token),
        user_id=user.id,
        tenant_id=user.tenant_id,
        csrf_token=secrets.token_urlsafe(32),
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(seconds=ttl),
    )
    user.last_login_at = now
    db.session.add(session)
    db.session.commit()
    response = jsonify({
        "user": _public_user(user),
        "csrfToken": session.csrf_token,
        "expiresAt": session.expires_at.isoformat(),
    })
    response.set_cookie(
        SESSION_COOKIE,
        raw_token,
        max_age=ttl,
        httponly=True,
        secure=bool(current_app.config.get("AUTH_COOKIE_SECURE", False)),
        samesite="Lax",
        path="/",
    )
    return response


@auth.get("/auth/session")
def session_info():
    principal = getattr(g, "principal", None)
    if principal is None:
        return _error("authentication_required", "Sign in to continue.", 401)
    session = getattr(g, "auth_session", None)
    return jsonify({
        "user": {
            "id": principal.subject,
            "email": principal.email,
            "role": principal.role,
            "tenantId": principal.tenant_id,
            "active": True,
        },
        "csrfToken": session.csrf_token if session else "",
        "expiresAt": session.expires_at.isoformat() if session else None,
    })


@auth.post("/auth/logout")
def logout():
    session = getattr(g, "auth_session", None)
    if session is not None:
        session.revoked_at = _now()
        db.session.commit()
    response = jsonify({"ok": True})
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@auth.get("/auth/users")
@role_required("admin")
def list_users():
    principal = g.principal
    rows = UserAccount.query.filter_by(tenant_id=principal.tenant_id).order_by(UserAccount.created_at.asc()).all()
    return jsonify({"items": [_public_user(row) for row in rows]})


@auth.post("/auth/users")
@role_required("admin")
def create_user_endpoint():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _error("invalid_request", "A JSON object is required.", 400)
    unknown = set(payload) - {"email", "password", "role", "tenantId", "active"}
    if unknown:
        return _error("invalid_request", f"Unexpected field(s): {', '.join(sorted(unknown))}.", 400)
    try:
        tenant_id = payload.get("tenantId", g.principal.tenant_id)
        if tenant_id != g.principal.tenant_id:
            return _error("forbidden", "Users can only be created in your tenant.", 403)
        user = create_user(
            email=payload.get("email"),
            password=payload.get("password"),
            role=payload.get("role", "viewer"),
            tenant_id=tenant_id,
            active=payload.get("active", True) is not False,
        )
    except AuthError as error:
        return _error(error.code, str(error), error.status)
    return jsonify(_public_user(user)), 201


@auth.patch("/auth/users/<user_id>")
@role_required("admin")
def update_user(user_id: str):
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _error("invalid_request", "A JSON object is required.", 400)
    unknown = set(payload) - {"role", "active"}
    if unknown or not payload:
        return _error("invalid_request", "Only role and active may be changed.", 400)
    user = db.session.get(UserAccount, user_id)
    if user is None or user.tenant_id != g.principal.tenant_id:
        return _error("user_not_found", "User was not found.", 404)
    if "role" in payload:
        try:
            user.role = _validate_role(payload["role"])
        except AuthError as error:
            return _error(error.code, str(error), error.status)
    if "active" in payload:
        if not isinstance(payload["active"], bool):
            return _error("invalid_request", "active must be a boolean.", 400)
        user.active = payload["active"]
    if user.role != "admin" or not user.active:
        active_admins = UserAccount.query.filter_by(
            tenant_id=user.tenant_id, role="admin", active=True
        ).count()
        if active_admins == 0:
            db.session.rollback()
            return _error("last_admin", "The tenant must keep an active admin.", 409)
    db.session.commit()
    return jsonify(_public_user(user))


@auth.post("/auth/users/<user_id>/revoke")
@role_required("admin")
def revoke_user_sessions(user_id: str):
    user = db.session.get(UserAccount, user_id)
    if user is None or user.tenant_id != g.principal.tenant_id:
        return _error("user_not_found", "User was not found.", 404)
    now = _now()
    sessions = AuthSession.query.filter_by(user_id=user.id, revoked_at=None).all()
    for session in sessions:
        session.revoked_at = now
    db.session.commit()
    return jsonify({"ok": True, "revoked": len(sessions)})
