"""Production-shaped authentication and role enforcement for the BFF.

The browser holds an opaque session cookie. Only a SHA-256 digest of that
token is stored, so a database read cannot mint a usable cookie. Every
state-changing request also needs a per-session CSRF token. Roles are ordered
``viewer < operator < admin`` and are enforced centrally before a route runs.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import wraps
from urllib.parse import urlsplit
from uuid import uuid4

from authlib.integrations.flask_client import OAuth
from flask import (
    Blueprint,
    current_app,
    g,
    jsonify,
    redirect,
    request,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db
from .mfa import (
    MfaError,
    decrypt_secret,
    encrypt_secret,
    generate_secret,
    provisioning_uri,
    verify_totp,
)
from .models import (
    AuthAuditEvent,
    AuthSession,
    OidcIdentity,
    PasswordResetToken,
    UserAccount,
)

auth = Blueprint("auth", __name__)

ROLE_RANK = {"viewer": 1, "operator": 2, "admin": 3}
ALLOWED_ROLES = frozenset(ROLE_RANK)
EMAIL_PATTERN = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,63}$")
SESSION_COOKIE = "zt_session"
PUBLIC_ENDPOINTS = {
    ("GET", "/api/v1/health"),
    ("GET", "/api/v1/ready"),
    ("GET", "/api/v1/metrics"),
    ("GET", "/api/v1/engine/metrics"),
    ("POST", "/api/v1/auth/login"),
    ("POST", "/api/v1/auth/password-reset"),
    ("GET", "/api/v1/auth/oidc/login"),
    ("GET", "/api/v1/auth/oidc/callback"),
}
MFA_ALLOWED_ENDPOINTS = {
    ("GET", "/api/v1/auth/session"),
    ("POST", "/api/v1/auth/mfa/verify"),
    ("POST", "/api/v1/auth/logout"),
}
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
LOGIN_ATTEMPTS: dict[str, deque[float]] = defaultdict(deque)
LOGIN_LOCK = threading.Lock()
oauth = OAuth()


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
    return datetime.now(UTC)


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


def _mfa_key() -> str:
    configured = str(current_app.config.get("AUTH_MFA_ENCRYPTION_KEY", "")).strip()
    if configured:
        return configured
    # Local/demo fallback only. Production validation requires an explicit key.
    secret = str(current_app.config.get("SECRET_KEY", "")).encode("utf-8")
    return base64.urlsafe_b64encode(hashlib.sha256(secret).digest()).decode("ascii")


def _session_ip() -> str | None:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded and current_app.config.get("TRUST_PROXY"):
        candidate = forwarded.split(",", 1)[0].strip()
    else:
        candidate = request.remote_addr or ""
    return candidate[:64] or None


def _session_user_agent() -> str | None:
    return (request.headers.get("User-Agent", "") or "")[:512] or None


def _record_auth_event(
    event_type: str,
    outcome: str,
    *,
    user: UserAccount | None = None,
    tenant_id: str | None = None,
    detail: str | None = None,
) -> None:
    try:
        db.session.add(
            AuthAuditEvent(
                id=f"aud_{uuid4().hex}",
                event_type=event_type[:64],
                outcome=outcome[:32],
                user_id=user.id if user is not None else None,
                tenant_id=(
                    user.tenant_id if user is not None else tenant_id
                ),
                ip_address=_session_ip(),
                user_agent=_session_user_agent(),
                detail=(detail or "")[:512] or None,
            )
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception("auth audit event could not be recorded")


def _create_session(
    user: UserAccount,
    *,
    auth_method: str,
    mfa_verified: bool,
) -> tuple[AuthSession, str]:
    now = _now()
    ttl = max(300, int(current_app.config.get("AUTH_SESSION_TTL_SECONDS", 28800)))
    raw_token = secrets.token_urlsafe(48)
    session = AuthSession(
        id=f"ses_{uuid4().hex}",
        token_hash=_hash_token(raw_token),
        user_id=user.id,
        tenant_id=user.tenant_id,
        csrf_token=secrets.token_urlsafe(32),
        auth_method=auth_method[:32],
        mfa_verified=mfa_verified,
        ip_address=_session_ip(),
        user_agent=_session_user_agent(),
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(seconds=ttl),
    )
    user.last_login_at = now
    db.session.add(session)
    db.session.commit()
    return session, raw_token


def _set_session_cookie(response, session: AuthSession, raw_token: str):
    ttl = max(0, int((_aware(session.expires_at) - _now()).total_seconds()))
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


def _session_response(
    user: UserAccount,
    session: AuthSession,
    raw_token: str,
    *,
    mfa_required: bool = False,
):
    response = jsonify({
        "user": _public_user(user),
        "csrfToken": session.csrf_token,
        "expiresAt": session.expires_at.isoformat(),
        "mfaRequired": mfa_required,
        "mfaVerified": bool(session.mfa_verified),
    })
    return _set_session_cookie(response, session, raw_token)


def _public_session(session: AuthSession, *, current: bool = False) -> dict[str, object]:
    return {
        "id": session.id,
        "createdAt": session.created_at.isoformat() if session.created_at else None,
        "lastSeenAt": (
            session.last_seen_at.isoformat() if session.last_seen_at else None
        ),
        "expiresAt": session.expires_at.isoformat() if session.expires_at else None,
        "revokedAt": session.revoked_at.isoformat() if session.revoked_at else None,
        "authMethod": session.auth_method,
        "mfaVerified": bool(session.mfa_verified),
        "ipAddress": session.ip_address,
        "userAgent": session.user_agent,
        "current": current,
    }


def configure_oidc(app) -> bool:
    app.config["AUTH_OIDC_READY"] = False
    if not app.config.get("AUTH_OIDC_ENABLED"):
        return False
    issuer = str(app.config.get("AUTH_OIDC_ISSUER", "")).strip()
    client_id = str(app.config.get("AUTH_OIDC_CLIENT_ID", "")).strip()
    client_secret = str(app.config.get("AUTH_OIDC_CLIENT_SECRET", "")).strip()
    if not issuer or not client_id or not client_secret:
        app.logger.warning(
            "OIDC is enabled but issuer/client credentials are incomplete"
        )
        return False
    oauth.init_app(app)
    oauth.register(
        name="oidc",
        server_metadata_url=f"{issuer}/.well-known/openid-configuration",
        client_id=client_id,
        client_secret=client_secret,
        client_kwargs={"scope": app.config.get("AUTH_OIDC_SCOPE")},
    )
    app.config["AUTH_OIDC_READY"] = True
    return True


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
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


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


def _register_failed_login(user: UserAccount | None, key: str) -> None:
    _record_failure(key)
    if user is None:
        return
    user.failed_login_count = int(user.failed_login_count or 0) + 1
    limit = max(1, int(current_app.config.get("AUTH_MAX_LOGIN_ATTEMPTS", 5)))
    if user.failed_login_count >= limit:
        user.locked_until = _now() + timedelta(
            seconds=max(60, int(current_app.config.get("AUTH_LOCKOUT_SECONDS", 900)))
        )
    db.session.commit()


def _required_role_for(method: str, path: str) -> str | None:
    if path == "/api/v1/auth/logout":
        return None
    if path.startswith("/api/v1/auth/users"):
        return "admin"
    if path.startswith("/api/v1/auth/mfa"):
        return None
    if path.startswith("/api/v1/auth/sessions"):
        return None
    if path == "/api/v1/auth/password":
        return None
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
            if (
                g.auth_session is not None
                and not g.auth_session.mfa_verified
                and (request.method, request.path) not in MFA_ALLOWED_ENDPOINTS
            ):
                return _error(
                    "mfa_required",
                    "Complete multi-factor authentication to continue.",
                    401,
                )
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
        "mfaEnabled": bool(user.mfa_enabled),
        "createdAt": user.created_at.isoformat() if user.created_at else None,
        "lastLoginAt": user.last_login_at.isoformat() if user.last_login_at else None,
    }


@auth.post("/auth/login")
def login():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _error("invalid_request", "A JSON object is required.", 400)
    if set(payload) - {"email", "password", "mfaCode"}:
        return _error(
            "invalid_request",
            "Only email, password, and mfaCode are accepted.",
            400,
        )
    try:
        email = _normalize_email(payload.get("email"))
        password = payload.get("password")
    except AuthError as error:
        return _error(error.code, str(error), error.status)
    key = f"{_session_ip() or 'unknown'}:{email}"
    if _rate_limited(key):
        _record_auth_event("login", "rate_limited", detail=email)
        return _error("rate_limited", "Too many sign-in attempts. Try again later.", 429)
    user = UserAccount.query.filter_by(email=email).first()
    now = _now()
    if user is not None and user.locked_until is not None and _aware(user.locked_until) > now:
        _record_auth_event("login", "locked", user=user)
        return _error("account_locked", "This account is temporarily locked.", 429)
    if (
        user is None
        or not user.active
        or not isinstance(password, str)
        or not check_password_hash(user.password_hash, password)
    ):
        _register_failed_login(user, key)
        _record_auth_event(
            "login", "invalid_credentials", user=user, detail=email
        )
        return _error("invalid_credentials", "Invalid email or password.", 401)
    _clear_failures(key)
    user.failed_login_count = 0
    user.locked_until = None
    db.session.commit()

    if user.mfa_enabled:
        code = payload.get("mfaCode")
        if code is None:
            session, raw_token = _create_session(
                user, auth_method="password", mfa_verified=False
            )
            _record_auth_event("login", "mfa_pending", user=user)
            return _session_response(
                user, session, raw_token, mfa_required=True
            )
        try:
            secret = decrypt_secret(user.mfa_secret or "", _mfa_key())
        except MfaError:
            _record_auth_event("login", "mfa_configuration_error", user=user)
            return _error(
                "mfa_unavailable",
                "MFA is not available for this account. Contact an administrator.",
                503,
            )
        if not verify_totp(secret, code):
            _register_failed_login(user, key)
            _record_auth_event("login", "invalid_mfa", user=user)
            return _error("invalid_mfa", "The authentication code is invalid.", 401)
        session, raw_token = _create_session(
            user, auth_method="password+mfa", mfa_verified=True
        )
        _record_auth_event("login", "success", user=user)
        return _session_response(user, session, raw_token)

    session, raw_token = _create_session(
        user, auth_method="password", mfa_verified=True
    )
    _record_auth_event("login", "success", user=user)
    return _session_response(user, session, raw_token)


@auth.get("/auth/session")
def session_info():
    principal = getattr(g, "principal", None)
    if principal is None:
        return _error("authentication_required", "Sign in to continue.", 401)
    session = getattr(g, "auth_session", None)
    user = db.session.get(UserAccount, principal.subject)
    return jsonify({
        "user": {
            "id": principal.subject,
            "email": principal.email,
            "role": principal.role,
            "tenantId": principal.tenant_id,
            "active": bool(user.active) if user else False,
            "mfaEnabled": bool(user.mfa_enabled) if user else False,
        },
        "csrfToken": session.csrf_token if session else "",
        "expiresAt": session.expires_at.isoformat() if session else None,
        "mfaVerified": bool(session.mfa_verified) if session else False,
        "authMethod": session.auth_method if session else None,
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


@auth.post("/auth/mfa/enroll")
def mfa_enroll():
    user = db.session.get(UserAccount, g.principal.subject)
    if user is None:
        return _error("user_not_found", "User was not found.", 404)
    if user.mfa_enabled:
        return _error(
            "mfa_already_enabled",
            "MFA is already enabled for this account.",
            409,
        )
    secret = generate_secret()
    try:
        user.mfa_pending_secret = encrypt_secret(secret, _mfa_key())
    except MfaError:
        return _error(
            "mfa_unavailable",
            "MFA is not configured correctly on this server.",
            503,
        )
    db.session.commit()
    _record_auth_event("mfa_enroll", "pending", user=user)
    return jsonify({
        "secret": secret,
        "otpauthUri": provisioning_uri(
            secret,
            email=user.email,
            issuer=str(current_app.config.get("AUTH_MFA_ISSUER", "ZeroTrace")),
        ),
        "issuer": current_app.config.get("AUTH_MFA_ISSUER", "ZeroTrace"),
    })


@auth.post("/auth/mfa/activate")
def mfa_activate():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or set(payload) - {"code"}:
        return _error("invalid_request", "A JSON object with code is required.", 400)
    user = db.session.get(UserAccount, g.principal.subject)
    if user is None:
        return _error("user_not_found", "User was not found.", 404)
    if user.mfa_enabled:
        return _error("mfa_already_enabled", "MFA is already enabled.", 409)
    if not user.mfa_pending_secret:
        return _error("mfa_not_started", "Start MFA enrollment first.", 409)
    try:
        secret = decrypt_secret(user.mfa_pending_secret, _mfa_key())
    except MfaError:
        return _error(
            "mfa_unavailable",
            "MFA is not configured correctly on this server.",
            503,
        )
    if not verify_totp(secret, payload.get("code")):
        _record_auth_event("mfa_activate", "invalid_code", user=user)
        return _error("invalid_mfa", "The authentication code is invalid.", 401)
    user.mfa_secret = user.mfa_pending_secret
    user.mfa_pending_secret = None
    user.mfa_enabled = True
    g.auth_session.mfa_verified = True
    db.session.commit()
    _record_auth_event("mfa_activate", "success", user=user)
    return jsonify({"mfaEnabled": True})


@auth.post("/auth/mfa/verify")
def mfa_verify():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or set(payload) - {"code"}:
        return _error("invalid_request", "A JSON object with code is required.", 400)
    session = getattr(g, "auth_session", None)
    if session is None:
        return _error("authentication_required", "Sign in to continue.", 401)
    user = db.session.get(UserAccount, session.user_id)
    if user is None or not user.mfa_enabled or not user.mfa_secret:
        return _error("mfa_not_enabled", "MFA is not enabled for this account.", 409)
    key = f"mfa:{user.id}"
    if _rate_limited(key):
        _record_auth_event("mfa_verify", "rate_limited", user=user)
        return _error("rate_limited", "Too many attempts. Try again later.", 429)
    try:
        secret = decrypt_secret(user.mfa_secret, _mfa_key())
    except MfaError:
        return _error(
            "mfa_unavailable",
            "MFA is not configured correctly on this server.",
            503,
        )
    if not verify_totp(secret, payload.get("code")):
        _record_failure(key)
        _record_auth_event("mfa_verify", "invalid_code", user=user)
        return _error("invalid_mfa", "The authentication code is invalid.", 401)
    _clear_failures(key)
    session.mfa_verified = True
    if not session.auth_method.endswith("+mfa"):
        session.auth_method = f"{session.auth_method}+mfa"[:32]
    db.session.commit()
    _record_auth_event("mfa_verify", "success", user=user)
    return jsonify({
        "ok": True,
        "mfaVerified": True,
        "csrfToken": session.csrf_token,
    })


@auth.post("/auth/password")
def change_password():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or set(payload) - {
        "currentPassword",
        "newPassword",
    }:
        return _error(
            "invalid_request",
            "currentPassword and newPassword are required.",
            400,
        )
    user = db.session.get(UserAccount, g.principal.subject)
    if user is None:
        return _error("user_not_found", "User was not found.", 404)
    current = payload.get("currentPassword")
    if not isinstance(current, str) or not check_password_hash(
        user.password_hash, current
    ):
        _record_auth_event("password_change", "invalid_current", user=user)
        return _error("invalid_credentials", "The current password is invalid.", 401)
    try:
        new_password = _validate_password(payload.get("newPassword"))
    except AuthError as error:
        return _error(error.code, str(error), error.status)
    if hmac.compare_digest(current, new_password):
        return _error(
            "password_unchanged", "The new password must be different.", 400
        )
    user.password_hash = generate_password_hash(new_password)
    user.password_changed_at = _now()
    user.failed_login_count = 0
    user.locked_until = None
    now = _now()
    for session in AuthSession.query.filter_by(
        user_id=user.id, revoked_at=None
    ).all():
        if session.id != g.auth_session.id:
            session.revoked_at = now
    db.session.commit()
    _record_auth_event("password_change", "success", user=user)
    return jsonify({"ok": True, "revokedOthers": True})


@auth.post("/auth/password-reset")
def reset_password():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or set(payload) - {"token", "password"}:
        return _error(
            "invalid_request", "token and password are required.", 400
        )
    token = payload.get("token")
    if not isinstance(token, str) or not 16 <= len(token) <= 256:
        return _error("invalid_reset_token", "The reset token is invalid.", 400)
    try:
        password = _validate_password(payload.get("password"))
    except AuthError as error:
        return _error(error.code, str(error), error.status)
    record = PasswordResetToken.query.filter_by(
        token_hash=_hash_token(token)
    ).first()
    now = _now()
    if (
        record is None
        or record.used_at is not None
        or _aware(record.expires_at) <= now
    ):
        return _error("invalid_reset_token", "The reset token is invalid.", 400)
    user = db.session.get(UserAccount, record.user_id)
    if user is None or not user.active:
        return _error("invalid_reset_token", "The reset token is invalid.", 400)
    user.password_hash = generate_password_hash(password)
    user.password_changed_at = now
    user.failed_login_count = 0
    user.locked_until = None
    record.used_at = now
    for session in AuthSession.query.filter_by(
        user_id=user.id, revoked_at=None
    ).all():
        session.revoked_at = now
    db.session.commit()
    _record_auth_event("password_reset", "success", user=user)
    return jsonify({"ok": True})


@auth.get("/auth/sessions")
def list_own_sessions():
    current = getattr(g, "auth_session", None)
    rows = AuthSession.query.filter_by(user_id=g.principal.subject).order_by(
        AuthSession.created_at.desc()
    ).all()
    return jsonify({
        "items": [
            _public_session(row, current=current is not None and row.id == current.id)
            for row in rows
        ],
        "currentSessionId": current.id if current else None,
    })


@auth.post("/auth/sessions/<session_id>/revoke")
def revoke_own_session(session_id: str):
    current = getattr(g, "auth_session", None)
    session = AuthSession.query.filter_by(
        id=session_id, user_id=g.principal.subject
    ).first()
    if session is None:
        return _error("session_not_found", "Session was not found.", 404)
    session.revoked_at = _now()
    db.session.commit()
    _record_auth_event("session_revoke", "success", detail=session_id)
    response = jsonify({"ok": True})
    if current is not None and current.id == session.id:
        response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@auth.get("/auth/users/<user_id>/sessions")
@role_required("admin")
def list_user_sessions(user_id: str):
    user = db.session.get(UserAccount, user_id)
    if user is None or user.tenant_id != g.principal.tenant_id:
        return _error("user_not_found", "User was not found.", 404)
    rows = AuthSession.query.filter_by(user_id=user.id).order_by(
        AuthSession.created_at.desc()
    ).all()
    return jsonify({"items": [_public_session(row) for row in rows]})


@auth.post("/auth/users/<user_id>/password-reset")
@role_required("admin")
def issue_password_reset(user_id: str):
    user = db.session.get(UserAccount, user_id)
    if user is None or user.tenant_id != g.principal.tenant_id:
        return _error("user_not_found", "User was not found.", 404)
    now = _now()
    for previous in PasswordResetToken.query.filter_by(
        user_id=user.id, used_at=None
    ).all():
        previous.used_at = now
    raw = secrets.token_urlsafe(32)
    expires_at = now + timedelta(
        seconds=max(
            300,
            int(current_app.config.get("AUTH_PASSWORD_RESET_TTL_SECONDS", 1800)),
        )
    )
    db.session.add(
        PasswordResetToken(
            id=f"prt_{uuid4().hex}",
            token_hash=_hash_token(raw),
            user_id=user.id,
            tenant_id=user.tenant_id,
            created_at=now,
            expires_at=expires_at,
        )
    )
    db.session.commit()
    _record_auth_event("password_reset_issue", "success", user=user)
    return jsonify({
        "token": raw,
        "expiresAt": expires_at.isoformat(),
        "userId": user.id,
    })


@auth.post("/auth/users/<user_id>/mfa/reset")
@role_required("admin")
def reset_user_mfa(user_id: str):
    user = db.session.get(UserAccount, user_id)
    if user is None or user.tenant_id != g.principal.tenant_id:
        return _error("user_not_found", "User was not found.", 404)
    user.mfa_enabled = False
    user.mfa_secret = None
    user.mfa_pending_secret = None
    now = _now()
    for session in AuthSession.query.filter_by(
        user_id=user.id, revoked_at=None
    ).all():
        session.revoked_at = now
    db.session.commit()
    _record_auth_event("mfa_reset", "success", user=user)
    return jsonify({"ok": True, "mfaEnabled": False})


@auth.get("/auth/oidc/login")
def oidc_login():
    if not current_app.config.get("AUTH_OIDC_READY"):
        return _error("oidc_disabled", "OIDC is not enabled.", 404)
    configured_path = str(
        current_app.config.get("AUTH_OIDC_REDIRECT_PATH", "")
    ).strip()
    redirect_uri = (
        f"{request.url_root.rstrip('/')}{configured_path}"
        if configured_path
        else url_for("auth.oidc_callback", _external=True)
    )
    return oauth.oidc.authorize_redirect(redirect_uri)


@auth.get("/auth/oidc/callback")
def oidc_callback():
    if not current_app.config.get("AUTH_OIDC_READY"):
        return _error("oidc_disabled", "OIDC is not enabled.", 404)
    try:
        token = oauth.oidc.authorize_access_token()
        userinfo = token.get("userinfo")
        if userinfo is None:
            userinfo = oauth.oidc.userinfo()
    except Exception:
        current_app.logger.exception("OIDC callback failed")
        return _error("oidc_failed", "The identity provider rejected the sign-in.", 401)
    issuer = str(userinfo.get("iss") or current_app.config.get("AUTH_OIDC_ISSUER"))
    subject = str(userinfo.get("sub") or "")
    email_value = userinfo.get("email")
    if not issuer or not subject:
        return _error("oidc_failed", "The identity provider response is incomplete.", 401)
    identity = OidcIdentity.query.filter_by(
        issuer=issuer, subject=subject
    ).first()
    if identity is not None:
        user = db.session.get(UserAccount, identity.user_id)
    else:
        email = ""
        if isinstance(email_value, str):
            try:
                email = _normalize_email(email_value)
            except AuthError:
                email = ""
        user = (
            UserAccount.query.filter_by(email=email).first()
            if email
            else None
        )
        if user is None and current_app.config.get("AUTH_OIDC_AUTO_PROVISION"):
            if not email:
                return _error(
                    "oidc_failed",
                    "The identity provider did not return an email address.",
                    403,
                )
            try:
                user = create_user(
                    email=email,
                    password=secrets.token_urlsafe(48),
                    role=str(
                        current_app.config.get("AUTH_OIDC_DEFAULT_ROLE", "viewer")
                    ),
                    tenant_id=str(
                        current_app.config.get("AUTH_OIDC_TENANT", "tenant_local")
                    ),
                    active=True,
                )
            except AuthError as error:
                return _error(error.code, str(error), error.status)
        if user is None:
            _record_auth_event(
                "oidc_login", "user_not_found", detail=email or subject
            )
            return _error(
                "oidc_user_not_found",
                "No ZeroTrace account is linked to this identity.",
                403,
            )
        db.session.add(
            OidcIdentity(
                id=f"oid_{uuid4().hex}",
                issuer=issuer[:512],
                subject=subject[:255],
                user_id=user.id,
                tenant_id=user.tenant_id,
                email=email or None,
            )
        )
        db.session.commit()
    if user is None or not user.active:
        _record_auth_event("oidc_login", "inactive", user=user)
        return _error("account_inactive", "This account is not active.", 403)
    session, raw_token = _create_session(
        user,
        auth_method="oidc",
        mfa_verified=not user.mfa_enabled,
    )
    _record_auth_event(
        "oidc_login",
        "mfa_pending" if user.mfa_enabled else "success",
        user=user,
    )
    target = "/" if not user.mfa_enabled else "/?mfa=required"
    response = redirect(target)
    return _set_session_cookie(response, session, raw_token)


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
