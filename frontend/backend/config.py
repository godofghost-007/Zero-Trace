import os
from pathlib import Path

from .env import env_or_file

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = Path(os.environ.get("ZEROTRACE_DATA_DIR", PROJECT_ROOT / "instance")).expanduser()
DATABASE_URL = env_or_file(
    "DATABASE_URL", f"sqlite:///{DATA_DIR / 'zerotrace.db'}"
)
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://") and "+" not in DATABASE_URL.split(":", 1)[0]:
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)


class Config:
    ENVIRONMENT = os.environ.get("ZEROTRACE_ENV", "development").strip().lower()
    SECRET_KEY = env_or_file(
        "FLASK_SECRET_KEY", "local-demo-only-not-for-production"
    )
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}
    REDIS_URL = os.environ.get("REDIS_URL", "")
    REDIS_STREAM = os.environ.get("REDIS_STREAM", "zerotrace:events")
    DATA_DIR = DATA_DIR
    AUDIT_DB_PATH = Path(os.environ.get("AUDIT_DB_PATH", DATA_DIR / "guard-audit.sqlite")).expanduser()
    FRONTEND_DIST = Path(os.environ.get("FRONTEND_DIST", PROJECT_ROOT / "dist" / "public")).expanduser()
    ENGINE_SETTINGS_PATH = (
        Path(os.environ["ENGINE_SETTINGS_PATH"]).expanduser()
        if os.environ.get("ENGINE_SETTINGS_PATH")
        else None
    )
    AUTO_CREATE_SCHEMA = os.environ.get("AUTO_CREATE_SCHEMA", "true").lower() == "true"
    DEMO_MODE = os.environ.get("DEMO_MODE", "true").lower() == "true"
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024
    AUTH_REQUIRED = os.environ.get("ZEROTRACE_AUTH_REQUIRED", "true").lower() == "true"
    AUTH_SESSION_TTL_SECONDS = int(os.environ.get("ZEROTRACE_SESSION_TTL_SECONDS", "28800"))
    AUTH_IDLE_TIMEOUT_SECONDS = int(
        os.environ.get("ZEROTRACE_IDLE_TIMEOUT_SECONDS", "1800")
    )
    AUTH_COOKIE_SECURE = os.environ.get("ZEROTRACE_COOKIE_SECURE", "false").lower() == "true"
    AUTH_MAX_LOGIN_ATTEMPTS = int(os.environ.get("ZEROTRACE_MAX_LOGIN_ATTEMPTS", "5"))
    AUTH_LOGIN_WINDOW_SECONDS = int(os.environ.get("ZEROTRACE_LOGIN_WINDOW_SECONDS", "300"))
    AUTH_BOOTSTRAP_EMAIL = os.environ.get("ZEROTRACE_BOOTSTRAP_EMAIL", "")
    AUTH_BOOTSTRAP_PASSWORD = env_or_file("ZEROTRACE_BOOTSTRAP_PASSWORD", "")
    AUTH_BOOTSTRAP_ROLE = os.environ.get("ZEROTRACE_BOOTSTRAP_ROLE", "admin")
    AUTH_BOOTSTRAP_TENANT = os.environ.get("ZEROTRACE_BOOTSTRAP_TENANT", "tenant_local")
    AUTH_MFA_ISSUER = os.environ.get("ZEROTRACE_MFA_ISSUER", "ZeroTrace")
    AUTH_MFA_ENCRYPTION_KEY = env_or_file("ZEROTRACE_MFA_ENCRYPTION_KEY", "")
    AUTH_MFA_REQUIRED = (
        os.environ.get("ZEROTRACE_MFA_REQUIRED", "false").lower() == "true"
    )
    AUTH_PASSWORD_RESET_TTL_SECONDS = int(
        os.environ.get("ZEROTRACE_PASSWORD_RESET_TTL_SECONDS", "1800")
    )
    AUTH_LOCKOUT_SECONDS = int(os.environ.get("ZEROTRACE_LOCKOUT_SECONDS", "900"))
    AUTH_OIDC_ENABLED = os.environ.get("ZEROTRACE_OIDC_ENABLED", "false").lower() == "true"
    AUTH_OIDC_ISSUER = os.environ.get("ZEROTRACE_OIDC_ISSUER", "").rstrip("/")
    AUTH_OIDC_CLIENT_ID = os.environ.get("ZEROTRACE_OIDC_CLIENT_ID", "")
    AUTH_OIDC_CLIENT_SECRET = env_or_file("ZEROTRACE_OIDC_CLIENT_SECRET", "")
    AUTH_OIDC_SCOPE = os.environ.get("ZEROTRACE_OIDC_SCOPE", "openid email profile")
    AUTH_OIDC_AUTO_PROVISION = (
        os.environ.get("ZEROTRACE_OIDC_AUTO_PROVISION", "false").lower() == "true"
    )
    AUTH_OIDC_DEFAULT_ROLE = os.environ.get("ZEROTRACE_OIDC_DEFAULT_ROLE", "viewer")
    AUTH_OIDC_TENANT = os.environ.get("ZEROTRACE_OIDC_TENANT", "tenant_local")
    AUTH_OIDC_REDIRECT_PATH = os.environ.get(
        "ZEROTRACE_OIDC_REDIRECT_PATH", "/api/v1/auth/oidc/callback"
    )
    TRUST_PROXY = os.environ.get("ZEROTRACE_TRUST_PROXY", "false").lower() == "true"
    LOG_LEVEL = os.environ.get("ZEROTRACE_LOG_LEVEL", "INFO")
    LOG_FORMAT = os.environ.get("ZEROTRACE_LOG_FORMAT", "text").lower()
    METRICS_ENABLED = os.environ.get("ZEROTRACE_METRICS_ENABLED", "false").lower() == "true"
    METRICS_TOKEN = env_or_file("ZEROTRACE_METRICS_TOKEN", "")
    GUARD_PROXY_ENABLED = (
        os.environ.get("ZEROTRACE_GUARD_PROXY_ENABLED", "false").lower() == "true"
    )
    GUARD_PROXY_URL = os.environ.get(
        "ZEROTRACE_GUARD_PROXY_URL", "http://127.0.0.1:8766"
    ).strip()
    GUARD_BFF_API_KEY = env_or_file("ZEROTRACE_GUARD_BFF_API_KEY", "")
    GUARD_PROXY_TIMEOUT_SECONDS = float(
        os.environ.get("ZEROTRACE_GUARD_PROXY_TIMEOUT_SECONDS", "30")
    )
    ENGINE_URL = os.environ.get(
        "ZEROTRACE_ENGINE_URL",
        os.environ.get("ZEROTRACE_ENGINE_BASE_URL", "http://127.0.0.1:8765"),
    )
    ENGINE_API_KEY = env_or_file("ZEROTRACE_ENGINE_API_KEY", "")
