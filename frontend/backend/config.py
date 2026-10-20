import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = Path(os.environ.get("ZEROTRACE_DATA_DIR", PROJECT_ROOT / "instance")).expanduser()
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{DATA_DIR / 'zerotrace.db'}")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://") and "+" not in DATABASE_URL.split(":", 1)[0]:
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)


class Config:
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "local-demo-only-not-for-production")
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
