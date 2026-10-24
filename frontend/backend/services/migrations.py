"""Small, idempotent compatibility migrations for local demo databases."""

from __future__ import annotations

from sqlalchemy import inspect, text
from sqlalchemy.exc import OperationalError

from ..extensions import db

IDENTITY_COLUMNS = {
    "user_accounts": (
        ("password_changed_at", "DATETIME"),
        ("failed_login_count", "INTEGER NOT NULL DEFAULT 0"),
        ("locked_until", "DATETIME"),
        ("mfa_enabled", "BOOLEAN NOT NULL DEFAULT 0"),
        ("mfa_secret", "VARCHAR(512)"),
        ("mfa_pending_secret", "VARCHAR(512)"),
    ),
    "auth_sessions": (
        ("auth_method", "VARCHAR(32) NOT NULL DEFAULT 'password'"),
        ("mfa_verified", "BOOLEAN NOT NULL DEFAULT 1"),
        ("ip_address", "VARCHAR(64)"),
        ("user_agent", "VARCHAR(512)"),
    ),
}


def migrate_identity_columns() -> bool:
    """Add identity-hardening columns to an existing local SQLite database."""

    if db.engine.dialect.name != "sqlite":
        return False
    inspector = inspect(db.engine)
    tables = set(inspector.get_table_names())
    changed = False
    for table, columns in IDENTITY_COLUMNS.items():
        if table not in tables:
            continue
        existing = {column["name"] for column in inspector.get_columns(table)}
        for name, definition in columns:
            if name in existing:
                continue
            try:
                db.session.execute(
                    text(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
                )
            except OperationalError as error:
                db.session.rollback()
                if "duplicate column" not in str(error).lower():
                    raise
                continue
            changed = True
    if changed:
        db.session.commit()
    return changed


LEGACY_EVENT_COLUMNS = (
    "id",
    "event_type",
    "entity_type",
    "entity_id",
    "source",
    "correlation_id",
    "schema_version",
    "payload",
    "occurred_at",
    "status",
    "attempts",
    "redis_entry_id",
    "last_error",
    "published_at",
)


def migrate_legacy_event_outbox() -> bool:
    """Copy the old ``event_outbox`` rows into the demo-specific table.

    The root application already owns a table named ``event_outbox`` in the
    shared PostgreSQL database. The BFF now uses ``demo_event_outbox`` so the
    two schema families can share a database without touching each other. An
    old SQLite demo database is migrated in place when its columns match.
    """

    if db.engine.dialect.name != "sqlite":
        return False
    inspector = inspect(db.engine)
    tables = set(inspector.get_table_names())
    if "event_outbox" not in tables or "demo_event_outbox" not in tables:
        return False
    legacy_columns = {column["name"] for column in inspector.get_columns("event_outbox")}
    if not set(LEGACY_EVENT_COLUMNS).issubset(legacy_columns):
        return False
    existing = db.session.execute(
        text("SELECT COUNT(*) FROM demo_event_outbox")
    ).scalar_one()
    if int(existing) > 0:
        return False
    columns = ", ".join(LEGACY_EVENT_COLUMNS)
    db.session.execute(
        text(
            f"INSERT INTO demo_event_outbox ({columns}) "
            f"SELECT {columns} FROM event_outbox"
        )
    )
    db.session.commit()
    return True
