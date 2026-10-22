"""Small, idempotent compatibility migrations for local demo databases."""

from __future__ import annotations

from sqlalchemy import inspect, text

from ..extensions import db

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
