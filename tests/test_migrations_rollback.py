"""Opt-in proof that the live-runtime migration can be applied and rolled back.

Set ``ZEROTRACE_TEST_DATABASE_URL`` to a PostgreSQL database whose user can
create databases. Each run uses a disposable database and drops it afterwards.
"""

from __future__ import annotations

import os
import secrets
import time
from urllib.parse import urlsplit, urlunsplit

import psycopg
import pytest

from scripts.run_migrations import apply, rollback_latest

TEST_DATABASE_URL = os.environ.get("ZEROTRACE_TEST_DATABASE_URL", "").strip()

pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="ZEROTRACE_TEST_DATABASE_URL is not configured",
)


def _database_urls(raw: str, database: str) -> tuple[str, str]:
    plain = raw.replace("postgresql+psycopg://", "postgresql://", 1)
    parts = urlsplit(plain)
    admin = urlunsplit(parts._replace(path="/postgres"))
    target = urlunsplit(parts._replace(path=f"/{database}"))
    return admin, target


def _connect(url: str, **kwargs):
    """Retry transient Docker Desktop port-proxy failures."""
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            return psycopg.connect(url, connect_timeout=10, **kwargs)
        except psycopg.OperationalError as error:
            last_error = error
            if attempt < 2:
                time.sleep(0.5 * (attempt + 1))
    assert last_error is not None
    raise last_error


def test_live_runtime_migration_rolls_back_and_reapplies():
    database = f"zerotrace_migration_test_{secrets.token_hex(5)}"
    admin_url, target_url = _database_urls(TEST_DATABASE_URL, database)
    with _connect(admin_url, autocommit=True) as connection:
        connection.execute(f'CREATE DATABASE "{database}"')
    try:
        apply(target_url)
        with _connect(target_url) as connection:
            assert connection.execute(
                "SELECT to_regclass('public.live_scopes')"
            ).fetchone()[0] == "live_scopes"
            assert connection.execute(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = %s",
                ("0007_live_runtime",),
            ).fetchone()[0] == 1

        assert rollback_latest(target_url) == "0008_identity_hardening"
        assert rollback_latest(target_url) == "0007_live_runtime"

        with _connect(target_url) as connection:
            assert connection.execute(
                "SELECT to_regclass('public.live_scopes')"
            ).fetchone()[0] is None
            assert connection.execute(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = %s",
                ("0007_live_runtime",),
            ).fetchone()[0] == 0

        apply(target_url)
        with _connect(target_url) as connection:
            assert connection.execute(
                "SELECT to_regclass('public.live_scopes')"
            ).fetchone()[0] == "live_scopes"
    finally:
        with _connect(admin_url, autocommit=True) as connection:
            connection.execute(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)')
