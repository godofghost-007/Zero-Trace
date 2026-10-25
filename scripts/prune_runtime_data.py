"""Retention pruning for bounded live-engine runtime data.

The audit chain is intentionally *not* touched here. Audit records are retained
as an immutable evidence trail and are handled by encrypted archive rotation,
not by deleting rows from the middle of a hash chain.

This command removes only operational projections that can be regenerated or
re-collected:

* terminal ``live_scans`` older than the retention window;
* Guard inspection counters older than the retention window;
* readiness snapshots older than the retention window;
* disabled scan schedules whose last run is older than the retention window.

It supports a dry run so an operator can inspect the counts before deleting.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sqlite3
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

TERMINAL_SCAN_STATES = (
    "completed",
    "partial",
    "cancelled",
    "timed_out",
    "failed",
)


def _cutoff(days: int, now: datetime | None = None) -> datetime:
    if days < 1:
        raise ValueError("retention days must be at least 1")
    current = now or datetime.now(timezone.utc)
    return current - timedelta(days=days)


def prune_sqlite(
    path: Path,
    *,
    days: int = 30,
    dry_run: bool = True,
    now: datetime | None = None,
) -> dict[str, int]:
    cutoff = _cutoff(days, now)
    cutoff_sql = cutoff.strftime("%Y-%m-%d %H:%M:%S")
    counts: dict[str, int] = {}
    connection = sqlite3.connect(path, timeout=10)
    try:
        connection.row_factory = sqlite3.Row
        statements = {
            "scans": (
                "SELECT COUNT(*) FROM live_scans "
                "WHERE state IN ({}) AND datetime(updated_at) < datetime(?)".format(
                    ",".join("?" for _ in TERMINAL_SCAN_STATES)
                ),
                (
                    "DELETE FROM live_scans "
                    "WHERE state IN ({}) AND datetime(updated_at) < datetime(?)".format(
                        ",".join("?" for _ in TERMINAL_SCAN_STATES)
                    )
                ),
            ),
            "guard_events": (
                "SELECT COUNT(*) FROM live_guard_events "
                "WHERE datetime(created_at) < datetime(?)",
                "DELETE FROM live_guard_events "
                "WHERE datetime(created_at) < datetime(?)",
            ),
            "readiness_snapshots": (
                "SELECT COUNT(*) FROM live_readiness_snapshots "
                "WHERE datetime(created_at) < datetime(?)",
                "DELETE FROM live_readiness_snapshots "
                "WHERE datetime(created_at) < datetime(?)",
            ),
            "disabled_schedules": (
                "SELECT COUNT(*) FROM live_scan_schedules "
                "WHERE enabled = 0 AND last_run_at IS NOT NULL "
                "AND datetime(last_run_at) < datetime(?)",
                "DELETE FROM live_scan_schedules "
                "WHERE enabled = 0 AND last_run_at IS NOT NULL "
                "AND datetime(last_run_at) < datetime(?)",
            ),
        }
        for name, (count_sql, delete_sql) in statements.items():
            if name == "scans":
                count = connection.execute(
                    count_sql, (*TERMINAL_SCAN_STATES, cutoff_sql)
                ).fetchone()[0]
            else:
                count = connection.execute(count_sql, (cutoff_sql,)).fetchone()[0]
            counts[name] = int(count)
            if not dry_run and count:
                if name == "scans":
                    connection.execute(
                        delete_sql, (*TERMINAL_SCAN_STATES, cutoff_sql)
                    )
                else:
                    connection.execute(delete_sql, (cutoff_sql,))
        if not dry_run:
            connection.commit()
    finally:
        connection.close()
    return counts


def prune_postgres(
    database_url: str,
    *,
    days: int = 30,
    dry_run: bool = True,
    now: datetime | None = None,
) -> dict[str, int]:
    import psycopg

    cutoff = _cutoff(days, now)
    normalized = database_url.replace(
        "postgresql+psycopg://", "postgresql://", 1
    )
    counts: dict[str, int] = {}
    with psycopg.connect(normalized, connect_timeout=10) as connection:
        with connection.cursor() as cursor:
            queries = {
                "scans": (
                    "SELECT COUNT(*) FROM live_scans "
                    "WHERE state = ANY(%s) AND updated_at < %s",
                    "DELETE FROM live_scans "
                    "WHERE state = ANY(%s) AND updated_at < %s",
                    (list(TERMINAL_SCAN_STATES), cutoff),
                ),
                "guard_events": (
                    "SELECT COUNT(*) FROM live_guard_events WHERE created_at < %s",
                    "DELETE FROM live_guard_events WHERE created_at < %s",
                    (cutoff,),
                ),
                "readiness_snapshots": (
                    "SELECT COUNT(*) FROM live_readiness_snapshots "
                    "WHERE created_at < %s",
                    "DELETE FROM live_readiness_snapshots WHERE created_at < %s",
                    (cutoff,),
                ),
                "disabled_schedules": (
                    "SELECT COUNT(*) FROM live_scan_schedules "
                    "WHERE enabled = FALSE AND last_run_at IS NOT NULL "
                    "AND last_run_at < %s",
                    "DELETE FROM live_scan_schedules "
                    "WHERE enabled = FALSE AND last_run_at IS NOT NULL "
                    "AND last_run_at < %s",
                    (cutoff,),
                ),
            }
            for name, (count_sql, delete_sql, params) in queries.items():
                cursor.execute(count_sql, params)
                count = int(cursor.fetchone()[0])
                counts[name] = count
                if not dry_run and count:
                    cursor.execute(delete_sql, params)
        if not dry_run:
            connection.commit()
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--sqlite-path", type=Path)
    source.add_argument("--database-url")
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Delete rows. Without this flag the command is a dry run.",
    )
    args = parser.parse_args()
    try:
        if args.sqlite_path:
            counts = prune_sqlite(
                args.sqlite_path, days=args.days, dry_run=not args.apply
            )
        else:
            counts = prune_postgres(
                args.database_url or os.environ.get("DATABASE_URL", ""),
                days=args.days,
                dry_run=not args.apply,
            )
    except Exception as error:
        print(f"retention prune failed: {error}", file=sys.stderr)
        return 1
    mode = "deleted" if args.apply else "would delete"
    print(f"{mode}: {counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
