from datetime import datetime, timedelta, timezone

from app.live_store import LiveStore
from scripts.prune_runtime_data import prune_sqlite


def test_retention_prunes_only_old_operational_rows(tmp_path):
    path = tmp_path / "live.sqlite3"
    store = LiveStore(path)
    now = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)
    old = (now - timedelta(days=45)).strftime("%Y-%m-%d %H:%M:%S")
    recent = (now - timedelta(days=5)).strftime("%Y-%m-%d %H:%M:%S")
    with store._session() as connection:
        connection.execute(
            """
            INSERT INTO live_scans
                (scan_id, scope_id, target, profile_id, state, updated_at)
            VALUES
                ('old', 'scope', 'lab.example.test', 'synthetic', 'completed', ?),
                ('recent', 'scope', 'lab.example.test', 'synthetic', 'completed', ?)
            """,
            (old, recent),
        )
        connection.execute(
            "INSERT INTO live_guard_events (created_at, blocked, reason, pii_blocked) "
            "VALUES (?, 0, NULL, 0)",
            (old,),
        )
        connection.execute(
            "INSERT INTO live_guard_events (created_at, blocked, reason, pii_blocked) "
            "VALUES (?, 0, NULL, 0)",
            (recent,),
        )
        connection.execute(
            "INSERT INTO live_readiness_snapshots (created_at, payload) VALUES (?, '{}')",
            (old,),
        )
        connection.execute(
            "INSERT INTO live_scan_schedules "
            "(schedule_id, owner_id, scope_id, target, profile_id, interval_seconds, "
            " enabled, next_run_at, created_at, last_run_at, runs) "
            "VALUES ('disabled-old', 'operator', 'scope', 'lab.example.test', "
            "'synthetic', 300, 0, ?, ?, ?, 1)",
            (recent, old, old),
        )

    dry = prune_sqlite(path, days=30, dry_run=True, now=now)
    assert dry == {
        "scans": 1,
        "guard_events": 1,
        "readiness_snapshots": 1,
        "disabled_schedules": 1,
    }
    with store._session() as connection:
        assert connection.execute("SELECT COUNT(*) FROM live_scans").fetchone()[0] == 2

    applied = prune_sqlite(path, days=30, dry_run=False, now=now)
    assert applied == dry
    with store._session() as connection:
        scans = {
            row["scan_id"]
            for row in connection.execute("SELECT scan_id FROM live_scans")
        }
        assert scans == {"recent"}
        assert (
            connection.execute("SELECT COUNT(*) FROM live_guard_events").fetchone()[0]
            == 1
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM live_scan_schedules"
            ).fetchone()[0]
            == 0
        )
