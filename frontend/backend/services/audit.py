import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=5, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_entries (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            action TEXT NOT NULL,
            outcome TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            finding_id TEXT NOT NULL,
            correlation_id TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            row_hash TEXT NOT NULL
        )
        """
    )
    return connection


def _canonical(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def append_entry(path: Path, record: dict[str, Any]) -> dict[str, Any]:
    connection = _connect(path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        existing = connection.execute(
            "SELECT * FROM audit_entries WHERE event_id = ?", (record["event_id"],)
        ).fetchone()
        if existing:
            connection.commit()
            return dict(existing)
        previous = connection.execute(
            "SELECT row_hash FROM audit_entries ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = previous["row_hash"] if previous else "0" * 64
        digest = hashlib.sha256(f"{previous_hash}|{_canonical(record)}".encode("utf-8")).hexdigest()
        cursor = connection.execute(
            """INSERT INTO audit_entries
               (event_id, action, outcome, asset_id, finding_id, correlation_id,
                occurred_at, previous_hash, row_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                record["event_id"], record["action"], record["outcome"],
                record["asset_id"], record["finding_id"], record["correlation_id"],
                record["occurred_at"], previous_hash, digest,
            ),
        )
        row = connection.execute(
            "SELECT * FROM audit_entries WHERE sequence = ?", (cursor.lastrowid,)
        ).fetchone()
        connection.commit()
        return dict(row)
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def verify_chain(path: Path) -> dict[str, Any]:
    connection = _connect(path)
    try:
        rows = connection.execute("SELECT * FROM audit_entries ORDER BY sequence ASC").fetchall()
    finally:
        connection.close()
    previous_hash = "0" * 64
    for expected_sequence, row in enumerate(rows, start=1):
        item = dict(row)
        record = {
            "event_id": item["event_id"],
            "action": item["action"],
            "outcome": item["outcome"],
            "asset_id": item["asset_id"],
            "finding_id": item["finding_id"],
            "correlation_id": item["correlation_id"],
            "occurred_at": item["occurred_at"],
        }
        expected_hash = hashlib.sha256(
            f"{previous_hash}|{_canonical(record)}".encode("utf-8")
        ).hexdigest()
        if item["sequence"] != expected_sequence or item["previous_hash"] != previous_hash or item["row_hash"] != expected_hash:
            return {"valid": False, "entries": len(rows), "broken_at": item["sequence"], "last_hash": previous_hash}
        previous_hash = item["row_hash"]
    return {"valid": True, "entries": len(rows), "broken_at": None, "last_hash": previous_hash}


def list_entries(path: Path) -> list[dict[str, Any]]:
    connection = _connect(path)
    try:
        rows = connection.execute("SELECT * FROM audit_entries ORDER BY sequence ASC").fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def reset_demo_chain(path: Path) -> None:
    connection = _connect(path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("DELETE FROM audit_entries")
        connection.execute("DELETE FROM sqlite_sequence WHERE name = 'audit_entries'")
        connection.commit()
    finally:
        connection.close()
