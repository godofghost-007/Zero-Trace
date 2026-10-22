from contextlib import closing
import sqlite3

import pytest

from backend.services.backup import (
    BackupError,
    backup_sqlite,
    restore_sqlite,
    verify_backup,
)


def make_database(path, value):
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
        connection.execute("DELETE FROM items")
        connection.execute("INSERT INTO items (value) VALUES (?)", (value,))
        connection.commit()


def test_sqlite_backup_manifest_and_restore_round_trip(tmp_path):
    source = tmp_path / "state.sqlite3"
    backup = tmp_path / "backups" / "state.sqlite3"
    make_database(source, "before")

    manifest = backup_sqlite(source, backup)
    assert manifest["kind"] == "sqlite"
    assert verify_backup(backup)["sha256"] == manifest["sha256"]

    make_database(source, "after")
    result = restore_sqlite(backup, source)
    assert result["preRestore"]
    with sqlite3.connect(source) as connection:
        assert connection.execute("SELECT value FROM items").fetchone()[0] == "before"


def test_tampered_backup_is_rejected(tmp_path):
    source = tmp_path / "state.sqlite3"
    backup = tmp_path / "state.sqlite3.bak"
    make_database(source, "before")
    backup_sqlite(source, backup)
    backup.write_bytes(backup.read_bytes() + b"tamper")

    with pytest.raises(BackupError, match="size|checksum"):
        verify_backup(backup)
    with pytest.raises(BackupError):
        restore_sqlite(backup, source)


def test_restore_removes_stale_sqlite_sidecars(tmp_path):
    source = tmp_path / "state.sqlite3"
    backup = tmp_path / "state.sqlite3.bak"
    make_database(source, "before")
    backup_sqlite(source, backup)
    make_database(source, "after")
    wal = tmp_path / "state.sqlite3-wal"
    shm = tmp_path / "state.sqlite3-shm"
    wal.write_bytes(b"stale")
    shm.write_bytes(b"stale")

    restore_sqlite(backup, source)

    assert not wal.exists()
    assert not shm.exists()
    with sqlite3.connect(source) as connection:
        assert connection.execute("SELECT value FROM items").fetchone()[0] == "before"


def test_backup_refuses_to_overwrite_unless_requested(tmp_path):
    source = tmp_path / "state.sqlite3"
    backup = tmp_path / "state.sqlite3.bak"
    make_database(source, "before")
    backup_sqlite(source, backup)

    with pytest.raises(BackupError, match="already exists"):
        backup_sqlite(source, backup)
    assert backup_sqlite(source, backup, overwrite=True)["bytes"] > 0
