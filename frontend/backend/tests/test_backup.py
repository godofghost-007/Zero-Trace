from contextlib import closing
import sqlite3

import pytest

from datetime import datetime, timedelta, timezone
import os

from backend.services.backup import (
    BackupError,
    backup_sqlite,
    decrypt_backup,
    encrypt_backup,
    encrypted_manifest_path,
    generate_key,
    prune_backups,
    restore_sqlite,
    verify_backup,
    verify_encrypted_backup,
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


def test_encrypted_backup_round_trip_and_restore(tmp_path):
    source = tmp_path / "state.sqlite3"
    plaintext = tmp_path / "state.sqlite3.bak"
    encrypted = tmp_path / "state.sqlite3.ztb"
    make_database(source, "encrypted-before")
    backup_sqlite(source, plaintext)
    key = generate_key()

    outer = encrypt_backup(plaintext, encrypted, key)
    assert outer["encryption"] == "fernet"
    assert verify_encrypted_backup(encrypted)["sha256"] == outer["sha256"]
    assert encrypted_manifest_path(encrypted).is_file()

    decrypted = decrypt_backup(encrypted, tmp_path / "decrypted", key)
    assert (
        verify_backup(decrypted["backup"])["sha256"]
        == verify_backup(plaintext)["sha256"]
    )
    make_database(source, "encrypted-after")
    restore_sqlite(decrypted["backup"], source)
    with sqlite3.connect(source) as connection:
        assert connection.execute("SELECT value FROM items").fetchone()[0] == "encrypted-before"


def test_encrypted_backup_rejects_tampering_and_wrong_key(tmp_path):
    source = tmp_path / "state.sqlite3"
    plaintext = tmp_path / "state.sqlite3.bak"
    encrypted = tmp_path / "state.sqlite3.ztb"
    make_database(source, "before")
    backup_sqlite(source, plaintext)
    key = generate_key()
    encrypt_backup(plaintext, encrypted, key)

    encrypted.write_bytes(encrypted.read_bytes() + b"tamper")
    with pytest.raises(BackupError, match="size|checksum"):
        verify_encrypted_backup(encrypted)

    encrypted.unlink()
    encrypted_manifest_path(encrypted).unlink()
    encrypt_backup(plaintext, encrypted, key)
    with pytest.raises(BackupError, match="decrypt"):
        decrypt_backup(encrypted, tmp_path / "wrong", generate_key())


def test_prune_keeps_minimum_and_deletes_old_backups(tmp_path):
    now = datetime(2026, 10, 25, tzinfo=timezone.utc)
    for index, age in enumerate((40, 20, 1)):
        path = tmp_path / f"backup-{index}.ztb"
        path.write_bytes(b"encrypted")
        timestamp = (now - timedelta(days=age)).timestamp()
        os.utime(path, (timestamp, timestamp))
        encrypted_manifest_path(path).write_text("{}", encoding="utf-8")

    deleted = prune_backups(
        tmp_path, retain_days=30, keep_minimum=1, now=now
    )
    assert str(tmp_path / "backup-0.ztb") in deleted
    assert (tmp_path / "backup-1.ztb").exists()
    assert (tmp_path / "backup-2.ztb").exists()
    assert not encrypted_manifest_path(tmp_path / "backup-0.ztb").exists()
