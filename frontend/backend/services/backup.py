"""Verified SQLite and PostgreSQL backup/restore helpers.

SQLite backups use the online backup API so a WAL-backed database is copied
consistently. PostgreSQL backups use the matching ``pg_dump``/``pg_restore``
inside the Compose container, so no host client installation is required.
Every backup gets a SHA-256 manifest and restore verifies it before replacing
live state. A pre-restore copy is retained for rollback.
"""

from __future__ import annotations

from base64 import b64decode, b64encode
from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
from typing import Any

from cryptography.fernet import Fernet, InvalidToken


class BackupError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def manifest_path(backup: Path) -> Path:
    return backup.with_name(f"{backup.name}.manifest.json")


def _write_manifest(backup: Path, *, kind: str, source: str) -> dict[str, Any]:
    manifest = {
        "format": "zerotrace-backup-v1",
        "kind": kind,
        "source": source,
        "createdAt": _now(),
        "bytes": backup.stat().st_size,
        "sha256": _digest(backup),
        "file": backup.name,
    }
    manifest_path(backup).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def read_manifest(backup: Path) -> dict[str, Any]:
    path = manifest_path(backup)
    if not path.is_file():
        raise BackupError("backup manifest is missing")
    try:
        manifest = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError) as error:
        raise BackupError("backup manifest is invalid") from error
    if not isinstance(manifest, dict) or manifest.get("format") != "zerotrace-backup-v1":
        raise BackupError("backup manifest is not supported")
    return manifest


def verify_backup(backup: Path) -> dict[str, Any]:
    if not backup.is_file():
        raise BackupError("backup file is missing")
    manifest = read_manifest(backup)
    if int(manifest.get("bytes", -1)) != backup.stat().st_size:
        raise BackupError("backup size does not match its manifest")
    if str(manifest.get("sha256")) != _digest(backup):
        raise BackupError("backup checksum does not match its manifest")
    return manifest


def backup_sqlite(source: str | Path, target: str | Path, *, overwrite: bool = False) -> dict[str, Any]:
    source_path = Path(source)
    target_path = Path(target)
    if not source_path.is_file():
        raise BackupError("SQLite source database is missing")
    if target_path.exists() and not overwrite:
        raise BackupError("backup target already exists")
    target_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = target_path.with_name(f".{target_path.name}.{os.getpid()}.tmp")
    try:
        with closing(sqlite3.connect(source_path)) as source_db, closing(
            sqlite3.connect(temporary)
        ) as target_db:
            source_db.backup(target_db)
            target_db.commit()
        _sqlite_integrity(temporary)
        os.replace(temporary, target_path)
        return _write_manifest(target_path, kind="sqlite", source=str(source_path))
    finally:
        if temporary.exists():
            temporary.unlink(missing_ok=True)


def _sqlite_integrity(path: Path) -> None:
    try:
        with closing(
            sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        ) as connection:
            row = connection.execute("PRAGMA integrity_check").fetchone()
    except sqlite3.Error as error:
        raise BackupError("SQLite backup could not be opened") from error
    if row is None or str(row[0]).lower() != "ok":
        raise BackupError("SQLite backup failed its integrity check")


def restore_sqlite(
    backup: str | Path,
    target: str | Path,
    *,
    pre_restore_copy: bool = True,
) -> dict[str, Any]:
    backup_path = Path(backup)
    target_path = Path(target)
    verify_backup(backup_path)
    _sqlite_integrity(backup_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    safety: Path | None = None
    if target_path.exists() and pre_restore_copy:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safety = target_path.with_name(f"{target_path.name}.pre-restore-{stamp}")
        with closing(sqlite3.connect(target_path)) as source_db, closing(
            sqlite3.connect(safety)
        ) as safety_db:
            source_db.backup(safety_db)
            safety_db.commit()
    temporary = target_path.with_name(f".{target_path.name}.restore.{os.getpid()}.tmp")
    try:
        shutil.copy2(backup_path, temporary)
        _sqlite_integrity(temporary)
        os.replace(temporary, target_path)
        for suffix in ("-wal", "-shm", "-journal"):
            target_path.with_name(f"{target_path.name}{suffix}").unlink(missing_ok=True)
    finally:
        temporary.unlink(missing_ok=True)
    return {
        "restored": str(target_path),
        "backup": str(backup_path),
        "preRestore": str(safety) if safety else None,
        "manifest": read_manifest(backup_path),
    }


def _docker(*args: str, input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            ["docker", *args],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=600,
        )
    except subprocess.TimeoutExpired as error:
        raise BackupError("Docker command exceeded its time limit") from error
    except OSError as error:
        raise BackupError("Docker is not available") from error


def backup_postgres_docker(
    *,
    container: str,
    database: str,
    user: str,
    target: str | Path,
    overwrite: bool = False,
) -> dict[str, Any]:
    target_path = Path(target)
    if target_path.exists() and not overwrite:
        raise BackupError("backup target already exists")
    target_path.parent.mkdir(parents=True, exist_ok=True)
    result = _docker(
        "exec",
        container,
        "pg_dump",
        "-U",
        user,
        "-d",
        database,
        "--format=custom",
        "--no-owner",
        "--no-privileges",
    )
    if result.returncode != 0:
        raise BackupError("PostgreSQL pg_dump failed")
    temporary = target_path.with_name(f".{target_path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_bytes(result.stdout)
        if not temporary.stat().st_size:
            raise BackupError("PostgreSQL backup is empty")
        os.replace(temporary, target_path)
        return _write_manifest(target_path, kind="postgresql", source=f"{container}:{database}")
    finally:
        temporary.unlink(missing_ok=True)


def verify_postgres_docker(*, container: str, backup: str | Path) -> dict[str, Any]:
    backup_path = Path(backup)
    verify_backup(backup_path)
    result = _docker(
        "exec",
        "-i",
        container,
        "pg_restore",
        "--list",
        input_bytes=backup_path.read_bytes(),
    )
    if result.returncode != 0:
        raise BackupError("PostgreSQL backup could not be listed by pg_restore")
    return read_manifest(backup_path)


def restore_postgres_docker(
    *,
    container: str,
    database: str,
    user: str,
    backup: str | Path,
    pre_restore_copy: bool = True,
) -> dict[str, Any]:
    backup_path = Path(backup)
    verify_postgres_docker(container=container, backup=backup_path)
    safety: str | None = None
    if pre_restore_copy:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safety_path = backup_path.with_name(f"{backup_path.name}.pre-restore-{stamp}")
        try:
            backup_postgres_docker(
                container=container,
                database=database,
                user=user,
                target=safety_path,
            )
            safety = str(safety_path)
        except BackupError:
            safety = None
    result = _docker(
        "exec",
        "-i",
        container,
        "pg_restore",
        "-U",
        user,
        "-d",
        database,
        "--clean",
        "--if-exists",
        "--no-owner",
        "--no-privileges",
        input_bytes=backup_path.read_bytes(),
    )
    if result.returncode != 0:
        raise BackupError("PostgreSQL pg_restore failed")
    return {
        "restored": f"{container}:{database}",
        "backup": str(backup_path),
        "preRestore": safety,
        "manifest": read_manifest(backup_path),
    }

# ---------------------------------------------------------------------------
# Encrypted backups
# ---------------------------------------------------------------------------

ENCRYPTED_FORMAT = "zerotrace-backup-v2"


def generate_key() -> str:
    """Return a new URL-safe Fernet key for backup encryption."""

    return Fernet.generate_key().decode("ascii")


def _fernet(key: str | bytes) -> Fernet:
    try:
        raw = key.encode("ascii") if isinstance(key, str) else key
        return Fernet(raw)
    except (ValueError, TypeError) as error:
        raise BackupError("backup encryption key is invalid") from error


def encrypted_manifest_path(backup: Path) -> Path:
    return backup.with_name(f"{backup.name}.manifest.json")


def read_encrypted_manifest(backup: Path) -> dict[str, Any]:
    path = encrypted_manifest_path(backup)
    if not path.is_file():
        raise BackupError("encrypted backup manifest is missing")
    try:
        manifest = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError) as error:
        raise BackupError("encrypted backup manifest is invalid") from error
    if not isinstance(manifest, dict) or manifest.get("format") != ENCRYPTED_FORMAT:
        raise BackupError("encrypted backup manifest is not supported")
    if manifest.get("encryption") != "fernet":
        raise BackupError("encrypted backup uses an unsupported cipher")
    return manifest


def verify_encrypted_backup(backup: str | Path) -> dict[str, Any]:
    backup_path = Path(backup)
    if not backup_path.is_file():
        raise BackupError("encrypted backup file is missing")
    manifest = read_encrypted_manifest(backup_path)
    if int(manifest.get("bytes", -1)) != backup_path.stat().st_size:
        raise BackupError("encrypted backup size does not match its manifest")
    if str(manifest.get("sha256")) != _digest(backup_path):
        raise BackupError("encrypted backup checksum does not match its manifest")
    return manifest


def encrypt_backup(
    source: str | Path,
    target: str | Path,
    key: str | bytes,
    *,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Encrypt a verified plaintext backup and its inner manifest.

    The outer manifest contains only metadata and the ciphertext digest. The
    inner manifest and database bytes are authenticated by Fernet, so a tampered
    outer file is rejected before any restore path is touched.
    """

    source_path = Path(source)
    target_path = Path(target)
    if target_path.exists() and not overwrite:
        raise BackupError("encrypted backup target already exists")
    inner_manifest = verify_backup(source_path)
    envelope = {
        "format": ENCRYPTED_FORMAT,
        "inner": inner_manifest,
        "payload": b64encode(source_path.read_bytes()).decode("ascii"),
    }
    token = _fernet(key).encrypt(
        json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    )
    target_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = target_path.with_name(f".{target_path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_bytes(token)
        os.replace(temporary, target_path)
        outer = {
            "format": ENCRYPTED_FORMAT,
            "kind": "encrypted",
            "encryption": "fernet",
            "innerFormat": inner_manifest.get("format"),
            "innerKind": inner_manifest.get("kind"),
            "createdAt": _now(),
            "bytes": target_path.stat().st_size,
            "sha256": _digest(target_path),
            "file": target_path.name,
        }
        encrypted_manifest_path(target_path).write_text(
            json.dumps(outer, indent=2), encoding="utf-8"
        )
        return outer
    finally:
        temporary.unlink(missing_ok=True)


def decrypt_backup(
    backup: str | Path,
    target_dir: str | Path,
    key: str | bytes,
) -> dict[str, Any]:
    """Decrypt an encrypted backup into a clean directory."""

    backup_path = Path(backup)
    output_dir = Path(target_dir)
    verify_encrypted_backup(backup_path)
    try:
        plaintext = _fernet(key).decrypt(backup_path.read_bytes())
        envelope = json.loads(plaintext)
    except (InvalidToken, ValueError, UnicodeDecodeError) as error:
        raise BackupError("encrypted backup could not be decrypted") from error
    if not isinstance(envelope, dict) or envelope.get("format") != ENCRYPTED_FORMAT:
        raise BackupError("encrypted backup envelope is invalid")
    inner = envelope.get("inner")
    payload = envelope.get("payload")
    if not isinstance(inner, dict) or not isinstance(payload, str):
        raise BackupError("encrypted backup envelope is incomplete")
    if inner.get("format") != "zerotrace-backup-v1":
        raise BackupError("encrypted backup inner manifest is not supported")
    try:
        raw = b64decode(payload.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as error:
        raise BackupError("encrypted backup payload is invalid") from error
    if hashlib.sha256(raw).hexdigest() != str(inner.get("sha256")):
        raise BackupError("encrypted backup payload checksum is invalid")
    output_dir.mkdir(parents=True, exist_ok=True)
    name = Path(str(inner.get("file", "backup.bin"))).name
    if not name or name in {".", ".."}:
        raise BackupError("encrypted backup has an unsafe file name")
    restored = output_dir / name
    restored.write_bytes(raw)
    manifest_path(restored).write_text(
        json.dumps(inner, indent=2), encoding="utf-8"
    )
    return {"backup": restored, "manifest": inner}


def prune_backups(
    directory: str | Path,
    *,
    retain_days: int,
    keep_minimum: int = 1,
    now: datetime | None = None,
) -> list[str]:
    """Delete encrypted backups older than the retention window.

    The newest ``keep_minimum`` backups are always retained, even when they are
    older than the window. This prevents a long outage from erasing the only
    recoverable copy.
    """

    if retain_days < 1:
        raise BackupError("retention must be at least one day")
    if keep_minimum < 0:
        raise BackupError("keep_minimum must be non-negative")
    root = Path(directory)
    if not root.is_dir():
        return []
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    candidates = sorted(
        (path for path in root.glob("*.ztb") if path.is_file()),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    deleted: list[str] = []
    for index, path in enumerate(candidates):
        if index < keep_minimum:
            continue
        modified = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        if current - modified < timedelta(days=retain_days):
            continue
        path.unlink(missing_ok=True)
        encrypted_manifest_path(path).unlink(missing_ok=True)
        deleted.append(str(path))
    return deleted
