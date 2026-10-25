"""Encrypted, verifiable database backup and restore CLI.

Examples:
    python -m scripts.backup_database generate-key
    python -m scripts.backup_database backup-sqlite \
        --source data/live-engine.sqlite3 --output backups/live.ztb
    python -m scripts.backup_database restore-sqlite \
        --backup backups/live.ztb --target data/live-engine.sqlite3 --yes
    python -m scripts.backup_database backup-postgres \
        --container zerotrace-postgres-1 --database zerotrace \
        --user zerotrace --output backups/postgres.ztb
    python -m scripts.backup_database verify --backup backups/postgres.ztb

The encryption key is read from ``ZEROTRACE_BACKUP_KEY`` (or --key-env /
--key-file). Keep it outside the backup host. The encrypted file and its outer
manifest are copied off-host when --offhost-dir or --rclone-remote is supplied.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"
if str(FRONTEND) not in sys.path:
    sys.path.insert(0, str(FRONTEND))

from backend.services.backup import (  # noqa: E402
    BackupError,
    backup_postgres_docker,
    backup_sqlite,
    decrypt_backup,
    encrypt_backup,
    encrypted_manifest_path,
    generate_key,
    prune_backups,
    restore_postgres_docker,
    restore_sqlite,
    verify_backup,
    verify_encrypted_backup,
)


def _key(args: argparse.Namespace) -> str:
    if args.key_file:
        value = Path(args.key_file).read_text("ascii").strip()
    else:
        value = os.environ.get(args.key_env, "").strip()
    if not value:
        raise BackupError(
            f"backup key is required (set {args.key_env} or use --key-file)"
        )
    return value


def _copy_offhost(paths: list[Path], args: argparse.Namespace) -> list[str]:
    copied: list[str] = []
    if args.offhost_dir:
        destination = Path(args.offhost_dir)
        destination.mkdir(parents=True, exist_ok=True)
        for path in paths:
            target = destination / path.name
            shutil.copy2(path, target)
            copied.append(str(target))
    if args.rclone_remote:
        for path in paths:
            target = f"{args.rclone_remote.rstrip('/')}/{path.name}"
            result = subprocess.run(
                ["rclone", "copyto", str(path), target],
                capture_output=True,
                check=False,
                text=True,
                timeout=600,
            )
            if result.returncode != 0:
                raise BackupError(
                    "rclone copy failed: " + (result.stderr or "").strip()
                )
            copied.append(target)
    return copied


def _emit(payload: dict[str, object]) -> None:
    print(json.dumps(payload, indent=2, default=str))


def _backup_sqlite(args: argparse.Namespace) -> dict[str, object]:
    output = Path(args.output)
    with tempfile.TemporaryDirectory(prefix="zerotrace-backup-") as temp:
        plaintext = Path(temp) / "live.sqlite3"
        backup_sqlite(args.source, plaintext)
        manifest = encrypt_backup(
            plaintext, output, _key(args), overwrite=args.overwrite
        )
    offhost = _copy_offhost([output, encrypted_manifest_path(output)], args)
    return {
        "kind": "sqlite",
        "encryptedBackup": str(output),
        "manifest": manifest,
        "offhost": offhost,
    }


def _backup_postgres(args: argparse.Namespace) -> dict[str, object]:
    output = Path(args.output)
    with tempfile.TemporaryDirectory(prefix="zerotrace-backup-") as temp:
        plaintext = Path(temp) / "postgres.dump"
        backup_postgres_docker(
            container=args.container,
            database=args.database,
            user=args.user,
            target=plaintext,
        )
        manifest = encrypt_backup(
            plaintext, output, _key(args), overwrite=args.overwrite
        )
    offhost = _copy_offhost([output, encrypted_manifest_path(output)], args)
    return {
        "kind": "postgresql",
        "encryptedBackup": str(output),
        "manifest": manifest,
        "offhost": offhost,
    }


def _restore_sqlite(args: argparse.Namespace) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="zerotrace-restore-") as temp:
        decrypted = decrypt_backup(args.backup, temp, _key(args))
        result = restore_sqlite(
            decrypted["backup"],
            args.target,
            pre_restore_copy=not args.no_pre_restore,
        )
    return {"kind": "sqlite", **result}


def _restore_postgres(args: argparse.Namespace) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="zerotrace-restore-") as temp:
        decrypted = decrypt_backup(args.backup, temp, _key(args))
        result = restore_postgres_docker(
            container=args.container,
            database=args.database,
            user=args.user,
            backup=decrypted["backup"],
            pre_restore_copy=not args.no_pre_restore,
        )
    return {"kind": "postgresql", **result}


def _verify(args: argparse.Namespace) -> dict[str, object]:
    outer = verify_encrypted_backup(args.backup)
    with tempfile.TemporaryDirectory(prefix="zerotrace-verify-") as temp:
        decrypted = decrypt_backup(args.backup, temp, _key(args))
        inner = verify_backup(decrypted["backup"])
    return {"ok": True, "outer": outer, "inner": inner}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("generate-key", help="print a new Fernet backup key")

    sqlite_backup = sub.add_parser("backup-sqlite")
    sqlite_backup.add_argument("--source", required=True)
    sqlite_backup.add_argument("--output", required=True)
    sqlite_backup.add_argument("--overwrite", action="store_true")

    pg_backup = sub.add_parser("backup-postgres")
    pg_backup.add_argument("--container", required=True)
    pg_backup.add_argument("--database", required=True)
    pg_backup.add_argument("--user", required=True)
    pg_backup.add_argument("--output", required=True)
    pg_backup.add_argument("--overwrite", action="store_true")

    sqlite_restore = sub.add_parser("restore-sqlite")
    sqlite_restore.add_argument("--backup", required=True)
    sqlite_restore.add_argument("--target", required=True)
    sqlite_restore.add_argument("--no-pre-restore", action="store_true")
    sqlite_restore.add_argument("--yes", action="store_true")

    pg_restore = sub.add_parser("restore-postgres")
    pg_restore.add_argument("--backup", required=True)
    pg_restore.add_argument("--container", required=True)
    pg_restore.add_argument("--database", required=True)
    pg_restore.add_argument("--user", required=True)
    pg_restore.add_argument("--no-pre-restore", action="store_true")
    pg_restore.add_argument("--yes", action="store_true")

    verify = sub.add_parser("verify")
    verify.add_argument("--backup", required=True)

    prune = sub.add_parser("prune")
    prune.add_argument("--directory", required=True)
    prune.add_argument("--retain-days", type=int, default=30)
    prune.add_argument("--keep-minimum", type=int, default=1)

    for command in (sqlite_backup, pg_backup, sqlite_restore, pg_restore, verify):
        command.add_argument("--key-env", default="ZEROTRACE_BACKUP_KEY")
        command.add_argument("--key-file")
    for command in (sqlite_backup, pg_backup):
        command.add_argument("--offhost-dir")
        command.add_argument("--rclone-remote")
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "generate-key":
            _emit({"key": generate_key()})
            return 0
        if args.command == "backup-sqlite":
            _emit(_backup_sqlite(args))
            return 0
        if args.command == "backup-postgres":
            _emit(_backup_postgres(args))
            return 0
        if args.command in {"restore-sqlite", "restore-postgres"}:
            if not args.yes:
                print("restore refused: pass --yes to replace live state", file=sys.stderr)
                return 2
            result = (
                _restore_sqlite(args)
                if args.command == "restore-sqlite"
                else _restore_postgres(args)
            )
            _emit(result)
            return 0
        if args.command == "verify":
            _emit(_verify(args))
            return 0
        if args.command == "prune":
            _emit(
                {
                    "deleted": prune_backups(
                        args.directory,
                        retain_days=args.retain_days,
                        keep_minimum=args.keep_minimum,
                    )
                }
            )
            return 0
    except BackupError as error:
        print(f"backup error: {error}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
