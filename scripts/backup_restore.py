"""Operator CLI for verified SQLite/PostgreSQL backup, restore, and rollback.

Examples:
    python -m scripts.backup_restore backup --sqlite data/live-engine.sqlite3 --output backups/live.sqlite3
    python -m scripts.backup_restore restore --backup backups/live.sqlite3 --sqlite data/live-engine.sqlite3 --yes
    python -m scripts.backup_restore postgres-backup --output backups/postgres.dump
    python -m scripts.backup_restore postgres-restore --backup backups/postgres.dump --yes
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"
if str(FRONTEND) not in sys.path:
    sys.path.insert(0, str(FRONTEND))

from backend.services.backup import (  # noqa: E402
    BackupError,
    backup_postgres_docker,
    backup_sqlite,
    restore_postgres_docker,
    restore_sqlite,
    verify_backup,
    verify_postgres_docker,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    backup = subparsers.add_parser("backup", help="back up a SQLite database")
    backup.add_argument("--sqlite", required=True, type=Path)
    backup.add_argument("--output", required=True, type=Path)
    backup.add_argument("--overwrite", action="store_true")

    restore = subparsers.add_parser("restore", help="restore a SQLite database")
    restore.add_argument("--backup", required=True, type=Path)
    restore.add_argument("--sqlite", required=True, type=Path)
    restore.add_argument("--yes", action="store_true")

    verify = subparsers.add_parser("verify", help="verify a SQLite backup manifest")
    verify.add_argument("--backup", required=True, type=Path)

    pg_backup = subparsers.add_parser("postgres-backup", help="back up via Docker pg_dump")
    pg_backup.add_argument("--container", default="zerotrace-postgres-1")
    pg_backup.add_argument("--database", default="zerotrace")
    pg_backup.add_argument("--user", default="zerotrace")
    pg_backup.add_argument("--output", required=True, type=Path)
    pg_backup.add_argument("--overwrite", action="store_true")

    pg_restore = subparsers.add_parser("postgres-restore", help="restore via Docker pg_restore")
    pg_restore.add_argument("--container", default="zerotrace-postgres-1")
    pg_restore.add_argument("--database", default="zerotrace")
    pg_restore.add_argument("--user", default="zerotrace")
    pg_restore.add_argument("--backup", required=True, type=Path)
    pg_restore.add_argument("--yes", action="store_true")

    pg_verify = subparsers.add_parser("postgres-verify", help="verify a PostgreSQL dump")
    pg_verify.add_argument("--container", default="zerotrace-postgres-1")
    pg_verify.add_argument("--backup", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "backup":
            result = backup_sqlite(args.sqlite, args.output, overwrite=args.overwrite)
        elif args.command == "restore":
            if not args.yes:
                raise BackupError("refusing to replace live state without --yes")
            result = restore_sqlite(args.backup, args.sqlite)
        elif args.command == "verify":
            result = verify_backup(args.backup)
        elif args.command == "postgres-backup":
            result = backup_postgres_docker(
                container=args.container,
                database=args.database,
                user=args.user,
                target=args.output,
                overwrite=args.overwrite,
            )
        elif args.command == "postgres-restore":
            if not args.yes:
                raise BackupError("refusing to replace live state without --yes")
            result = restore_postgres_docker(
                container=args.container,
                database=args.database,
                user=args.user,
                backup=args.backup,
            )
        else:
            result = verify_postgres_docker(
                container=args.container, backup=args.backup
            )
    except (BackupError, OSError) as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        return 1
    print(json.dumps({"ok": True, "result": result}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
