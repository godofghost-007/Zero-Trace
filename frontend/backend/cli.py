"""Operator CLI commands for accounts and local recovery."""

from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime
from pathlib import Path

import click
from flask import Flask, current_app
from sqlalchemy.engine import make_url
from werkzeug.security import generate_password_hash

from .auth import AuthError, _validate_password, create_user
from .extensions import db
from .models import AuthSession, UserAccount
from .services.backup import (
    BackupError,
    backup_postgres_docker,
    backup_sqlite,
    restore_postgres_docker,
    restore_sqlite,
    verify_backup,
    verify_postgres_docker,
)


def _default_backup_path() -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return Path(current_app.config["DATA_DIR"]).parent / "backups" / f"zerotrace-{stamp}"


def _database_parts() -> tuple[str, Path | None, str | None, str | None]:
    raw = current_app.config["SQLALCHEMY_DATABASE_URI"]
    url = make_url(raw)
    if url.get_backend_name() == "sqlite":
        return "sqlite", Path(url.database or ""), None, None
    return "postgresql", None, url.database, url.username


def register_cli(app: Flask) -> None:
    @app.cli.command("init-schema")
    def init_schema_command() -> None:
        """Create BFF tables once, then keep AUTO_CREATE_SCHEMA=false."""
        db.create_all()
        from .services.migrations import (
            migrate_identity_columns,
            migrate_legacy_event_outbox,
        )

        migrate_identity_columns()
        migrate_legacy_event_outbox()
        click.echo("BFF schema initialized")

    @app.cli.command("create-user")
    @click.option("--email", prompt=True)
    @click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
    @click.option("--role", type=click.Choice(["viewer", "operator", "admin"]), default="operator", show_default=True)
    @click.option("--tenant", "tenant_id", default="tenant_local", show_default=True)
    def create_user_command(email: str, password: str, role: str, tenant_id: str) -> None:
        """Create a local account without putting a password in shell history."""
        try:
            user = create_user(
                email=email, password=password, role=role, tenant_id=tenant_id
            )
        except AuthError as error:
            raise click.ClickException(str(error)) from error
        click.echo(f"created {user.email} ({user.role}, tenant={user.tenant_id})")

    @app.cli.command("demo-credentials")
    def demo_credentials_command() -> None:
        """Create a random local admin only when the database has no users."""
        existing = UserAccount.query.count()
        if existing:
            click.echo(
                json.dumps(
                    {
                        "created": False,
                        "users": existing,
                        "message": "An account already exists. Use that account or create-user.",
                    },
                    indent=2,
                )
            )
            return
        email = "admin@zerotrace.local"
        password = secrets.token_urlsafe(18)
        try:
            user = create_user(
                email=email,
                password=password,
                role="admin",
                tenant_id="tenant_local",
            )
        except AuthError as error:
            raise click.ClickException(str(error)) from error
        credentials = Path(current_app.config["DATA_DIR"]) / "local-credentials.txt"
        credentials.parent.mkdir(parents=True, exist_ok=True)
        credentials.write_text(
            "ZeroTrace local demo credentials\n"
            f"email: {user.email}\n"
            f"password: {password}\n"
            "Delete this file after the first sign-in.\n",
            encoding="utf-8",
        )
        click.echo(
            json.dumps(
                {
                    "created": True,
                    "email": user.email,
                    "password": password,
                    "credentialsFile": str(credentials),
                    "warning": "Local demo only. Delete the credentials file after sign-in.",
                },
                indent=2,
            )
        )

    @app.cli.command("set-password")
    @click.argument("email")
    @click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
    def set_password_command(email: str, password: str) -> None:
        user = UserAccount.query.filter_by(email=email.strip().lower()).first()
        if user is None:
            raise click.ClickException("user was not found")
        try:
            normalized = _validate_password(password)
        except AuthError as error:
            raise click.ClickException(str(error)) from error
        user.password_hash = generate_password_hash(normalized)
        sessions = AuthSession.query.filter_by(user_id=user.id, revoked_at=None).all()
        now = datetime.now(UTC)
        for session in sessions:
            session.revoked_at = now
        db.session.commit()
        click.echo(f"updated password for {user.email} and revoked {len(sessions)} session(s)")

    @app.cli.command("list-users")
    def list_users_command() -> None:
        rows = UserAccount.query.order_by(UserAccount.created_at.asc()).all()
        for row in rows:
            state = "active" if row.active else "disabled"
            click.echo(
                f"{row.email}\t{row.role}\t{row.tenant_id}\t{state}\t{row.id}"
            )

    @app.cli.command("revoke-user")
    @click.argument("email")
    def revoke_user_command(email: str) -> None:
        user = UserAccount.query.filter_by(email=email.strip().lower()).first()
        if user is None:
            raise click.ClickException("user was not found")
        sessions = AuthSession.query.filter_by(user_id=user.id, revoked_at=None).all()
        now = datetime.now(UTC)
        for session in sessions:
            session.revoked_at = now
        user.active = False
        db.session.commit()
        click.echo(
            f"disabled {user.email} and revoked {len(sessions)} session(s)"
        )

    @app.cli.command("enable-user")
    @click.argument("email")
    def enable_user_command(email: str) -> None:
        user = UserAccount.query.filter_by(email=email.strip().lower()).first()
        if user is None:
            raise click.ClickException("user was not found")
        user.active = True
        db.session.commit()
        click.echo(f"enabled {user.email}")

    @app.cli.command("backup-db")
    @click.option("--output", "output_path", type=click.Path(path_type=Path), default=None)
    @click.option("--container", default="zerotrace-postgres-1", show_default=True)
    @click.option("--overwrite", is_flag=True, default=False)
    def backup_db_command(output_path: Path | None, container: str, overwrite: bool) -> None:
        kind, sqlite_path, database, user = _database_parts()
        output = output_path or _default_backup_path().with_suffix(
            ".sqlite3" if kind == "sqlite" else ".dump"
        )
        try:
            if kind == "sqlite":
                if sqlite_path is None:
                    raise BackupError("SQLite path is missing")
                main = backup_sqlite(sqlite_path, output, overwrite=overwrite)
                audit_path = Path(current_app.config["AUDIT_DB_PATH"])
                audit = backup_sqlite(
                    audit_path,
                    output.with_name(f"{output.stem}-audit.sqlite3"),
                    overwrite=overwrite,
                )
                click.echo(json.dumps({"main": main, "audit": audit}, indent=2))
            else:
                manifest = backup_postgres_docker(
                    container=container,
                    database=database or "zerotrace",
                    user=user or "zerotrace",
                    target=output,
                    overwrite=overwrite,
                )
                click.echo(json.dumps(manifest, indent=2))
        except (BackupError, OSError) as error:
            raise click.ClickException(str(error)) from error

    @app.cli.command("restore-db")
    @click.argument("backup", type=click.Path(path_type=Path, exists=True))
    @click.option("--container", default="zerotrace-postgres-1", show_default=True)
    @click.option("--yes", is_flag=True, default=False, help="Required to replace live state.")
    def restore_db_command(backup: Path, container: str, yes: bool) -> None:
        if not yes:
            raise click.ClickException("refusing to replace live state without --yes")
        db.session.remove()
        db.engine.dispose()
        kind, sqlite_path, database, user = _database_parts()
        try:
            if kind == "sqlite":
                if sqlite_path is None:
                    raise BackupError("SQLite path is missing")
                result = restore_sqlite(backup, sqlite_path)
                click.echo(json.dumps(result, indent=2))
            else:
                result = restore_postgres_docker(
                    container=container,
                    database=database or "zerotrace",
                    user=user or "zerotrace",
                    backup=backup,
                )
                click.echo(json.dumps(result, indent=2))
        except (BackupError, OSError) as error:
            raise click.ClickException(str(error)) from error

    @app.cli.command("verify-db-backup")
    @click.argument("backup", type=click.Path(path_type=Path, exists=True))
    @click.option("--container", default="zerotrace-postgres-1", show_default=True)
    def verify_db_backup_command(backup: Path, container: str) -> None:
        kind, _, _, _ = _database_parts()
        try:
            manifest = (
                verify_backup(backup)
                if kind == "sqlite"
                else verify_postgres_docker(container=container, backup=backup)
            )
        except (BackupError, OSError) as error:
            raise click.ClickException(str(error)) from error
        click.echo(json.dumps(manifest, indent=2))
