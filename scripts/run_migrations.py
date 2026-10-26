import sys
from pathlib import Path

import psycopg

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app.errors import ConfigurationError, DependencyUnavailableError
from app.settings import env_or_file

MIGRATIONS_DIR = PROJECT_ROOT / "migrations"
DOWN_DIR = MIGRATIONS_DIR / "down"


def migration_files() -> list[Path]:
    return sorted(MIGRATIONS_DIR.glob("*.sql"))


def migration_statements() -> list[str]:
    return [
        migration.read_text(encoding="utf-8")
        for migration in migration_files()
    ]


def _database_url(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ConfigurationError("DATABASE_URL is required")
    if normalized.startswith("postgresql+psycopg://"):
        normalized = normalized.replace(
            "postgresql+psycopg://", "postgresql://", 1
        )
    return normalized


def apply(database_url: str) -> None:
    try:
        with psycopg.connect(
            _database_url(database_url), connect_timeout=5
        ) as connection:
            with connection.cursor() as cursor:
                for migration, statement in zip(
                    migration_files(), migration_statements()
                ):
                    cursor.execute(statement)
                    cursor.execute(
                        """
                        INSERT INTO schema_migrations (version)
                        VALUES (%s)
                        ON CONFLICT (version) DO NOTHING
                        """,
                        (migration.stem,),
                    )
            connection.commit()
    except psycopg.Error as error:
        raise DependencyUnavailableError(
            "PostgreSQL migration failed; inspect the database dependency"
        ) from error


def rollback_latest(database_url: str) -> str:
    """Apply the down migration for the most recently recorded version."""

    try:
        with psycopg.connect(
            _database_url(database_url), connect_timeout=5
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT version FROM schema_migrations
                    ORDER BY version DESC LIMIT 1
                    """
                )
                row = cursor.fetchone()
                if row is None:
                    raise ConfigurationError("no applied migration to roll back")
                version = str(row[0])
                down = DOWN_DIR / f"{version}.down.sql"
                if not down.is_file():
                    raise ConfigurationError(
                        f"no down migration exists for {version}"
                    )
                cursor.execute(down.read_text(encoding="utf-8"))
                cursor.execute(
                    "DELETE FROM schema_migrations WHERE version = %s",
                    (version,),
                )
            connection.commit()
    except psycopg.Error as error:
        raise DependencyUnavailableError(
            "PostgreSQL rollback failed; inspect the database dependency"
        ) from error
    return version


def run(rollback: bool = False) -> None:
    database_url = env_or_file("DATABASE_URL")
    if not database_url:
        raise ConfigurationError("DATABASE_URL is required")
    if rollback:
        rollback_latest(database_url)
    else:
        apply(database_url)


if __name__ == "__main__":
    try:
        run(rollback="--rollback" in sys.argv[1:])
    except (ConfigurationError, DependencyUnavailableError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
