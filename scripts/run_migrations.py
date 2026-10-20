from pathlib import Path
import os
import sys

import psycopg

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app.errors import ConfigurationError, DependencyUnavailableError


MIGRATIONS_DIR = PROJECT_ROOT / "migrations"


def migration_files() -> list[Path]:
    return sorted(MIGRATIONS_DIR.glob("*.sql"))


def migration_statements() -> list[str]:
    return [
        migration.read_text(encoding="utf-8")
        for migration in migration_files()
    ]


def run() -> None:
    database_url = os.environ.get("DATABASE_URL", "").strip()
    if not database_url:
        raise ConfigurationError("DATABASE_URL is required")

    try:
        with psycopg.connect(database_url, connect_timeout=5) as connection:
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


if __name__ == "__main__":
    try:
        run()
    except (ConfigurationError, DependencyUnavailableError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
