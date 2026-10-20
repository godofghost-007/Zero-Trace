from collections.abc import Callable
from typing import Any

import psycopg

from .intel_pg import PostgresIntelRepository
from .recon_pg import PostgresReconRepository
from .intel_api import InMemoryIntelRepository, create_intel_app
from .recon_api import ReconQueue, create_recon_app
from fastapi import FastAPI, Request
from .security import Principal


def postgres_connection_factory(
    database_url: str,
) -> Callable[[], Any]:
    if not database_url.strip():
        raise ValueError("database URL is required")

    def connect() -> Any:
        return psycopg.connect(database_url, connect_timeout=5)

    return connect


def create_postgres_repositories(
    database_url: str,
) -> tuple[PostgresReconRepository, PostgresIntelRepository]:
    connection_factory = postgres_connection_factory(database_url)
    return (
        PostgresReconRepository(connection_factory),
        PostgresIntelRepository(connection_factory),
    )


def create_runtime_app(
    *,
    recon_queue: ReconQueue,
    recon_repository: PostgresReconRepository,
    intel_repository: PostgresIntelRepository,
    principal_provider: Callable[[Request], Principal | None],
    transport: Any,
) -> FastAPI:
    """Compose one API while keeping PostgreSQL canonical for read paths."""
    recon_queue.persistence = recon_repository
    app = FastAPI()
    recon_app = create_recon_app(
        recon_queue,
        principal_provider,
        read_repository=recon_repository,
    )
    intel_app = create_intel_app(
        InMemoryIntelRepository(),
        principal_provider,
        transport,
        persistence=intel_repository,
        read_repository=intel_repository,
    )
    app.router.routes.extend(
        route for route in recon_app.routes
        if getattr(route, "path", "").startswith("/api/")
    )
    app.router.routes.extend(
        route for route in intel_app.routes
        if getattr(route, "path", "").startswith("/api/")
    )
    return app
