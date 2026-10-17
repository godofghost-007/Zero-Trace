from collections.abc import Callable, Iterable
import json
from typing import Any
from uuid import uuid4

from .events import EventEnvelope
from .recon import ReconError


class PostgresReconRepository:
    """Parameterized PostgreSQL repository for canonical Recon state."""

    def __init__(self, connection_factory: Callable[[], Any]) -> None:
        self.connection_factory = connection_factory

    def claim_idempotency(self, key: str, request_hash: str) -> str | None:
        with self.connection_factory() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT request_hash, run_id
                    FROM recon_idempotency
                    WHERE idempotency_key = %s
                    FOR UPDATE
                    """,
                    (key,),
                )
                existing = cursor.fetchone()
                if existing is None:
                    return None
                if existing[0] != request_hash:
                    raise ReconError(
                        "idempotency key was reused with a different request"
                    )
                return str(existing[1])

    def create_run(
        self,
        run_id: str,
        scope_id: str,
        target: str,
        profile_id: str,
        request_hash: str,
        idempotency_key: str | None,
    ) -> str:
        with self.connection_factory() as connection:
            with connection.cursor() as cursor:
                if idempotency_key is not None:
                    cursor.execute(
                        """
                        SELECT request_hash, run_id
                        FROM recon_idempotency
                        WHERE idempotency_key = %s
                        FOR UPDATE
                        """,
                        (idempotency_key,),
                    )
                    existing = cursor.fetchone()
                    if existing is not None:
                        if existing[0] != request_hash:
                            raise ReconError(
                                "idempotency key was reused with a different request"
                            )
                        return str(existing[1])
                cursor.execute(
                    """
                    INSERT INTO recon_runs
                        (run_id, scope_id, target, profile_id, state, started_at)
                    VALUES (%s, %s, %s, %s, 'running', CURRENT_TIMESTAMP)
                    """,
                    (run_id, scope_id, target, profile_id),
                )
                if idempotency_key is not None:
                    cursor.execute(
                        """
                        INSERT INTO recon_idempotency
                            (idempotency_key, request_hash, run_id)
                        VALUES (%s, %s, %s)
                        """,
                        (idempotency_key, request_hash, run_id),
                    )
            connection.commit()
        return run_id

    def commit_results(
        self,
        run_id: str,
        scope_id: str,
        state: str,
        assets: Iterable[str],
        services: Iterable[tuple[str, str, int, str]],
        warnings: Iterable[str],
    ) -> None:
        event_id = str(uuid4())
        asset_list = list(assets)
        service_list = list(services)
        warning_list = list(warnings)
        payload = json.dumps(
            {
                "state": state,
                "warningCount": len(warning_list),
            },
            separators=(",", ":"),
        )
        with self.connection_factory() as connection:
            with connection.cursor() as cursor:
                asset_ids: dict[str, str] = {}
                identifiers = asset_list + [
                    asset for asset, _, _, _ in service_list if asset not in asset_list
                ]
                for identifier in identifiers:
                    cursor.execute(
                        """
                        INSERT INTO recon_assets
                            (asset_id, scope_id, canonical_identifier, asset_kind)
                        VALUES (%s, %s, %s, 'domain')
                        ON CONFLICT (scope_id, canonical_identifier)
                        DO UPDATE SET last_seen_at = CURRENT_TIMESTAMP
                        """,
                        (str(uuid4()), scope_id, identifier),
                    )
                    cursor.execute(
                        """
                        SELECT asset_id
                        FROM recon_assets
                        WHERE scope_id = %s AND canonical_identifier = %s
                        """,
                        (scope_id, identifier),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        raise ReconError("persisted asset could not be reloaded")
                    asset_ids[identifier] = str(row[0])
                for asset, protocol, port, product in service_list:
                    cursor.execute(
                        """
                        INSERT INTO recon_services
                            (service_id, asset_id, protocol, port, product)
                        VALUES (%s, %s, %s, %s, %s)
                        ON CONFLICT (asset_id, protocol, port)
                        DO UPDATE SET product = EXCLUDED.product,
                                      last_seen_at = CURRENT_TIMESTAMP
                        RETURNING service_id
                        """,
                        (
                            str(uuid4()),
                            asset_ids[asset],
                            protocol,
                            port,
                            product,
                        ),
                    )
                    service_row = cursor.fetchone()
                    if service_row is None:
                        raise ReconError("persisted service could not be reloaded")
                    cursor.execute(
                        """
                        INSERT INTO recon_observations
                            (observation_id, run_id, asset_id, service_id,
                             source, evidence)
                        VALUES (%s, %s, %s, %s, 'recon', %s::jsonb)
                        """,
                        (
                            str(uuid4()),
                            run_id,
                            asset_ids[asset],
                            str(service_row[0]),
                            json.dumps(
                                {
                                    "asset": asset,
                                    "protocol": protocol,
                                    "port": port,
                                    "product": product,
                                },
                                separators=(",", ":"),
                            ),
                        ),
                    )
                cursor.execute(
                    """
                    UPDATE recon_runs
                    SET state = %s, warnings = %s::jsonb,
                        completed_at = CURRENT_TIMESTAMP
                    WHERE run_id = %s
                    """,
                    (state, json.dumps(warning_list), run_id),
                )
                cursor.execute(
                    """
                    INSERT INTO event_outbox
                        (event_id, event_type, schema_version, entity_type,
                         entity_id, correlation_id, payload, status)
                    VALUES (%s, 'scan_status_changed', 1, 'scan_run',
                            %s, %s, %s::jsonb, 'pending')
                    """,
                    (event_id, run_id, run_id, payload),
                )
            connection.commit()
