"""PostgreSQL-backed durable state for the live engine.

The SQLite ``LiveStore`` remains the zero-dependency demo fallback. This module
implements the same narrow persistence contract against PostgreSQL so the live
engine can run with the same canonical database used by the BFF and the
production repositories.

The schema is created by ``migrations/0007_live_runtime.sql``; this module does
not create tables at runtime. A missing table is a deployment/configuration
error, not a reason to silently fall back to SQLite.
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from contextlib import contextmanager
from datetime import date, datetime
from typing import Any

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from .intel import ServiceFinding, UncertainMatch, VulnerabilityFact
from .intel_api import Ingestion
from .intel_feeds import EpssRecord, KevRecord
from .live_store import (
    fact_from_dict,
    fact_to_dict,
    finding_from_dict,
    finding_to_dict,
    uncertain_from_dict,
    uncertain_to_dict,
)
from .recon import Scope
from .scan_schedule import ScanSchedule


def _json(value: object) -> Jsonb:
    return Jsonb(value)


def _iso(value: Any) -> str | None:
    return None if value is None else value.isoformat()


def _parse_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value))


def _parse_date(value: Any) -> date | None:
    if value is None:
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    return date.fromisoformat(str(value))


class PostgresLiveStore:
    """PostgreSQL implementation of the live-engine persistence contract."""

    backend = "postgresql"

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    @classmethod
    def from_url(
        cls,
        database_url: str,
        *,
        min_size: int = 1,
        max_size: int = 5,
        timeout: float = 5.0,
    ) -> PostgresLiveStore:
        if not database_url.strip():
            raise ValueError("database URL is required")
        if database_url.startswith("postgresql+psycopg://"):
            database_url = database_url.replace(
                "postgresql+psycopg://", "postgresql://", 1
            )
        if min_size < 1 or max_size < min_size:
            raise ValueError("PostgreSQL pool sizes are invalid")
        last_error: Exception | None = None
        for attempt in range(3):
            pool = ConnectionPool(
                conninfo=database_url,
                min_size=min_size,
                max_size=max_size,
                timeout=timeout,
                open=True,
                check=ConnectionPool.check_connection,
                configure=lambda connection: setattr(
                    connection, "row_factory", dict_row
                ),
            )
            try:
                pool.wait(timeout=timeout)
            except Exception as error:
                last_error = error
                pool.close()
                if attempt < 2:
                    time.sleep(0.5 * (attempt + 1))
                continue
            return cls(pool)
        assert last_error is not None
        raise last_error

    def close(self) -> None:
        self._pool.close()

    @contextmanager
    def _session(self):
        with self._pool.connection() as connection:
            yield connection

    def ping(self) -> bool:
        with self._session() as connection:
            row = connection.execute("SELECT 1").fetchone()
        return row is not None

    # -- scopes ---------------------------------------------------------
    def save_scope(self, scope: Scope) -> None:
        with self._session() as connection:
            connection.execute(
                """
                INSERT INTO live_scopes
                    (scope_id, owner_id, targets, environment, approved,
                     expires_at, profiles)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (scope_id) DO UPDATE SET
                    owner_id = EXCLUDED.owner_id,
                    targets = EXCLUDED.targets,
                    environment = EXCLUDED.environment,
                    approved = EXCLUDED.approved,
                    expires_at = EXCLUDED.expires_at,
                    profiles = EXCLUDED.profiles
                """,
                (
                    scope.scope_id,
                    scope.owner_id,
                    _json(list(scope.targets)),
                    scope.environment,
                    scope.approved,
                    scope.expires_at,
                    _json(list(scope.profiles)),
                ),
            )

    def load_scopes(self) -> list[Scope]:
        with self._session() as connection:
            rows = connection.execute(
                "SELECT * FROM live_scopes ORDER BY scope_id"
            ).fetchall()
        return [self._scope_from_row(row) for row in rows]

    def delete_scope(self, scope_id: str) -> None:
        with self._session() as connection:
            connection.execute(
                "DELETE FROM live_scopes WHERE scope_id = %s", (scope_id,)
            )

    @staticmethod
    def _scope_from_row(row: Any) -> Scope:
        return Scope(
            scope_id=str(row["scope_id"]),
            owner_id=str(row["owner_id"]),
            targets=tuple(str(item) for item in row["targets"]),
            environment=str(row["environment"]),
            approved=bool(row["approved"]),
            expires_at=row["expires_at"],
            profiles=tuple(str(item) for item in row["profiles"]),
        )

    # -- scans ----------------------------------------------------------
    def save_scan(
        self,
        *,
        scan_id: str,
        run_id: str | None,
        scope_id: str,
        target: str,
        profile_id: str,
        state: str,
        warnings: Iterable[str] = (),
        assets: Iterable[str] = (),
        services: Iterable[dict[str, object]] = (),
        tls_findings: Iterable[dict[str, object]] = (),
    ) -> None:
        with self._session() as connection:
            connection.execute(
                """
                INSERT INTO live_scans
                    (scan_id, run_id, scope_id, target, profile_id, state,
                     warnings, assets, services, tls_findings)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (scan_id) DO UPDATE SET
                    run_id = EXCLUDED.run_id,
                    state = EXCLUDED.state,
                    warnings = EXCLUDED.warnings,
                    assets = EXCLUDED.assets,
                    services = EXCLUDED.services,
                    tls_findings = EXCLUDED.tls_findings,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    scan_id,
                    run_id,
                    scope_id,
                    target,
                    profile_id,
                    state,
                    _json(list(warnings)),
                    _json(list(assets)),
                    _json(list(services)),
                    _json(list(tls_findings)),
                ),
            )

    def load_scans(self) -> list[dict[str, object]]:
        with self._session() as connection:
            rows = connection.execute(
                "SELECT * FROM live_scans ORDER BY created_at, scan_id"
            ).fetchall()
        return [
            {
                "scanId": str(row["scan_id"]),
                "runId": None if row["run_id"] is None else str(row["run_id"]),
                "scopeId": str(row["scope_id"]),
                "target": str(row["target"]),
                "profileId": str(row["profile_id"]),
                "state": str(row["state"]),
                "warnings": list(row["warnings"]),
                "assets": list(row["assets"]),
                "services": list(row["services"]),
                "tlsFindings": list(row["tls_findings"]),
            }
            for row in rows
        ]

    # -- scheduled scans -----------------------------------------------
    def save_scan_schedule(self, schedule: ScanSchedule) -> None:
        with self._session() as connection:
            connection.execute(
                """
                INSERT INTO live_scan_schedules
                    (schedule_id, owner_id, scope_id, target, profile_id,
                     interval_seconds, enabled, next_run_at, created_at,
                     authorization_id, last_run_at, last_scan_id, last_state,
                     last_error, runs)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (schedule_id) DO UPDATE SET
                    enabled = EXCLUDED.enabled,
                    next_run_at = EXCLUDED.next_run_at,
                    authorization_id = EXCLUDED.authorization_id,
                    last_run_at = EXCLUDED.last_run_at,
                    last_scan_id = EXCLUDED.last_scan_id,
                    last_state = EXCLUDED.last_state,
                    last_error = EXCLUDED.last_error,
                    runs = EXCLUDED.runs
                """,
                (
                    schedule.schedule_id,
                    schedule.owner_id,
                    schedule.scope_id,
                    schedule.target,
                    schedule.profile_id,
                    schedule.interval_seconds,
                    schedule.enabled,
                    schedule.next_run_at,
                    schedule.created_at,
                    schedule.authorization_id,
                    schedule.last_run_at,
                    schedule.last_scan_id,
                    schedule.last_state,
                    schedule.last_error,
                    schedule.runs,
                ),
            )

    def load_scan_schedules(self) -> list[ScanSchedule]:
        with self._session() as connection:
            rows = connection.execute(
                "SELECT * FROM live_scan_schedules ORDER BY next_run_at"
            ).fetchall()
        return [
            ScanSchedule(
                schedule_id=str(row["schedule_id"]),
                owner_id=str(row["owner_id"]),
                scope_id=str(row["scope_id"]),
                target=str(row["target"]),
                profile_id=str(row["profile_id"]),
                interval_seconds=int(row["interval_seconds"]),
                enabled=bool(row["enabled"]),
                next_run_at=row["next_run_at"],
                created_at=row["created_at"],
                authorization_id=row["authorization_id"],
                last_run_at=row["last_run_at"],
                last_scan_id=row["last_scan_id"],
                last_state=row["last_state"],
                last_error=row["last_error"],
                runs=int(row["runs"]),
            )
            for row in rows
        ]

    def delete_scan_schedule(self, schedule_id: str) -> None:
        with self._session() as connection:
            connection.execute(
                "DELETE FROM live_scan_schedules WHERE schedule_id = %s",
                (schedule_id,),
            )

    # -- intel ----------------------------------------------------------
    def save_intel_state(
        self,
        *,
        facts: Iterable[VulnerabilityFact],
        epss_records: Iterable[EpssRecord],
        kev_records: Iterable[KevRecord],
        ingestions: dict[str, Ingestion],
        idempotency: dict[str, tuple[str, str]],
        findings: Iterable[ServiceFinding] = (),
        uncertain_matches: Iterable[UncertainMatch] = (),
        nvd_checkpoint: str | None = None,
    ) -> None:
        fact_rows = [
            (fact.cve_id, _json(fact_to_dict(fact))) for fact in facts
        ]
        finding_rows = [
            (
                f"{finding.service_id}:{finding.cve_id}",
                _json(finding_to_dict(finding)),
            )
            for finding in findings
        ]
        uncertain_rows = [
            (
                f"{match.service_id}:{match.cve_id}",
                _json(uncertain_to_dict(match)),
            )
            for match in uncertain_matches
        ]
        epss_rows = [
            {
                "cve_id": record.cve_id,
                "score": record.score,
                "score_date": record.score_date.isoformat(),
            }
            for record in epss_records
        ]
        kev_rows = [
            {
                "cve_id": record.cve_id,
                "date_added": record.date_added.isoformat(),
                "due_date": record.due_date.isoformat(),
                "known_ransomware_campaign_use": record.known_ransomware_campaign_use,
            }
            for record in kev_records
        ]
        ingestion_rows = {
            key: {
                "ingestion_id": value.ingestion_id,
                "source": value.source,
                "state": value.state,
                "fact_count": value.fact_count,
                "error": value.error,
                "checkpoint": value.checkpoint,
                "truncated": value.truncated,
                "total_results": value.total_results,
                "pages": value.pages,
            }
            for key, value in ingestions.items()
        }
        with self._session() as connection:
            connection.execute("DELETE FROM live_intel_facts")
            with connection.cursor() as cursor:
                if fact_rows:
                    cursor.executemany(
                        "INSERT INTO live_intel_facts (cve_id, payload) "
                        "VALUES (%s, %s)",
                        fact_rows,
                    )
            connection.execute("DELETE FROM live_findings")
            with connection.cursor() as cursor:
                if finding_rows:
                    cursor.executemany(
                        "INSERT INTO live_findings (finding_id, payload) "
                        "VALUES (%s, %s)",
                        finding_rows,
                    )
            connection.execute("DELETE FROM live_uncertain_matches")
            with connection.cursor() as cursor:
                if uncertain_rows:
                    cursor.executemany(
                        "INSERT INTO live_uncertain_matches (match_id, payload) "
                        "VALUES (%s, %s)",
                        uncertain_rows,
                    )
            for key, payload in (
                ("epss", epss_rows),
                ("kev", kev_rows),
                ("ingestions", ingestion_rows),
                ("idempotency", idempotency),
                ("nvd_checkpoint", nvd_checkpoint),
            ):
                connection.execute(
                    """
                    INSERT INTO live_intel_meta (key, payload)
                    VALUES (%s, %s)
                    ON CONFLICT (key) DO UPDATE SET payload = EXCLUDED.payload
                    """,
                    (key, _json(payload)),
                )

    def load_intel_state(self) -> dict[str, object]:
        with self._session() as connection:
            fact_rows = connection.execute(
                "SELECT payload FROM live_intel_facts ORDER BY cve_id"
            ).fetchall()
            meta_rows = connection.execute(
                "SELECT key, payload FROM live_intel_meta"
            ).fetchall()
            finding_rows = connection.execute(
                "SELECT payload FROM live_findings ORDER BY finding_id"
            ).fetchall()
            uncertain_rows = connection.execute(
                "SELECT payload FROM live_uncertain_matches ORDER BY match_id"
            ).fetchall()
        meta = {str(row["key"]): row["payload"] for row in meta_rows}
        facts = tuple(
            fact_from_dict(row["payload"]) for row in fact_rows
        )
        findings = tuple(
            finding_from_dict(row["payload"]) for row in finding_rows
        )
        uncertain_matches = tuple(
            uncertain_from_dict(row["payload"]) for row in uncertain_rows
        )
        epss = tuple(
            EpssRecord(
                cve_id=str(item["cve_id"]),
                score=float(item["score"]),
                score_date=_parse_date(item["score_date"]),
            )
            for item in meta.get("epss", [])
        )
        kev = tuple(
            KevRecord(
                cve_id=str(item["cve_id"]),
                date_added=_parse_date(item["date_added"]),
                due_date=_parse_date(item["due_date"]),
                known_ransomware_campaign_use=bool(
                    item["known_ransomware_campaign_use"]
                ),
            )
            for item in meta.get("kev", [])
        )
        ingestions = {
            str(key): Ingestion(
                ingestion_id=str(item["ingestion_id"]),
                source=str(item["source"]),
                state=str(item["state"]),
                fact_count=int(item["fact_count"]),
                error=item.get("error"),
                checkpoint=(
                    None if item.get("checkpoint") is None else str(item["checkpoint"])
                ),
                truncated=bool(item.get("truncated", False)),
                total_results=(
                    None
                    if item.get("total_results") is None
                    else int(item["total_results"])
                ),
                pages=int(item.get("pages", 0)),
            )
            for key, item in meta.get("ingestions", {}).items()
        }
        idempotency = {
            str(key): (str(value[0]), str(value[1]))
            for key, value in meta.get("idempotency", {}).items()
        }
        return {
            "facts": facts,
            "epss": epss,
            "kev": kev,
            "ingestions": ingestions,
            "idempotency": idempotency,
            "findings": findings,
            "uncertain_matches": uncertain_matches,
            "nvd_checkpoint": meta.get("nvd_checkpoint"),
        }

    # -- scheduled intel ------------------------------------------------
    def save_schedule_state(
        self,
        source: str,
        *,
        last_started: str | None,
        last_completed: str | None,
        last_state: str,
        last_error: str | None,
        last_fact_count: int,
        runs: int,
    ) -> None:
        with self._session() as connection:
            connection.execute(
                """
                INSERT INTO live_intel_schedule
                    (source, last_started, last_completed, last_state,
                     last_error, last_fact_count, runs)
                VALUES (%s, %s::timestamptz, %s::timestamptz, %s, %s, %s, %s)
                ON CONFLICT (source) DO UPDATE SET
                    last_started = EXCLUDED.last_started,
                    last_completed = EXCLUDED.last_completed,
                    last_state = EXCLUDED.last_state,
                    last_error = EXCLUDED.last_error,
                    last_fact_count = EXCLUDED.last_fact_count,
                    runs = EXCLUDED.runs
                """,
                (
                    source,
                    last_started,
                    last_completed,
                    last_state,
                    last_error,
                    last_fact_count,
                    runs,
                ),
            )

    def load_schedule_state(self) -> dict[str, dict[str, object]]:
        with self._session() as connection:
            rows = connection.execute(
                "SELECT * FROM live_intel_schedule ORDER BY source"
            ).fetchall()
        return {
            str(row["source"]): {
                "source": str(row["source"]),
                "lastStarted": _iso(row["last_started"]),
                "lastCompleted": _iso(row["last_completed"]),
                "state": str(row["last_state"]),
                "lastError": row["last_error"],
                "lastFactCount": int(row["last_fact_count"]),
                "runs": int(row["runs"]),
            }
            for row in rows
        }

    # -- guard and readiness -------------------------------------------
    def record_guard_event(
        self, *, blocked: bool, reason: str | None, pii_blocked: bool
    ) -> None:
        with self._session() as connection:
            connection.execute(
                """
                INSERT INTO live_guard_events (blocked, reason, pii_blocked)
                VALUES (%s, %s, %s)
                """,
                (blocked, reason, pii_blocked),
            )

    def guard_counts(self) -> dict[str, int]:
        with self._session() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS total,
                       COALESCE(SUM(CASE WHEN blocked = FALSE THEN 1 ELSE 0 END), 0)
                           AS unblocked
                FROM live_guard_events
                """
            ).fetchone()
        return {"total": int(row["total"]), "unblocked": int(row["unblocked"])}

    def save_readiness(self, payload: dict[str, object]) -> None:
        with self._session() as connection:
            connection.execute(
                "INSERT INTO live_readiness_snapshots (payload) VALUES (%s)",
                (_json(payload),),
            )

    def latest_readiness(self) -> dict[str, object] | None:
        with self._session() as connection:
            row = connection.execute(
                "SELECT payload FROM live_readiness_snapshots "
                "ORDER BY snapshot_id DESC LIMIT 1"
            ).fetchone()
        return None if row is None else row["payload"]

    def counts(self) -> dict[str, int]:
        with self._session() as connection:
            scopes = connection.execute(
                "SELECT COUNT(*) AS count FROM live_scopes"
            ).fetchone()["count"]
            scans = connection.execute(
                "SELECT COUNT(*) AS count FROM live_scans"
            ).fetchone()["count"]
            facts = connection.execute(
                "SELECT COUNT(*) AS count FROM live_intel_facts"
            ).fetchone()["count"]
        return {
            "scopes": int(scopes),
            "scans": int(scans),
            "facts": int(facts),
        }
