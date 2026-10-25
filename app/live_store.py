"""Small, durable state store for the loopback live-engine demo.

The production runtime uses PostgreSQL (``app/recon_pg.py`` and
``app/intel_pg.py``).  The demo engine must also work on a developer laptop
without a database service, so it keeps its bounded demo state in SQLite.  The
store deliberately contains only the data the live console needs: approved
scopes, completed/queued scan results, the last Intel feed snapshot, Guard
inspection counters, and the latest readiness calculation.

Nothing in this module accepts arbitrary SQL, and every value is serialized to
JSON or stored as a bound parameter.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
import json
from pathlib import Path
import sqlite3
from threading import RLock
from typing import Any, Iterable

from .intel import (
    PriorityResult,
    ServiceFinding,
    UncertainMatch,
    VulnerabilityFact,
)
from .intel_api import Ingestion
from .intel_feeds import EpssRecord, KevRecord
from .recon import NormalizedService, Scope
from .scan_schedule import ScanSchedule


def _json(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def _iso(value: Any) -> str | None:
    return None if value is None else value.isoformat()


def _parse_datetime(value: str | None):
    from datetime import datetime

    return None if value is None else datetime.fromisoformat(value)


def _parse_date(value: str | None):
    from datetime import date

    return None if value is None else date.fromisoformat(value)


def fact_to_dict(fact: VulnerabilityFact) -> dict[str, object]:
    """Serialize a provenance-bearing Intel fact without losing its fields."""

    return {
        "cve_id": fact.cve_id,
        "source": fact.source,
        "source_record_id": fact.source_record_id,
        "source_revision": fact.source_revision,
        "summary": fact.summary,
        "cpe_names": list(fact.cpe_names),
        "cvss_score": fact.cvss_score,
        "epss_score": fact.epss_score,
        "kev": fact.kev,
        "published_at": _iso(fact.published_at),
        "modified_at": _iso(fact.modified_at),
        "retrieved_at": _iso(fact.retrieved_at),
        "schema_version": fact.schema_version,
        "payload_digest": fact.payload_digest,
        "epss_score_date": _iso(fact.epss_score_date),
        "kev_due_date": _iso(fact.kev_due_date),
    }


def fact_from_dict(value: dict[str, object]) -> VulnerabilityFact:
    return VulnerabilityFact(
        cve_id=str(value["cve_id"]),
        source=str(value["source"]),
        source_record_id=str(value["source_record_id"]),
        source_revision=str(value["source_revision"]),
        summary=str(value["summary"]),
        cpe_names=tuple(str(item) for item in value.get("cpe_names", [])),
        cvss_score=value.get("cvss_score"),  # type: ignore[arg-type]
        epss_score=value.get("epss_score"),  # type: ignore[arg-type]
        kev=value.get("kev"),  # type: ignore[arg-type]
        published_at=_parse_datetime(value.get("published_at")),  # type: ignore[arg-type]
        modified_at=_parse_datetime(value.get("modified_at")),  # type: ignore[arg-type]
        retrieved_at=_parse_datetime(value["retrieved_at"]),  # type: ignore[arg-type]
        schema_version=int(value["schema_version"]),  # type: ignore[arg-type]
        payload_digest=str(value["payload_digest"]),
        epss_score_date=_parse_date(value.get("epss_score_date")),  # type: ignore[arg-type]
        kev_due_date=_parse_date(value.get("kev_due_date")),  # type: ignore[arg-type]
    )


def service_to_dict(service: NormalizedService) -> dict[str, object]:
    return {
        "asset": service.asset,
        "protocol": service.protocol,
        "port": service.port,
        "product": service.product,
        "version": service.version,
        "tlsStatus": service.tls_status,
    }


def service_from_dict(value: dict[str, object]) -> NormalizedService:
    return NormalizedService(
        asset=str(value["asset"]),
        protocol=str(value["protocol"]),
        port=int(value["port"]),  # type: ignore[arg-type]
        product=None if value.get("product") is None else str(value["product"]),
        version=None if value.get("version") is None else str(value["version"]),
        tls_status=(
            None if value.get("tlsStatus") is None else str(value["tlsStatus"])
        ),
    )


def finding_to_dict(finding: ServiceFinding) -> dict[str, object]:
    payload = asdict(finding)
    payload["evidence"] = list(finding.evidence)
    payload["priority"] = {
        **asdict(finding.priority),
        "inputs": dict(finding.priority.inputs),
        "missing": list(finding.priority.missing),
    }
    return payload


def finding_from_dict(value: dict[str, object]) -> ServiceFinding:
    priority = value["priority"]
    if not isinstance(priority, dict):
        raise ValueError("finding priority payload is invalid")
    return ServiceFinding(
        service_id=str(value["service_id"]),
        asset_id=str(value["asset_id"]),
        cve_id=str(value["cve_id"]),
        match_method=str(value["match_method"]),
        confidence=float(value["confidence"]),  # type: ignore[arg-type]
        evidence=tuple(str(item) for item in value.get("evidence", [])),
        freshness=str(value["freshness"]),
        priority=PriorityResult(
            formula_version=str(priority["formula_version"]),
            score=float(priority["score"]),  # type: ignore[arg-type]
            inputs={
                str(key): float(item)
                for key, item in dict(priority.get("inputs", {})).items()
            },
            missing=tuple(str(item) for item in priority.get("missing", [])),
            confidence=float(priority["confidence"]),  # type: ignore[arg-type]
        ),
    )


def uncertain_to_dict(match: UncertainMatch) -> dict[str, object]:
    payload = asdict(match)
    payload["evidence"] = list(match.evidence)
    return payload


def uncertain_from_dict(value: dict[str, object]) -> UncertainMatch:
    return UncertainMatch(
        service_id=str(value["service_id"]),
        asset_id=str(value["asset_id"]),
        cve_id=str(value["cve_id"]),
        reason=str(value["reason"]),
        evidence=tuple(str(item) for item in value.get("evidence", [])),
        freshness=str(value["freshness"]),
        source_revision=str(value["source_revision"]),
    )


class LiveStore:
    """SQLite-backed durable state for the local live engine."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    @contextmanager
    def _session(self):
        connection = self._connect()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._lock, self._session() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS live_scopes (
                    scope_id TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    targets TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    approved INTEGER NOT NULL,
                    expires_at TEXT NOT NULL,
                    profiles TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS live_scans (
                    scan_id TEXT PRIMARY KEY,
                    run_id TEXT,
                    scope_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    warnings TEXT NOT NULL DEFAULT '[]',
                    assets TEXT NOT NULL DEFAULT '[]',
                    services TEXT NOT NULL DEFAULT '[]',
                    tls_findings TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS live_scans_scope_idx
                    ON live_scans (scope_id, created_at);

                CREATE TABLE IF NOT EXISTS live_scan_schedules (
                    schedule_id TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    scope_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    interval_seconds INTEGER NOT NULL,
                    enabled INTEGER NOT NULL,
                    next_run_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    authorization_id TEXT,
                    last_run_at TEXT,
                    last_scan_id TEXT,
                    last_state TEXT,
                    last_error TEXT,
                    runs INTEGER NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS live_scan_schedules_due_idx
                    ON live_scan_schedules (enabled, next_run_at);

                CREATE TABLE IF NOT EXISTS live_intel_facts (
                    cve_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS live_intel_meta (
                    key TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS live_findings (
                    finding_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS live_uncertain_matches (
                    match_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS live_guard_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    blocked INTEGER NOT NULL,
                    reason TEXT,
                    pii_blocked INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS live_readiness_snapshots (
                    snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    payload TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS live_intel_schedule (
                    source TEXT PRIMARY KEY,
                    last_started TEXT,
                    last_completed TEXT,
                    last_state TEXT NOT NULL DEFAULT 'never',
                    last_error TEXT,
                    last_fact_count INTEGER NOT NULL DEFAULT 0,
                    runs INTEGER NOT NULL DEFAULT 0
                );
                """
            )

    def ping(self) -> bool:
        with self._session() as connection:
            row = connection.execute("SELECT 1").fetchone()
        return row is not None

    # -- scopes ---------------------------------------------------------
    def save_scope(self, scope: Scope) -> None:
        with self._lock, self._session() as connection:
            connection.execute(
                """
                INSERT INTO live_scopes
                    (scope_id, owner_id, targets, environment, approved,
                     expires_at, profiles)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (scope_id) DO UPDATE SET
                    owner_id = excluded.owner_id,
                    targets = excluded.targets,
                    environment = excluded.environment,
                    approved = excluded.approved,
                    expires_at = excluded.expires_at,
                    profiles = excluded.profiles
                """,
                (
                    scope.scope_id,
                    scope.owner_id,
                    _json(list(scope.targets)),
                    scope.environment,
                    1 if scope.approved else 0,
                    scope.expires_at.isoformat(),
                    _json(list(scope.profiles)),
                ),
            )

    def load_scopes(self) -> list[Scope]:
        with self._session() as connection:
            rows = connection.execute(
                "SELECT * FROM live_scopes ORDER BY scope_id"
            ).fetchall()
        return [self._scope_from_row(row) for row in rows]

    @staticmethod
    def _scope_from_row(row: sqlite3.Row) -> Scope:
        from datetime import datetime

        return Scope(
            scope_id=str(row["scope_id"]),
            owner_id=str(row["owner_id"]),
            targets=tuple(str(item) for item in json.loads(row["targets"])),
            environment=str(row["environment"]),
            approved=bool(row["approved"]),
            expires_at=datetime.fromisoformat(str(row["expires_at"])),
            profiles=tuple(str(item) for item in json.loads(row["profiles"])),
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
        with self._lock, self._session() as connection:
            connection.execute(
                """
                INSERT INTO live_scans
                    (scan_id, run_id, scope_id, target, profile_id, state,
                     warnings, assets, services, tls_findings)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (scan_id) DO UPDATE SET
                    run_id = excluded.run_id,
                    state = excluded.state,
                    warnings = excluded.warnings,
                    assets = excluded.assets,
                    services = excluded.services,
                    tls_findings = excluded.tls_findings,
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
                "warnings": list(json.loads(row["warnings"])),
                "assets": list(json.loads(row["assets"])),
                "services": list(json.loads(row["services"])),
                "tlsFindings": list(json.loads(row["tls_findings"])),
            }
            for row in rows
        ]

    # -- scheduled scans -----------------------------------------------
    def save_scan_schedule(self, schedule: ScanSchedule) -> None:
        with self._lock, self._session() as connection:
            connection.execute(
                """
                INSERT INTO live_scan_schedules
                    (schedule_id, owner_id, scope_id, target, profile_id,
                     interval_seconds, enabled, next_run_at, created_at,
                     authorization_id, last_run_at, last_scan_id, last_state,
                     last_error, runs)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (schedule_id) DO UPDATE SET
                    enabled = excluded.enabled,
                    next_run_at = excluded.next_run_at,
                    authorization_id = excluded.authorization_id,
                    last_run_at = excluded.last_run_at,
                    last_scan_id = excluded.last_scan_id,
                    last_state = excluded.last_state,
                    last_error = excluded.last_error,
                    runs = excluded.runs
                """,
                (
                    schedule.schedule_id,
                    schedule.owner_id,
                    schedule.scope_id,
                    schedule.target,
                    schedule.profile_id,
                    schedule.interval_seconds,
                    1 if schedule.enabled else 0,
                    schedule.next_run_at.isoformat(),
                    schedule.created_at.isoformat(),
                    schedule.authorization_id,
                    _iso(schedule.last_run_at),
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
                next_run_at=_parse_datetime(str(row["next_run_at"])),  # type: ignore[arg-type]
                created_at=_parse_datetime(str(row["created_at"])),  # type: ignore[arg-type]
                authorization_id=row["authorization_id"],
                last_run_at=_parse_datetime(row["last_run_at"]),
                last_scan_id=row["last_scan_id"],
                last_state=row["last_state"],
                last_error=row["last_error"],
                runs=int(row["runs"]),
            )
            for row in rows
        ]

    def delete_scan_schedule(self, schedule_id: str) -> None:
        with self._lock, self._session() as connection:
            connection.execute(
                "DELETE FROM live_scan_schedules WHERE schedule_id = ?",
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
            }
            for key, value in ingestions.items()
        }
        with self._lock, self._session() as connection:
            connection.execute("DELETE FROM live_intel_facts")
            connection.executemany(
                "INSERT INTO live_intel_facts (cve_id, payload) VALUES (?, ?)",
                fact_rows,
            )
            connection.execute("DELETE FROM live_findings")
            connection.executemany(
                "INSERT INTO live_findings (finding_id, payload) VALUES (?, ?)",
                finding_rows,
            )
            connection.execute("DELETE FROM live_uncertain_matches")
            connection.executemany(
                "INSERT INTO live_uncertain_matches (match_id, payload) "
                "VALUES (?, ?)",
                uncertain_rows,
            )
            for key, payload in (
                ("epss", epss_rows),
                ("kev", kev_rows),
                ("ingestions", ingestion_rows),
                ("idempotency", idempotency),
            ):
                connection.execute(
                    """
                    INSERT INTO live_intel_meta (key, payload) VALUES (?, ?)
                    ON CONFLICT (key) DO UPDATE SET payload = excluded.payload
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
        meta = {str(row["key"]): json.loads(row["payload"]) for row in meta_rows}
        facts = tuple(
            fact_from_dict(json.loads(row["payload"])) for row in fact_rows
        )
        findings = tuple(
            finding_from_dict(json.loads(row["payload"])) for row in finding_rows
        )
        uncertain_matches = tuple(
            uncertain_from_dict(json.loads(row["payload"]))
            for row in uncertain_rows
        )
        epss = tuple(
            EpssRecord(
                cve_id=str(item["cve_id"]),
                score=float(item["score"]),
                score_date=_parse_date(item["score_date"]),  # type: ignore[arg-type]
            )
            for item in meta.get("epss", [])
        )
        kev = tuple(
            KevRecord(
                cve_id=str(item["cve_id"]),
                date_added=_parse_date(item["date_added"]),  # type: ignore[arg-type]
                due_date=_parse_date(item["due_date"]),  # type: ignore[arg-type]
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
        with self._lock, self._session() as connection:
            connection.execute(
                """
                INSERT INTO live_intel_schedule
                    (source, last_started, last_completed, last_state,
                     last_error, last_fact_count, runs)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (source) DO UPDATE SET
                    last_started = excluded.last_started,
                    last_completed = excluded.last_completed,
                    last_state = excluded.last_state,
                    last_error = excluded.last_error,
                    last_fact_count = excluded.last_fact_count,
                    runs = excluded.runs
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
                "lastStarted": row["last_started"],
                "lastCompleted": row["last_completed"],
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
        with self._lock, self._session() as connection:
            connection.execute(
                """
                INSERT INTO live_guard_events (blocked, reason, pii_blocked)
                VALUES (?, ?, ?)
                """,
                (1 if blocked else 0, reason, 1 if pii_blocked else 0),
            )

    def guard_counts(self) -> dict[str, int]:
        with self._session() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS total,
                       COALESCE(SUM(CASE WHEN blocked = 0 THEN 1 ELSE 0 END), 0)
                           AS unblocked
                FROM live_guard_events
                """
            ).fetchone()
        return {"total": int(row["total"]), "unblocked": int(row["unblocked"])}

    def save_readiness(self, payload: dict[str, object]) -> None:
        with self._lock, self._session() as connection:
            connection.execute(
                "INSERT INTO live_readiness_snapshots (payload) VALUES (?)",
                (_json(payload),),
            )

    def latest_readiness(self) -> dict[str, object] | None:
        with self._session() as connection:
            row = connection.execute(
                "SELECT payload FROM live_readiness_snapshots "
                "ORDER BY snapshot_id DESC LIMIT 1"
            ).fetchone()
        return None if row is None else json.loads(row["payload"])

    def counts(self) -> dict[str, int]:
        with self._session() as connection:
            scopes = connection.execute(
                "SELECT COUNT(*) FROM live_scopes"
            ).fetchone()[0]
            scans = connection.execute(
                "SELECT COUNT(*) FROM live_scans"
            ).fetchone()[0]
            facts = connection.execute(
                "SELECT COUNT(*) FROM live_intel_facts"
            ).fetchone()[0]
        return {
            "scopes": int(scopes),
            "scans": int(scans),
            "facts": int(facts),
        }
