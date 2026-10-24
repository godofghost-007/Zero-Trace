"""PostgreSQL parity tests for the live-engine persistence contract.

These tests are opt-in because they require a disposable PostgreSQL server::

    set ZEROTRACE_TEST_DATABASE_URL=postgresql://zerotrace:zerotrace-dev-only@127.0.0.1:5432/zerotrace
    py -3.13 -m pytest tests/test_live_store_pg.py -q

Each test creates and drops its own database. No table in the configured
database is touched.
"""

from __future__ import annotations

import os
import secrets
import time
from datetime import UTC, date, datetime
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import psycopg
import pytest
from fastapi.testclient import TestClient

from app.intel import (
    ServiceFinding,
    UncertainMatch,
    VulnerabilityFact,
    calculate_priority,
)
from app.intel_api import Ingestion
from app.intel_feeds import EpssRecord, KevRecord
from app.live_store_pg import PostgresLiveStore
from app.recon import Scope
from scripts.live_engine import EngineSettings, create_live_engine

TEST_DATABASE_URL = os.environ.get("ZEROTRACE_TEST_DATABASE_URL", "").strip()
MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations"

pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="ZEROTRACE_TEST_DATABASE_URL is not configured",
)


def _database_urls(raw: str, database: str) -> tuple[str, str]:
    plain = raw.replace("postgresql+psycopg://", "postgresql://", 1)
    parts = urlsplit(plain)
    admin = urlunsplit(parts._replace(path="/postgres"))
    target = urlunsplit(parts._replace(path=f"/{database}"))
    return admin, target


def _connect(url: str, **kwargs):
    """Retry transient Docker Desktop port-proxy failures."""
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            return psycopg.connect(url, connect_timeout=10, **kwargs)
        except psycopg.OperationalError as error:
            last_error = error
            if attempt < 2:
                time.sleep(0.5 * (attempt + 1))
    assert last_error is not None
    raise last_error


@pytest.fixture()
def store():
    database = f"zerotrace_live_test_{secrets.token_hex(5)}"
    admin_url, target_url = _database_urls(TEST_DATABASE_URL, database)
    with _connect(admin_url, autocommit=True) as connection:
        connection.execute(f'CREATE DATABASE "{database}"')
    try:
        with _connect(target_url) as connection:
            for migration in sorted(MIGRATIONS.glob("*.sql")):
                connection.execute(migration.read_text(encoding="utf-8"))
        live_store = PostgresLiveStore.from_url(target_url)
        try:
            yield live_store
        finally:
            live_store.close()
    finally:
        with _connect(admin_url, autocommit=True) as connection:
            connection.execute(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)')


def test_postgres_live_store_round_trips_scope_scan_and_readiness(store):
    scope = Scope(
        scope_id="scope-store",
        owner_id="local-operator",
        targets=("lab.example.test",),
        environment="synthetic",
        approved=True,
        expires_at=datetime(2026, 10, 25, 12, 0, tzinfo=UTC),
        profiles=("synthetic_inventory_v1",),
    )
    store.save_scope(scope)
    assert store.load_scopes() == [scope]

    store.save_scan(
        scan_id="scan-1",
        run_id="run-1",
        scope_id=scope.scope_id,
        target="lab.example.test",
        profile_id="synthetic_inventory_v1",
        state="completed",
        warnings=("warning",),
        assets=("lab.example.test",),
        services=(
            {
                "asset": "lab.example.test",
                "protocol": "tcp",
                "port": 443,
                "product": "https",
                "version": None,
                "tlsStatus": "valid",
            },
        ),
        tls_findings=({"subject": "lab.example.test", "status": "valid"},),
    )
    restored = store.load_scans()[0]
    assert restored["scanId"] == "scan-1"
    assert restored["services"][0]["product"] == "https"
    assert restored["tlsFindings"][0]["status"] == "valid"

    store.record_guard_event(
        blocked=True, reason="prompt_injection", pii_blocked=False
    )
    assert store.guard_counts() == {"total": 1, "unblocked": 0}
    store.save_readiness({"score": None, "components": {"database": "ready"}})
    assert store.latest_readiness()["components"]["database"] == "ready"
    assert store.counts() == {"scopes": 1, "scans": 1, "facts": 0}


def test_postgres_live_store_round_trips_intel_findings_and_schedule(store):
    fact = VulnerabilityFact(
        cve_id="CVE-2025-0001",
        source="nvd",
        source_record_id="CVE-2025-0001",
        source_revision="nvd-1",
        summary="Synthetic fact for persistence testing.",
        cpe_names=("cpe:2.3:a:nginx:nginx:1.25.0:*:*:*:*:*:*:*",),
        cvss_score=9.8,
        epss_score=0.42,
        kev=True,
        published_at=datetime(2025, 1, 1, tzinfo=UTC),
        modified_at=datetime(2025, 1, 2, tzinfo=UTC),
        retrieved_at=datetime(2025, 1, 3, tzinfo=UTC),
        schema_version=1,
        payload_digest="a" * 64,
        epss_score_date=date(2025, 1, 3),
        kev_due_date=date(2025, 2, 1),
    )
    epss = EpssRecord(
        cve_id="CVE-2025-0001", score=0.42, score_date=date(2025, 1, 3)
    )
    kev = KevRecord(
        cve_id="CVE-2025-0001",
        date_added=date(2025, 1, 1),
        due_date=date(2025, 2, 1),
        known_ransomware_campaign_use=False,
    )
    finding = ServiceFinding(
        "service-1",
        "asset-1",
        "CVE-2025-0001",
        "exact_cpe",
        1.0,
        ("cpe:2.3:a:nginx:nginx:1.25.0:*:*:*:*:*:*:*",),
        "fresh",
        calculate_priority(
            cvss_score=9.8,
            epss_score=0.42,
            kev=True,
            exposed=True,
            confidence=1.0,
        ),
    )
    uncertain = UncertainMatch(
        "service-2",
        "asset-2",
        "CVE-2025-0001",
        "missing_service_version",
        (),
        "fresh",
        "nvd-1",
    )
    ingestion = Ingestion(
        ingestion_id="ing-1",
        source="nvd",
        state="completed",
        fact_count=1,
        error=None,
    )
    store.save_intel_state(
        facts=(fact,),
        epss_records=(epss,),
        kev_records=(kev,),
        ingestions={"nvd": ingestion},
        idempotency={"key-1": ("CVE-2025-0001", "nvd-1")},
        findings=(finding,),
        uncertain_matches=(uncertain,),
    )
    intel = store.load_intel_state()
    assert intel["facts"][0].cpe_names == fact.cpe_names
    assert intel["facts"][0].kev_due_date == date(2025, 2, 1)
    assert intel["epss"][0].score == 0.42
    assert intel["kev"][0].cve_id == "CVE-2025-0001"
    assert intel["findings"][0].priority.score == finding.priority.score
    assert intel["uncertain_matches"][0].reason == "missing_service_version"
    assert intel["ingestions"]["nvd"].fact_count == 1
    assert intel["idempotency"]["key-1"] == ("CVE-2025-0001", "nvd-1")
    assert store.counts()["facts"] == 1

    store.save_schedule_state(
        "nvd",
        last_started="2026-10-25T10:00:00+00:00",
        last_completed="2026-10-25T10:00:05+00:00",
        last_state="completed",
        last_error=None,
        last_fact_count=1,
        runs=1,
    )
    schedule = store.load_schedule_state()["nvd"]
    assert schedule["state"] == "completed"
    assert schedule["lastFactCount"] == 1
    assert schedule["runs"] == 1


def test_live_engine_uses_the_postgresql_store(store):
    settings = EngineSettings(
        api_key="sk-test-live-engine-postgres-123",
        auth_secret=b"test-secret-at-least-32-bytes-long!",
    )
    headers = {"X-API-Key": settings.api_key}
    engine = create_live_engine(settings, store=store)
    with TestClient(engine) as client:
        status = client.get("/api/v1/engine/status", headers=headers)
        assert status.status_code == 200
        assert status.json()["storage"] == "postgresql"

        scope = client.post(
            "/api/v1/recon/scopes",
            headers=headers,
            json={
                "scopeId": "scope-postgres",
                "targets": ["lab.example.test"],
                "environment": "synthetic",
                "profiles": ["synthetic_inventory_v1"],
                "expiresInHours": 1,
            },
        )
        assert scope.status_code == 201, scope.text
        scan = client.post(
            "/api/v1/recon/scans",
            headers=headers,
            json={
                "scopeId": "scope-postgres",
                "target": "lab.example.test",
                "profileId": "synthetic_inventory_v1",
            },
        )
        assert scan.status_code == 202, scan.text
        scan_id = scan.json()["scanId"]
        for _ in range(60):
            current = client.get(
                f"/api/v1/recon/scans/{scan_id}", headers=headers
            )
            assert current.status_code == 200
            if current.json()["state"] == "completed":
                break
            time.sleep(0.1)
        else:
            pytest.fail("scan did not reach a terminal state")

        assert [scope.scope_id for scope in store.load_scopes()] == [
            "scope-postgres"
        ]
        assert store.load_scans()[0]["state"] == "completed"
