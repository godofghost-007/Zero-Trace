from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.live_store import LiveStore
from app.recon import (
    AdapterResult,
    InMemoryReconRepository,
    ReconEngine,
    Scope,
    SyntheticAdapter,
)
from app.recon_api import ReconQueue
from app.scan_schedule import ScanScheduleRegistry
from app.target_policy import TargetPolicy

NOW = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)


def _queue(tmp_path: Path) -> tuple[ReconQueue, InMemoryReconRepository]:
    repository = InMemoryReconRepository()
    engine = ReconEngine(
        repository,
        {
            "synthetic_inventory_v1": SyntheticAdapter(
                AdapterResult(("lab.example.test",), (), ())
            )
        },
    )
    queue = ReconQueue(
        engine,
        repository,
        persistence=LiveStore(tmp_path / "live.sqlite3"),
        target_policy=TargetPolicy(denylist=("blocked.example",)),
    )
    scope = Scope(
        scope_id="scope-lab",
        owner_id="operator-1",
        targets=("lab.example.test",),
        environment="synthetic",
        approved=True,
        expires_at=NOW + timedelta(days=2),
        profiles=("synthetic_inventory_v1",),
    )
    queue.add_scope(scope)
    return queue, repository


def test_schedule_is_created_and_runs_only_when_due(tmp_path):
    queue, _repository = _queue(tmp_path)
    registry = ScanScheduleRegistry(
        queue,
        persistence=queue.persistence,
        target_policy=TargetPolicy(denylist=("blocked.example",)),
    )
    schedule = registry.create(
        owner_id="operator-1",
        scope_id="scope-lab",
        target="lab.example.test",
        profile_id="synthetic_inventory_v1",
        interval_seconds=600,
        now=NOW,
    )
    assert schedule.enabled is True
    assert schedule.next_run_at == NOW + timedelta(minutes=10)
    assert registry.run_due(now=NOW + timedelta(minutes=5)) == []

    results = registry.run_due(now=NOW + timedelta(minutes=10))
    assert results == [
        {
            "scheduleId": schedule.schedule_id,
            "state": "queued",
            "scanId": results[0]["scanId"],
        }
    ]
    updated = registry.get(schedule.schedule_id)
    assert updated is not None
    assert updated.runs == 1
    assert updated.last_scan_id == results[0]["scanId"]
    assert updated.next_run_at == NOW + timedelta(minutes=20)


def test_schedule_persists_across_registry_restart(tmp_path):
    queue, _repository = _queue(tmp_path)
    registry = ScanScheduleRegistry(queue, persistence=queue.persistence)
    schedule = registry.create(
        owner_id="operator-1",
        scope_id="scope-lab",
        target="lab.example.test",
        profile_id="synthetic_inventory_v1",
        interval_seconds=300,
        now=NOW,
    )

    restored = ScanScheduleRegistry(queue, persistence=queue.persistence)
    loaded = restored.get(schedule.schedule_id)
    assert loaded is not None
    assert loaded.target == "lab.example.test"
    assert loaded.interval_seconds == 300


def test_schedule_cannot_escape_scope_or_target_policy(tmp_path):
    queue, _repository = _queue(tmp_path)
    registry = ScanScheduleRegistry(
        queue,
        persistence=queue.persistence,
        target_policy=TargetPolicy(denylist=("blocked.example",)),
    )
    with pytest.raises(Exception, match="outside the approved scope"):
        registry.create(
            owner_id="operator-1",
            scope_id="scope-lab",
            target="other.example.test",
            profile_id="synthetic_inventory_v1",
            interval_seconds=300,
            now=NOW,
        )
    with pytest.raises(Exception, match="denylist"):
        registry.create(
            owner_id="operator-1",
            scope_id="scope-lab",
            target="blocked.example",
            profile_id="synthetic_inventory_v1",
            interval_seconds=300,
            now=NOW,
        )


def test_high_profile_schedule_requires_isolated_lab_authorization(tmp_path):
    queue, _repository = _queue(tmp_path)
    scope = Scope(
        scope_id="scope-high",
        owner_id="operator-1",
        targets=("lab.example.test",),
        environment="synthetic",
        approved=True,
        expires_at=NOW + timedelta(days=2),
        profiles=("service_inventory_high_v1",),
    )
    queue.add_scope(scope)
    registry = ScanScheduleRegistry(queue, persistence=queue.persistence)
    with pytest.raises(Exception, match="Authorization denied"):
        registry.create(
            owner_id="operator-1",
            scope_id="scope-high",
            target="lab.example.test",
            profile_id="service_inventory_high_v1",
            interval_seconds=300,
            now=NOW,
        )


def test_expired_scope_disables_schedule_without_queueing(tmp_path):
    queue, _repository = _queue(tmp_path)
    registry = ScanScheduleRegistry(queue, persistence=queue.persistence)
    schedule = registry.create(
        owner_id="operator-1",
        scope_id="scope-lab",
        target="lab.example.test",
        profile_id="synthetic_inventory_v1",
        interval_seconds=300,
        now=NOW,
    )
    results = registry.run_due(now=NOW + timedelta(days=3))
    assert results == [{"scheduleId": schedule.schedule_id, "state": "blocked"}]
    updated = registry.get(schedule.schedule_id)
    assert updated is not None
    assert updated.enabled is False
    assert "expired" in (updated.last_error or "")
    assert not any(job.profile_id == schedule.profile_id for job in queue._jobs.values())


def test_schedule_api_requires_operator_and_acknowledgement(tmp_path):
    from fastapi.testclient import TestClient

    from app.recon_api import create_recon_app
    from app.security import Principal

    queue, _repository = _queue(tmp_path)
    registry = ScanScheduleRegistry(queue, persistence=queue.persistence)
    client = TestClient(
        create_recon_app(
            queue,
            lambda request: Principal(
                request.headers.get("X-Principal-ID", ""),
                request.headers.get("X-Principal-Role", ""),
            ),
            schedule_registry=registry,
        )
    )
    payload = {
        "scopeId": "scope-lab",
        "target": "lab.example.test",
        "profileId": "synthetic_inventory_v1",
        "intervalSeconds": 300,
    }
    denied = client.post(
        "/api/v1/recon/schedules",
        headers={"X-Principal-ID": "operator-1", "X-Principal-Role": "viewer"},
        json=payload,
    )
    assert denied.status_code == 403
    created = client.post(
        "/api/v1/recon/schedules",
        headers={"X-Principal-ID": "operator-1", "X-Principal-Role": "operator"},
        json=payload,
    )
    assert created.status_code == 201
    schedule_id = created.json()["scheduleId"]
    listed = client.get(
        "/api/v1/recon/schedules",
        headers={"X-Principal-ID": "operator-1", "X-Principal-Role": "viewer"},
    )
    assert [item["scheduleId"] for item in listed.json()["items"]] == [schedule_id]
    disabled = client.delete(
        f"/api/v1/recon/schedules/{schedule_id}",
        headers={"X-Principal-ID": "operator-1", "X-Principal-Role": "operator"},
    )
    assert disabled.status_code == 200
    assert disabled.json()["enabled"] is False
