from datetime import datetime, timezone
from typing import Any

from flask import current_app

from ..extensions import db
from ..models import Asset, DemoScenario, EventOutbox, Finding, GuardEvent, PatchProposal, ScanRun, ScoreSnapshot, ServiceVulnerability
from .audit import append_entry, list_entries, reset_demo_chain, verify_chain

CORRELATION_ID = "corr_demo_7a20"
EVENT_IDS = {
    "asset": "EVT-DEMO-1042",
    "recon_score": "EVT-DEMO-1043",
    "finding": "EVT-DEMO-1044",
    "intel_score": "EVT-DEMO-1045",
    "guard": "EVT-DEMO-1046",
    "guard_score": "EVT-DEMO-1047",
}
ASSET_FIXTURE = {
    "id": "asset_zt_001",
    "hostname": "portal.zt-lab.test",
    "scope_id": "scope_demo_lab_01",
    "environment": "Lab / simulated",
    "services": [
        {"port": 443, "protocol": "TCP", "name": "HTTPS", "version": "nginx 1.24.x (fixture)"},
        {"port": 22, "protocol": "TCP", "name": "SSH", "version": "OpenSSH 9.x (fixture)"},
    ],
}
FINDING_FIXTURE = {
    "id": "finding_zt_001",
    "identifier": "ZT-DEMO-0001",
    "title": "Synthetic TLS gateway fixture",
    "cvss": 9.1,
    "epss": 0.64,
    "confidence": "0.82 — illustrative",
    "cpe": "cpe:2.3:a:demo:gateway:1.0:*:*:*:*:*:*:*",
}


def _score(stage: int) -> dict[str, Any]:
    aei = 20.0 if stage >= 1 else None
    vui = (35.0 if stage >= 2 else 0.0) if stage >= 1 else None
    # AIET is unknown until the sample request exists; a blocked request is not an unblocked attempt.
    aiet = 0.0 if stage >= 3 else None
    if aei is None or vui is None or aiet is None:
        score = None
    else:
        score = round(max(0.0, min(100.0, 100.0 - (0.40 * aei + 0.40 * vui + 0.20 * aiet))), 2)
    return {
        "score": score,
        "aei": aei,
        "vui": vui,
        "aiet": aiet,
        "formula_version": "demo-v1",
        "components": {
            "aei": {"value": aei, "numerator": 1 if stage >= 1 else 0, "denominator": 5 if stage >= 1 else 0, "note": "synthetic fixture services"},
            "vui": {"value": vui, "numerator": vui if vui is not None else 0, "denominator": 1 if stage >= 1 else 0, "note": "illustrative normalized index; not a model probability"},
            "aiet": {"value": aiet, "numerator": 0, "denominator": 1 if stage >= 3 else 0, "note": "blocked requests are not counted as unblocked attacks"},
        },
    }


def initialize_demo_state() -> None:
    scenario = db.session.get(DemoScenario, "default")
    if scenario is None:
        db.session.add(DemoScenario(id="default", stage=0, correlation_id=CORRELATION_ID))
    if db.session.get(ScoreSnapshot, "EVT-DEMO-1041") is None:
        base = _score(0)
        db.session.add(ScoreSnapshot(id="EVT-DEMO-1041", stage=0, **base))
    db.session.commit()


def _serialize_event(event: EventOutbox) -> dict[str, Any]:
    return {
        "id": event.id,
        "type": event.event_type,
        "entity": event.entity_id,
        "source": event.source,
        "correlation": event.correlation_id,
        "at": event.occurred_at.isoformat(),
        "status": event.status,
        "attempts": event.attempts,
        "lastError": event.last_error,
        "redisEntryId": event.redis_entry_id,
    }


def _serialize_audit(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "sequence": row["sequence"],
        "action": row["action"],
        "outcome": row["outcome"],
        "eventId": row["event_id"],
        "assetId": row["asset_id"],
        "findingId": row["finding_id"],
        "correlation": row["correlation_id"],
        "previousHash": row["previous_hash"],
        "hash": row["row_hash"],
        "at": row["occurred_at"],
    }


def get_state() -> dict[str, Any]:
    scenario = db.session.get(DemoScenario, "default")
    if scenario is None:
        initialize_demo_state()
        scenario = db.session.get(DemoScenario, "default")
    stage = int(scenario.stage)
    asset = db.session.get(Asset, ASSET_FIXTURE["id"])
    finding = db.session.get(Finding, FINDING_FIXTURE["id"])
    snapshots = ScoreSnapshot.query.order_by(ScoreSnapshot.created_at.asc()).all()
    snapshot = snapshots[-1] if snapshots else None
    readiness = {
        "score": snapshot.score,
        "aei": snapshot.aei,
        "vui": snapshot.vui,
        "aiet": snapshot.aiet,
        "formulaVersion": snapshot.formula_version,
        "components": snapshot.components or {},
    } if snapshot else _score(stage)
    event_rows = EventOutbox.query.order_by(EventOutbox.occurred_at.asc(), EventOutbox.id.asc()).all()
    audit_rows = list_entries(current_app.config["AUDIT_DB_PATH"])
    bus = __import__("backend.services.outbox", fromlist=["bus_status"]).bus_status()
    uri = current_app.config["SQLALCHEMY_DATABASE_URI"]
    database_type = "postgresql" if uri.startswith(("postgresql:", "postgresql+")) else "sqlite"
    return {
        "stage": stage,
        "correlationId": scenario.correlation_id,
        "asset": {
            "id": asset.id,
            "hostname": asset.hostname,
            "scope": asset.scope_id,
            "environment": asset.environment,
            "services": asset.services,
            "provenance": asset.provenance,
        } if asset else None,
        "finding": {
            "id": finding.id,
            "identifier": finding.identifier,
            "title": finding.title,
            "cvss": finding.cvss,
            "epss": finding.epss,
            "confidence": finding.confidence,
            "cpe": finding.cpe,
            "synthetic": finding.synthetic,
        } if finding else None,
        "events": [_serialize_event(row) for row in event_rows],
        "audit": [_serialize_audit(row) for row in audit_rows],
        "readiness": readiness,
        "backend": {
            "database": database_type,
            "databaseConnected": True,
            "eventBus": bus,
            "audit": {"store": "sqlite", **verify_chain(current_app.config["AUDIT_DB_PATH"])},
        },
    }


def _add_event(event_id: str, event_type: str, entity_type: str, entity_id: str, source: str, payload: dict[str, Any]) -> None:
    if db.session.get(EventOutbox, event_id) is None:
        db.session.add(EventOutbox(
            id=event_id,
            event_type=event_type,
            entity_type=entity_type,
            entity_id=entity_id,
            source=source,
            correlation_id=CORRELATION_ID,
            schema_version=1,
            payload=payload,
            status="pending",
        ))


def _add_snapshot(stage: int, snapshot_id: str) -> None:
    if db.session.get(ScoreSnapshot, snapshot_id) is not None:
        return
    values = _score(stage)
    db.session.add(ScoreSnapshot(id=snapshot_id, stage=stage, **values))
    _add_event(snapshot_id, "score_snapshot", "score_snapshot", snapshot_id, "Readiness", {
        "stage": stage,
        "score": values["score"],
        "formula_version": values["formula_version"],
    })


def advance_scenario(step: str) -> dict[str, Any]:
    targets = {"recon": 1, "intel": 2, "guard": 3}
    if step not in targets:
        raise ValueError("Unknown demo step")
    target = targets[step]
    scenario = db.session.get(DemoScenario, "default")
    if scenario is None:
        initialize_demo_state()
        scenario = db.session.get(DemoScenario, "default")
    if scenario.stage >= target:
        return get_state()
    if scenario.stage != target - 1:
        raise RuntimeError("Run the previous engine step first")

    now = datetime.now(timezone.utc)
    if step == "recon":
        if db.session.get(ScanRun, "RUN-DEMO-0081") is None:
            db.session.add(ScanRun(
                id="RUN-DEMO-0081", scope_id=ASSET_FIXTURE["scope_id"],
                status="completed_with_warnings", partial=True,
                warnings=["S3 check not queried: no cloud adapter configured."],
                started_at=now, completed_at=now,
            ))
        if db.session.get(Asset, ASSET_FIXTURE["id"]) is None:
            db.session.add(Asset(
                id=ASSET_FIXTURE["id"],
                hostname=ASSET_FIXTURE["hostname"],
                scope_id=ASSET_FIXTURE["scope_id"],
                environment=ASSET_FIXTURE["environment"],
                services=ASSET_FIXTURE["services"],
                provenance="fixture_set_a",
            ))
        _add_event(EVENT_IDS["asset"], "asset_created", "asset", ASSET_FIXTURE["id"], "Trace Recon", {"scope_id": ASSET_FIXTURE["scope_id"], "fixture": True})
        snapshot_id = EVENT_IDS["recon_score"]
    elif step == "intel":
        if db.session.get(Asset, ASSET_FIXTURE["id"]) is None:
            raise RuntimeError("Recon asset is missing; reset the demo and run Recon first")
        if db.session.get(Finding, FINDING_FIXTURE["id"]) is None:
            db.session.add(Finding(id=FINDING_FIXTURE["id"], **{k: v for k, v in FINDING_FIXTURE.items() if k != "id"}, synthetic=True))
            db.session.add(ServiceVulnerability(
                id="match_zt_001",
                asset_id=ASSET_FIXTURE["id"],
                finding_id=FINDING_FIXTURE["id"],
                match_method="fixture_alias",
                confidence=FINDING_FIXTURE["confidence"],
                evidence=["synthetic product alias", "synthetic version overlap"],
                review_state="needs_review",
            ))
            db.session.add(PatchProposal(
                id="proposal_demo_001", finding_id=FINDING_FIXTURE["id"],
                status="proposed", review_required=True, execution_allowed=False,
                due_window_hours=48, safe_next_action="Verify the software version and consult the vendor advisory.", synthetic=True,
            ))
        _add_event(EVENT_IDS["finding"], "vuln_matched", "service_vulnerability", "match_zt_001", "Trace Intel", {"asset_id": ASSET_FIXTURE["id"], "finding_id": FINDING_FIXTURE["id"], "synthetic": True})
        snapshot_id = EVENT_IDS["intel_score"]
    else:
        if db.session.get(Finding, FINDING_FIXTURE["id"]) is None:
            raise RuntimeError("Intel finding is missing; run the previous engine step first")
        audit_record = {
            "event_id": EVENT_IDS["guard"],
            "action": "attack_blocked",
            "outcome": "blocked",
            "asset_id": ASSET_FIXTURE["id"],
            "finding_id": FINDING_FIXTURE["id"],
            "correlation_id": CORRELATION_ID,
            "occurred_at": now.isoformat(),
        }
        audit_row = append_entry(current_app.config["AUDIT_DB_PATH"], audit_record)
        if db.session.get(GuardEvent, EVENT_IDS["guard"]) is None:
            db.session.add(GuardEvent(
                id=EVENT_IDS["guard"], action="attack_blocked", outcome="blocked",
                asset_id=ASSET_FIXTURE["id"], finding_id=FINDING_FIXTURE["id"],
                correlation_id=CORRELATION_ID, audit_sequence=audit_row["sequence"], audit_hash=audit_row["row_hash"],
            ))
        _add_event(EVENT_IDS["guard"], "attack_blocked", "guard_event", EVENT_IDS["guard"], "Trace Guard", {
            "asset_id": ASSET_FIXTURE["id"], "finding_id": FINDING_FIXTURE["id"], "audit_sequence": audit_row["sequence"], "synthetic": True,
        })
        snapshot_id = EVENT_IDS["guard_score"]

    scenario.stage = target
    scenario.updated_at = now
    _add_snapshot(target, snapshot_id)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise
    return get_state()


def reset_scenario() -> None:
    reset_demo_chain(current_app.config["AUDIT_DB_PATH"])
    EventOutbox.query.delete(synchronize_session=False)
    ScoreSnapshot.query.delete(synchronize_session=False)
    GuardEvent.query.delete(synchronize_session=False)
    PatchProposal.query.delete(synchronize_session=False)
    ServiceVulnerability.query.delete(synchronize_session=False)
    Finding.query.delete(synchronize_session=False)
    ScanRun.query.delete(synchronize_session=False)
    Asset.query.delete(synchronize_session=False)
    scenario = db.session.get(DemoScenario, "default")
    if scenario is None:
        scenario = DemoScenario(id="default", stage=0, correlation_id=CORRELATION_ID)
        db.session.add(scenario)
    scenario.stage = 0
    scenario.correlation_id = CORRELATION_ID
    scenario.updated_at = datetime.now(timezone.utc)
    baseline = _score(0)
    db.session.add(ScoreSnapshot(id="EVT-DEMO-1041", stage=0, **baseline))
    db.session.commit()
