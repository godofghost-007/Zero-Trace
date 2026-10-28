import hmac

from flask import Blueprint, Response, current_app, g, jsonify, request
from sqlalchemy import text

from .extensions import db
from .models import Asset, EventOutbox, Finding, GuardEvent, PatchProposal, ScanRun, ScoreSnapshot, ServiceVulnerability
from .services.audit import verify_chain
from .services.outbox import bus_status, relay_pending
from .services.scenario import advance_scenario, get_state, reset_scenario

api = Blueprint("api", __name__)


def _error(code: str, message: str, status: int):
    return jsonify({"error": {"code": code, "message": message}, "request_id": getattr(g, "request_id", None)}), status


@api.get("/health")
def health():
    return jsonify({"status": "ok", "service": "zerotrace-flask", "mode": "local-simulated-demo"})


@api.get("/ready")
def ready():
    try:
        db.session.execute(text("SELECT 1"))
        db_state = "connected"
    except Exception:
        db.session.rollback()
        db_state = "unavailable"
    payload = {"ready": db_state == "connected", "database": db_state, "event_bus": bus_status()}
    return jsonify(payload), (200 if payload["ready"] else 503)


@api.get("/metrics")
def metrics():
    """Prometheus scrape endpoint, disabled unless explicitly enabled.

    When a token is configured, the scraper must send
    ``Authorization: Bearer <token>``. The endpoint is in the public auth list
    only so Prometheus does not need an interactive session; the token check is
    the authorization boundary.
    """

    if not current_app.config.get("METRICS_ENABLED", False):
        return _error("metrics_disabled", "Metrics are not enabled.", 404)
    token = str(current_app.config.get("METRICS_TOKEN", "")).strip()
    if token:
        supplied = request.headers.get("Authorization", "")
        if not hmac.compare_digest(supplied, f"Bearer {token}"):
            return _error("metrics_unauthorized", "A metrics token is required.", 401)
    registry = current_app.extensions.get("metrics")
    if registry is None:
        return _error("metrics_unavailable", "Metrics are not initialized.", 503)
    return Response(
        registry.render(),
        mimetype="text/plain",
        headers={"Cache-Control": "no-store"},
    )


@api.get("/demo/state")
def demo_state():
    return jsonify(get_state())


@api.post("/demo/reset")
def demo_reset():
    if not current_app.config.get("DEMO_MODE", True):
        return _error("demo_mode_disabled", "Demo reset is disabled.", 403)
    try:
        reset_scenario()
    except Exception:
        db.session.rollback()
        raise
    return jsonify(get_state())


@api.post("/demo/steps/<step>")
def demo_step(step: str):
    if not current_app.config.get("DEMO_MODE", True):
        return _error("demo_mode_disabled", "Simulated engine actions are disabled.", 403)
    if step not in {"recon", "intel", "guard"}:
        return _error("unknown_step", "Allowed steps are recon, intel, and guard.", 404)
    try:
        state = advance_scenario(step)
    except RuntimeError as exc:
        db.session.rollback()
        return _error("step_order_conflict", str(exc), 409)
    except ValueError as exc:
        db.session.rollback()
        return _error("invalid_step", str(exc), 400)
    relay = relay_pending()
    state = get_state()
    state["relay"] = relay
    return jsonify(state)


@api.get("/dashboard/summary")
def dashboard_summary():
    state = get_state()
    state["summary"] = {
        "assets": Asset.query.count(),
        "scan_runs": ScanRun.query.count(),
        "matches": ServiceVulnerability.query.count(),
        "proposals": PatchProposal.query.count(),
        "guard_events": GuardEvent.query.count(),
        "events": EventOutbox.query.count(),
    }
    return jsonify(state)


def _event_context(rows: list[EventOutbox]) -> dict[str, tuple[str | None, str | None]]:
    """Resolve explicit target/scope context without changing the event envelope."""

    asset_ids: set[str] = set()
    for row in rows:
        payload = row.payload if isinstance(row.payload, dict) else {}
        if row.entity_type == "asset":
            asset_ids.add(row.entity_id)
        asset_id = payload.get("asset_id")
        if isinstance(asset_id, str) and asset_id:
            asset_ids.add(asset_id)
    assets = Asset.query.filter(Asset.id.in_(asset_ids)).all() if asset_ids else []
    by_id = {asset.id: asset for asset in assets}
    contexts: dict[str, tuple[str | None, str | None]] = {}
    for row in rows:
        payload = row.payload if isinstance(row.payload, dict) else {}
        asset = by_id.get(row.entity_id) if row.entity_type == "asset" else None
        if asset is None:
            asset = by_id.get(payload.get("asset_id"))
        scope_id = payload.get("scope_id") or payload.get("scopeId")
        if not isinstance(scope_id, str) or not scope_id:
            scope_id = asset.scope_id if asset else None
        target = payload.get("target") or payload.get("hostname")
        if not isinstance(target, str) or not target:
            target = asset.hostname if asset else None
        contexts[row.id] = (scope_id, target)
    return contexts


@api.get("/events")
def events():
    limit = request.args.get("limit", default=50, type=int) or 50
    limit = max(1, min(100, limit))
    rows = EventOutbox.query.order_by(EventOutbox.occurred_at.desc()).limit(limit).all()
    contexts = _event_context(rows)
    return jsonify({"items": [
        {"id": row.id, "type": row.event_type, "entityType": row.entity_type, "entity": row.entity_id,
         "source": row.source, "correlation": row.correlation_id, "at": row.occurred_at.isoformat(),
         "status": row.status, "attempts": row.attempts, "lastError": row.last_error,
         "redisEntryId": row.redis_entry_id, "schemaVersion": row.schema_version, "payload": row.payload,
         "scopeId": contexts[row.id][0], "target": contexts[row.id][1]}
        for row in rows
    ], "pending": EventOutbox.query.filter_by(status="pending").count(), "bus": bus_status()})


@api.post("/events/relay-pending")
def relay_events():
    return jsonify(relay_pending())


@api.get("/assets")
def assets():
    rows = Asset.query.order_by(Asset.created_at.desc()).all()
    return jsonify({"items": [
        {"id": row.id, "hostname": row.hostname, "scope": row.scope_id, "environment": row.environment,
         "services": row.services, "provenance": row.provenance, "createdAt": row.created_at.isoformat()}
        for row in rows
    ]})


@api.get("/recon/scans")
def recon_scans():
    rows = ScanRun.query.order_by(ScanRun.started_at.desc()).all()
    return jsonify({"items": [{"id": row.id, "scope": row.scope_id, "status": row.status,
                              "partial": row.partial, "warnings": row.warnings,
                              "startedAt": row.started_at.isoformat(), "completedAt": row.completed_at.isoformat()} for row in rows]})


@api.get("/assets/<asset_id>")
def asset_detail(asset_id: str):
    row = db.session.get(Asset, asset_id)
    if row is None:
        return _error("asset_not_found", "Asset does not exist in the local demo state.", 404)
    return jsonify({"id": row.id, "hostname": row.hostname, "scope": row.scope_id, "environment": row.environment, "services": row.services, "provenance": row.provenance, "createdAt": row.created_at.isoformat()})


@api.get("/intel/status")
def intel_status():
    state = get_state()
    return jsonify({"mode": "synthetic-fixture-only", "feeds": {"nvd": "not_queried", "epss": "not_queried", "kev": "not_queried"}, "model": "not_loaded", "lastSync": None, "matchCount": ServiceVulnerability.query.count(), "stage": state["stage"]})


@api.get("/matches")
def matches():
    rows = ServiceVulnerability.query.order_by(ServiceVulnerability.created_at.desc()).all()
    items = []
    for match in rows:
        finding = db.session.get(Finding, match.finding_id)
        items.append({"id": match.id, "assetId": match.asset_id, "findingId": match.finding_id,
                      "identifier": finding.identifier if finding else None, "title": finding.title if finding else None,
                      "method": match.match_method, "confidence": match.confidence, "evidence": match.evidence,
                      "reviewState": match.review_state, "synthetic": bool(finding.synthetic) if finding else True})
    return jsonify({"items": items})


@api.get("/patch-proposals")
def patch_proposals():
    rows = PatchProposal.query.order_by(PatchProposal.created_at.desc()).all()
    items = []
    for row in rows:
        finding = db.session.get(Finding, row.finding_id)
        items.append({"id": row.id, "findingId": row.finding_id, "identifier": finding.identifier if finding else None,
                      "status": row.status, "reviewRequired": row.review_required, "executionAllowed": row.execution_allowed,
                      "dueWindowHours": row.due_window_hours, "synthetic": row.synthetic,
                      "safeNextAction": row.safe_next_action})
    return jsonify({"items": items, "mode": "proposal-only-demo"})


@api.get("/guard/status")
def guard_status():
    return jsonify({"mode": "simulated-only", "proxyEnabled": False, "regex": "not_invoked", "onnx": "not_loaded",
                    "upstream": "not_configured", "piiScanner": "not_invoked", "audit": verify_chain(current_app.config["AUDIT_DB_PATH"])})


@api.get("/guard/events")
def guard_events():
    rows = GuardEvent.query.order_by(GuardEvent.created_at.desc()).all()
    return jsonify({"items": [{"id": row.id, "action": row.action, "outcome": row.outcome,
                              "assetId": row.asset_id, "findingId": row.finding_id,
                              "correlation": row.correlation_id, "auditSequence": row.audit_sequence,
                              "auditHash": row.audit_hash, "createdAt": row.created_at.isoformat()} for row in rows]})


@api.get("/guard/audit/verify")
def audit_verify():
    return jsonify({"store": "sqlite", **verify_chain(current_app.config["AUDIT_DB_PATH"])})


@api.get("/readiness/current")
def readiness_current():
    state = get_state()
    return jsonify(state["readiness"] | {"calculatedAt": ScoreSnapshot.query.order_by(ScoreSnapshot.created_at.desc()).first().created_at.isoformat()})


@api.get("/readiness/history")
def readiness_history():
    rows = ScoreSnapshot.query.order_by(ScoreSnapshot.created_at.asc()).all()
    return jsonify({"items": [{"id": row.id, "stage": row.stage, "score": row.score, "aei": row.aei,
                              "vui": row.vui, "aiet": row.aiet, "components": row.components,
                              "formulaVersion": row.formula_version, "calculatedAt": row.created_at.isoformat()} for row in rows]})
