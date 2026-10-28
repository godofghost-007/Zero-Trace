"""Flask endpoints for the optional live engine.

These routes are a server-side adapter. The browser talks to Flask; Flask
validates input, keeps the API key private, and forwards to the loopback-only
live engine. Every state-changing route requires a JSON body, and scope/scan
creation requires an explicit ``authorized: true`` acknowledgement.
"""

from __future__ import annotations

import hmac
import re
import time
from pathlib import Path
from urllib.parse import urlencode, urlsplit
from uuid import uuid4

from flask import Blueprint, Response, current_app, g, jsonify, request

from .services.engine import (
    LOOPBACK_HOSTS,
    EngineClient,
    EngineError,
    EngineSettingsStore,
    validate_api_key,
    validate_base_url,
    validate_mode,
)

engine_api = Blueprint("engine_api", __name__)

SCAN_ID_PATTERN = re.compile(r"^[A-Za-z0-9-]{1,64}$")
SCOPE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
TERMINAL_SCAN_STATES = {
    "completed",
    "partial",
    "failed",
    "timed_out",
    "cancelled",
}


def _error(code: str, message: str, status: int):
    return jsonify({
        "error": {"code": code, "message": message},
        "request_id": getattr(g, "request_id", None),
    }), status


def _settings_path() -> Path:
    configured = current_app.config.get("ENGINE_SETTINGS_PATH")
    if configured:
        return Path(configured)
    return Path(current_app.config["DATA_DIR"]) / "engine-settings.json"


def _store() -> EngineSettingsStore:
    return EngineSettingsStore(_settings_path())


def _client() -> EngineClient:
    settings = _store().load()
    headers: dict[str, str] = {}
    trace_id = getattr(g, "trace_id", None)
    span_id = getattr(g, "span_id", None)
    if trace_id and span_id:
        headers["traceparent"] = f"00-{trace_id}-{span_id}-01"
    principal = getattr(g, "principal", None)
    if principal is not None:
        # The engine is loopback-only and trusts the BFF's API key. Forward the
        # authenticated identity so engine-side owner checks are per-user, not
        # a single shared ``local-operator`` identity.
        headers["X-ZeroTrace-Subject"] = str(principal.subject)
        headers["X-ZeroTrace-Role"] = str(principal.role)
    return EngineClient(
        settings.base_url, settings.api_key, default_headers=headers
    )


def _json_body() -> dict[str, object] | None:
    payload = request.get_json(silent=True)
    return payload if isinstance(payload, dict) else None


def _only(payload: dict[str, object], allowed: set[str]) -> dict[str, object]:
    unknown = set(payload) - allowed
    if unknown:
        raise ValueError(f"Unexpected field(s): {', '.join(sorted(unknown))}.")
    return {key: payload[key] for key in allowed if key in payload}


@engine_api.before_request
def protect_local_endpoints():
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if request.content_length and not request.is_json:
            return _error(
                "unsupported_media_type",
                "Content-Type must be application/json.",
                415,
            )
        origin = request.headers.get("Origin")
        if origin:
            try:
                origin_host = (urlsplit(origin).hostname or "").lower()
                request_host = (urlsplit(f"//{request.host}").hostname or "").lower()
            except ValueError:
                origin_host = None
                request_host = ""
            if origin_host != request_host and origin_host not in LOOPBACK_HOSTS:
                return _error("origin_denied", "Request origin is not allowed.", 403)
    return None


@engine_api.errorhandler(EngineError)
def handle_engine_error(error: EngineError):
    return _error("engine_error", str(error), error.status_code)


@engine_api.errorhandler(ValueError)
def handle_validation_error(error: ValueError):
    return _error("invalid_request", str(error), 400)


@engine_api.get("/settings/engine")
def get_engine_settings():
    return jsonify(_store().load().public())


@engine_api.put("/settings/engine")
def update_engine_settings():
    payload = _json_body()
    if payload is None:
        return _error("invalid_request", "A JSON object is required.", 400)
    payload = _only(payload, {"baseUrl", "mode", "apiKey"})
    current = _store().load()
    base_url = payload.get("baseUrl", current.base_url)
    mode = payload.get("mode", current.mode)
    api_key = payload.get("apiKey", "")
    if not isinstance(base_url, str) or not isinstance(mode, str):
        return _error("invalid_request", "baseUrl and mode must be strings.", 400)
    if api_key is None or api_key == "":
        resolved_key = current.api_key
    elif isinstance(api_key, str):
        resolved_key = validate_api_key(api_key)
    else:
        return _error("invalid_request", "apiKey must be a string.", 400)
    saved = _store().save(
        validate_base_url(base_url),
        resolved_key,
        validate_mode(mode),
    )
    return jsonify(saved.public())


@engine_api.post("/engine/test")
def test_engine():
    started = time.monotonic()
    try:
        client = _client()
        data = client.request("GET", "/api/v1/engine/status", timeout=4.0)
    except EngineError as error:
        return jsonify({
            "ok": False,
            "latencyMs": int((time.monotonic() - started) * 1000),
            "message": str(error),
        })
    if not isinstance(data, dict):
        return jsonify({
            "ok": False,
            "latencyMs": int((time.monotonic() - started) * 1000),
            "message": "Live engine returned an unexpected response.",
        })
    return jsonify({
        "ok": True,
        "latencyMs": int((time.monotonic() - started) * 1000),
        "service": data.get("service"),
        "mode": data.get("mode"),
        "profiles": data.get("profiles", []),
        "guard": data.get("guard", {}),
    })


@engine_api.get("/engine/status")
def engine_status():
    return jsonify(_client().request("GET", "/api/v1/engine/status", timeout=15.0))


@engine_api.get("/engine/metrics")
def engine_metrics():
    if not current_app.config.get("METRICS_ENABLED", False):
        return _error("metrics_disabled", "Metrics are not enabled.", 404)
    token = str(current_app.config.get("METRICS_TOKEN", "")).strip()
    if token:
        supplied = request.headers.get("Authorization", "")
        if not hmac.compare_digest(supplied, f"Bearer {token}"):
            return _error(
                "metrics_unauthorized", "A metrics token is required.", 401
            )
    return Response(
        _client().metrics(),
        mimetype="text/plain",
        headers={"Cache-Control": "no-store"},
    )


@engine_api.get("/engine/readiness")
def engine_readiness():
    return jsonify(
        _client().request("GET", "/api/v1/engine/readiness", timeout=6.0)
    )


@engine_api.get("/engine/scopes")
def engine_scopes():
    return jsonify(_client().request("GET", "/api/v1/recon/scopes", timeout=15.0))


@engine_api.delete("/engine/scopes/<scope_id>")
def delete_engine_scope(scope_id: str):
    if not SCOPE_ID_PATTERN.fullmatch(scope_id):
        return _error("invalid_request", "Scope ID is invalid.", 400)
    return jsonify(
        _client().request(
            "DELETE", f"/api/v1/recon/scopes/{scope_id}", timeout=15.0
        )
    )


@engine_api.post("/engine/scopes")
def create_engine_scope():
    payload = _json_body()
    if payload is None:
        return _error("invalid_request", "A JSON object is required.", 400)
    if payload.get("authorized") is not True:
        return _error(
            "authorization_required",
            "Confirm that you are authorized to test this target.",
            400,
        )
    fields = _only(
        payload,
        {
            "authorized",
            "scopeId",
            "targets",
            "environment",
            "profiles",
            "expiresInHours",
            "authorizationId",
        },
    )
    fields.pop("authorized", None)
    if not isinstance(fields.get("targets"), list) or not fields["targets"]:
        return _error("invalid_request", "At least one target is required.", 400)
    return jsonify(
        _client().request("POST", "/api/v1/recon/scopes", fields, timeout=15.0)
    ), 201


@engine_api.post("/engine/authorizations/challenges")
def create_engine_authorization_challenge():
    payload = _json_body()
    if payload is None:
        return _error("invalid_request", "A JSON object is required.", 400)
    fields = _only(payload, {"domain"})
    domain = fields.get("domain")
    if not isinstance(domain, str) or not domain.strip() or len(domain) > 253:
        return _error("invalid_request", "A domain is required.", 400)
    return jsonify(
        _client().request(
            "POST",
            "/api/v1/recon/authorizations/challenges",
            {"domain": domain.strip()},
            timeout=8.0,
        )
    ), 201


@engine_api.post("/engine/authorizations")
def verify_engine_authorization():
    payload = _json_body()
    if payload is None:
        return _error("invalid_request", "A JSON object is required.", 400)
    fields = _only(payload, {"challengeId", "profileIds"})
    challenge_id = fields.get("challengeId")
    profile_ids = fields.get("profileIds")
    if not isinstance(challenge_id, str) or not challenge_id.strip():
        return _error("invalid_request", "A challengeId is required.", 400)
    if (
        not isinstance(profile_ids, list)
        or not 1 <= len(profile_ids) <= 4
        or any(not isinstance(item, str) or not item.strip() for item in profile_ids)
    ):
        return _error(
            "invalid_request",
            "profileIds must contain one to four profile identifiers.",
            400,
        )
    return jsonify(
        _client().request(
            "POST",
            "/api/v1/recon/authorizations",
            {"challengeId": challenge_id, "profileIds": profile_ids},
            timeout=12.0,
        )
    ), 201


@engine_api.get("/engine/scans")
def engine_scans():
    return jsonify(_client().request("GET", "/api/v1/recon/scans", timeout=15.0))


@engine_api.post("/engine/scans")
def create_engine_scan():
    payload = _json_body()
    if payload is None:
        return _error("invalid_request", "A JSON object is required.", 400)
    if payload.get("authorized") is not True:
        return _error(
            "authorization_required",
            "Confirm that you are authorized to test this target.",
            400,
        )
    fields = _only(
        payload, {"authorized", "scopeId", "target", "profileId"}
    )
    fields.pop("authorized", None)
    return jsonify(
        _client().request("POST", "/api/v1/recon/scans", fields, timeout=60.0)
    ), 202


@engine_api.get("/engine/scans/<scan_id>")
def engine_scan_status(scan_id: str):
    if not SCAN_ID_PATTERN.fullmatch(scan_id):
        return _error("invalid_request", "Scan ID is invalid.", 400)
    return jsonify(
        _client().request(
            "GET", f"/api/v1/recon/scans/{scan_id}", timeout=15.0
        )
    )


@engine_api.get("/engine/scans/<scan_id>/result")
def engine_scan_result(scan_id: str):
    if not SCAN_ID_PATTERN.fullmatch(scan_id):
        return _error("invalid_request", "Scan ID is invalid.", 400)
    return jsonify(
        _client().request(
            "GET", f"/api/v1/recon/scans/{scan_id}/result", timeout=60.0
        )
    )


@engine_api.get("/engine/records")
def engine_records():
    """Return the latest persisted scan result per target/profile.

    The engine already stores bounded, normalized results. This adapter groups
    them by target so the Database view and report downloads can show Nmap,
    Subfinder, TLS metadata and synthetic inventory without exposing engine
    internals to the browser.
    """

    client = _client()
    payload = client.request("GET", "/api/v1/recon/scans", timeout=15.0)
    scans = payload.get("items", []) if isinstance(payload, dict) else []
    latest: dict[tuple[str, str, str], dict[str, object]] = {}
    for scan in scans:
        if not isinstance(scan, dict):
            continue
        scope_id = str(scan.get("scopeId", ""))
        target = str(scan.get("target", ""))
        profile_id = str(scan.get("profileId", ""))
        scan_id = str(scan.get("scanId", ""))
        if not scope_id or not target or not profile_id or not scan_id:
            continue
        latest[(scope_id, target, profile_id)] = scan

    grouped: dict[tuple[str, str], list[dict[str, object]]] = {}
    for (scope_id, target, profile_id), scan in latest.items():
        scan_id = str(scan.get("scanId", ""))
        state = str(scan.get("state", "unknown"))
        record: dict[str, object] = {
            "scanId": scan_id,
            "scopeId": scope_id,
            "target": target,
            "profileId": profile_id,
            "state": state,
            "assets": [],
            "services": [],
            "tlsFindings": [],
            "warnings": [],
        }
        if state in TERMINAL_SCAN_STATES and SCAN_ID_PATTERN.fullmatch(scan_id):
            try:
                result = client.request(
                    "GET",
                    f"/api/v1/recon/scans/{scan_id}/result",
                    timeout=20.0,
                )
            except EngineError:
                result = None
            if isinstance(result, dict):
                record.update(
                    {
                        "assets": result.get("assets", []),
                        "services": result.get("services", []),
                        "tlsFindings": result.get("tlsFindings", []),
                        "warnings": result.get("warnings", []),
                    }
                )
        grouped.setdefault((scope_id, target), []).append(record)

    items = []
    for (scope_id, target), records in grouped.items():
        records.sort(key=lambda item: str(item["profileId"]))
        items.append(
            {"scopeId": scope_id, "target": target, "scans": records}
        )
    items.sort(key=lambda item: (str(item["target"]), str(item["scopeId"])))
    return jsonify({"items": items})


@engine_api.get("/engine/schedules")
def engine_schedules():
    return jsonify(
        _client().request("GET", "/api/v1/recon/schedules", timeout=6.0)
    )


@engine_api.post("/engine/schedules")
def create_engine_schedule():
    payload = _json_body()
    if payload is None:
        return _error("invalid_request", "A JSON object is required.", 400)
    if payload.get("authorized") is not True:
        return _error(
            "authorization_required",
            "Confirm that you are authorized to schedule this target.",
            400,
        )
    fields = _only(
        payload,
        {
            "authorized",
            "scopeId",
            "target",
            "profileId",
            "intervalSeconds",
        },
    )
    fields.pop("authorized", None)
    interval = fields.get("intervalSeconds")
    if not isinstance(interval, int) or isinstance(interval, bool):
        return _error(
            "invalid_request", "intervalSeconds must be an integer.", 400
        )
    if not 300 <= interval <= 604800:
        return _error(
            "invalid_request",
            "intervalSeconds must be between 300 and 604800.",
            400,
        )
    return jsonify(
        _client().request("POST", "/api/v1/recon/schedules", fields, timeout=8.0)
    ), 201


@engine_api.post("/engine/schedules/<schedule_id>/run")
def run_engine_schedule(schedule_id: str):
    if not SCAN_ID_PATTERN.fullmatch(schedule_id):
        return _error("invalid_request", "Schedule ID is invalid.", 400)
    return jsonify(
        _client().request(
            "POST",
            f"/api/v1/recon/schedules/{schedule_id}/run",
            timeout=12.0,
        )
    )


@engine_api.delete("/engine/schedules/<schedule_id>")
def disable_engine_schedule(schedule_id: str):
    if not SCAN_ID_PATTERN.fullmatch(schedule_id):
        return _error("invalid_request", "Schedule ID is invalid.", 400)
    return jsonify(
        _client().request(
            "DELETE",
            f"/api/v1/recon/schedules/{schedule_id}",
            timeout=8.0,
        )
    )


@engine_api.post("/engine/guard/inspect")
def engine_guard_inspect():
    payload = _json_body()
    if payload is None:
        return _error("invalid_request", "A JSON object is required.", 400)
    fields = _only(payload, {"text"})
    text = fields.get("text")
    if not isinstance(text, str) or not text.strip():
        return _error("invalid_request", "Text is required.", 400)
    if len(text) > 8_000:
        return _error("invalid_request", "Text exceeds the 8,000 character limit.", 400)
    return jsonify(
        _client().request(
            "POST", "/api/v1/guard/inspect", {"text": text}, timeout=6.0
        )
    )


@engine_api.get("/engine/intel/status")
def engine_intel_status():
    return jsonify(
        _client().request("GET", "/api/v1/intel/status", timeout=6.0)
    )


@engine_api.post("/engine/intel/ingest")
def engine_intel_ingest():
    payload = _json_body()
    if payload is None:
        return _error("invalid_request", "A JSON object is required.", 400)
    if payload.get("source") != "kev":
        return _error(
            "invalid_request",
            "This console only exposes the CISA KEV feed.",
            400,
        )
    return jsonify(
        _client().request(
            "POST",
            "/api/v1/intel/ingestions",
            {"source": "kev"},
            timeout=40.0,
            extra_headers={"Idempotency-Key": uuid4().hex},
        )
    ), 202


@engine_api.get("/engine/intel/schedule")
def engine_intel_schedule():
    return jsonify(
        _client().request("GET", "/api/v1/intel/schedule", timeout=6.0)
    )


@engine_api.post("/engine/intel/schedule/run")
def run_engine_intel_schedule():
    source = request.args.get("source", "").strip().lower()
    if source and source not in {"nvd", "epss", "kev"}:
        return _error("invalid_request", "Scheduled feed source is not allowlisted.", 400)
    query = f"?source={source}" if source else ""
    return jsonify(
        _client().request(
            "POST",
            f"/api/v1/intel/schedule/run{query}",
            timeout=300.0,
        )
    )


@engine_api.get("/engine/intel/findings")
def engine_intel_findings():
    try:
        page = max(1, int(request.args.get("page", "1")))
        page_size = min(100, max(1, int(request.args.get("pageSize", "20"))))
    except ValueError:
        return _error("invalid_request", "Pagination values are invalid.", 400)
    query = urlencode({"page": page, "pageSize": page_size})
    return jsonify(
        _client().request(
            "GET", f"/api/v1/findings?{query}", timeout=6.0
        )
    )
