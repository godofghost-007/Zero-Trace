"""Flask endpoints for the optional live engine.

These routes are a server-side adapter. The browser talks to Flask; Flask
validates input, keeps the API key private, and forwards to the loopback-only
live engine. Every state-changing route requires a JSON body, and scope/scan
creation requires an explicit ``authorized: true`` acknowledgement.
"""

from __future__ import annotations

from pathlib import Path
import re
import time
from urllib.parse import urlencode, urlsplit
from uuid import uuid4

from flask import Blueprint, current_app, g, jsonify, request

from .services.engine import (
    EngineClient,
    EngineError,
    EngineSettingsStore,
    LOOPBACK_HOSTS,
    validate_api_key,
    validate_base_url,
    validate_mode,
)

engine_api = Blueprint("engine_api", __name__)

SCAN_ID_PATTERN = re.compile(r"^[A-Za-z0-9-]{1,64}$")


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
    return EngineClient(settings.base_url, settings.api_key)


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
                origin_host = urlsplit(origin).hostname
            except ValueError:
                origin_host = None
            if origin_host not in LOOPBACK_HOSTS:
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
    return jsonify(_client().request("GET", "/api/v1/engine/status", timeout=6.0))


@engine_api.get("/engine/readiness")
def engine_readiness():
    return jsonify(
        _client().request("GET", "/api/v1/engine/readiness", timeout=6.0)
    )


@engine_api.get("/engine/scopes")
def engine_scopes():
    return jsonify(_client().request("GET", "/api/v1/recon/scopes", timeout=6.0))


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
        {"authorized", "scopeId", "targets", "environment", "profiles", "expiresInHours"},
    )
    fields.pop("authorized", None)
    if not isinstance(fields.get("targets"), list) or not fields["targets"]:
        return _error("invalid_request", "At least one target is required.", 400)
    return jsonify(
        _client().request("POST", "/api/v1/recon/scopes", fields, timeout=8.0)
    ), 201


@engine_api.get("/engine/scans")
def engine_scans():
    return jsonify(_client().request("GET", "/api/v1/recon/scans", timeout=6.0))


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
        _client().request("POST", "/api/v1/recon/scans", fields, timeout=12.0)
    ), 202


@engine_api.get("/engine/scans/<scan_id>")
def engine_scan_status(scan_id: str):
    if not SCAN_ID_PATTERN.fullmatch(scan_id):
        return _error("invalid_request", "Scan ID is invalid.", 400)
    return jsonify(
        _client().request(
            "GET", f"/api/v1/recon/scans/{scan_id}", timeout=6.0
        )
    )


@engine_api.get("/engine/scans/<scan_id>/result")
def engine_scan_result(scan_id: str):
    if not SCAN_ID_PATTERN.fullmatch(scan_id):
        return _error("invalid_request", "Scan ID is invalid.", 400)
    return jsonify(
        _client().request(
            "GET", f"/api/v1/recon/scans/{scan_id}/result", timeout=8.0
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
