"""Authenticated BFF route for OpenAI-compatible Guard traffic.

Applications should call this route instead of talking to a model provider
directly. The BFF adds the Guard credential, and Guard adds the provider key
only after inspecting the prompt.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from flask import Blueprint, current_app, g, jsonify, request

from .services.guard_proxy import (
    LOOPBACK_HOSTS,
    GuardProxyClient,
    GuardProxyError,
    GuardProxySettings,
)

guard_api = Blueprint("guard_api", __name__)

ALLOWED_REQUEST_FIELDS = {
    "model",
    "messages",
    "temperature",
    "top_p",
    "max_tokens",
}
MAX_MESSAGES = 50
MAX_MESSAGE_CHARS = 32_768


def _error(code: str, message: str, status: int):
    return jsonify({
        "error": {"code": code, "message": message},
        "request_id": getattr(g, "request_id", None),
    }), status


@guard_api.before_request
def protect_guard_endpoint():
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


@guard_api.errorhandler(GuardProxyError)
def handle_guard_error(error: GuardProxyError):
    return _error(error.code, str(error), error.status_code)


def _client() -> GuardProxyClient:
    return GuardProxyClient(
        GuardProxySettings(
            enabled=bool(current_app.config.get("GUARD_PROXY_ENABLED", False)),
            base_url=str(current_app.config.get("GUARD_PROXY_URL", "")),
            api_key=str(current_app.config.get("GUARD_BFF_API_KEY", "")),
            timeout_seconds=float(
                current_app.config.get("GUARD_PROXY_TIMEOUT_SECONDS", 30)
            ),
        )
    )


def _validate_payload(payload: dict[str, object]) -> dict[str, object]:
    unknown = set(payload) - ALLOWED_REQUEST_FIELDS - {"stream"}
    if unknown:
        raise ValueError(
            f"Unexpected field(s): {', '.join(sorted(unknown))}."
        )
    if payload.get("stream") is True:
        raise ValueError("Streaming is not supported by the Guard route.")
    cleaned: dict[str, object] = {}

    model = payload.get("model")
    if model is not None:
        if not isinstance(model, str) or not model.strip():
            raise ValueError("model must be a non-empty string.")
        if len(model) > 128:
            raise ValueError("model is too long.")
        cleaned["model"] = model.strip()

    messages = payload.get("messages")
    if not isinstance(messages, list) or not 1 <= len(messages) <= MAX_MESSAGES:
        raise ValueError(f"messages must contain 1 to {MAX_MESSAGES} items.")
    total_chars = 0
    cleaned_messages: list[dict[str, str]] = []
    for item in messages:
        if not isinstance(item, dict):
            raise TypeError("Each message must be an object.")
        if set(item) - {"role", "content"}:
            raise ValueError("Messages only accept role and content.")
        role = item.get("role")
        content = item.get("content")
        if role not in {"system", "user", "assistant"}:
            raise ValueError("Message role must be system, user, or assistant.")
        if not isinstance(content, str) or not content:
            raise ValueError("Message content must be a non-empty string.")
        total_chars += len(content)
        cleaned_messages.append({"role": role, "content": content})
    if total_chars > MAX_MESSAGE_CHARS:
        raise ValueError("Prompt exceeds the Guard message size limit.")
    cleaned["messages"] = cleaned_messages

    for name, lower, upper in (
        ("temperature", 0.0, 2.0),
        ("top_p", 0.0, 1.0),
    ):
        if name in payload:
            value = payload[name]
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise ValueError(f"{name} must be a number.")
            if not lower <= float(value) <= upper:
                raise ValueError(f"{name} is outside the allowed range.")
            cleaned[name] = float(value)
    if "max_tokens" in payload:
        value = payload["max_tokens"]
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError("max_tokens must be an integer.")
        if not 1 <= value <= 4096:
            raise ValueError("max_tokens is outside the allowed range.")
        cleaned["max_tokens"] = value
    return cleaned


@guard_api.post("/guard/chat")
def guard_chat():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _error("invalid_request", "A JSON object is required.", 400)
    try:
        cleaned = _validate_payload(payload)
    except (TypeError, ValueError) as error:
        return _error("invalid_request", str(error), 400)
    result, headers = _client().chat(cleaned)
    response = jsonify(result)
    for name, value in headers.items():
        response.headers[name] = value
    return response
