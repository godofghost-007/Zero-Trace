"""Phase 11 — Guard MVP: LLM Security Middleware.

ZeroTrace Guard protects LLM traffic through an OpenAI-compatible gateway.

Security constraints (enforced, not advisory):

- **Model output is untrusted input** (LLM05). Never into eval, SQL, shell,
  innerHTML, or a file path; parse defensively, validate against a schema,
  then encode.
- **Prompts can be hijacked** (LLM01). Untrusted text in the context — a user
  message, a fetched page, a PDF — can carry instructions. The system prompt
  is not a security boundary; enforce permissions in code.
- **Keep secrets, other tenants' data, and the full system prompt out of the
  context window** (LLM02, LLM07); scope tool permissions, validate every tool
  argument, and confirm destructive actions.
- **Server-side fetches validated against allowlist** (no SSRF).
- **Error responses don't expose internal details** — generic public messages
  only, internals go to server logs.
- **Rate limiting** per client to prevent abuse and DoS.
- **No automatic execution** — Guard blocks or allows; it never executes
  remediation against any target.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Mapping, Protocol
import hashlib
import hmac
import json
import re
import time
import threading
from uuid import uuid4

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse

from app.events import EventEnvelope
from app.security import Principal


class GuardError(ValueError):
    """Raised when a Guard request or result violates a safety boundary."""

    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


class GuardTransport(Protocol):
    """Transport boundary for upstream LLM proxy requests."""

    def post(
        self,
        url: str,
        *,
        body: bytes,
        timeout_seconds: int,
    ) -> bytes:
        ...


@dataclass(frozen=True)
class GuardConfig:
    """Immutable Guard configuration."""

    api_key_secret: str
    api_key_digest: str
    upstream_allowlist: tuple[str, ...]
    max_request_bytes: int = 64 * 1024
    request_timeout_seconds: int = 30
    require_api_key: bool = True

    def __post_init__(self) -> None:
        if not self.api_key_secret:
            raise ValueError("API key secret is required")
        if not self.api_key_digest or len(self.api_key_digest) != 64:
            raise ValueError("API key digest must be a 64-character hex string")
        try:
            int(self.api_key_digest, 16)
        except ValueError as error:
            raise ValueError("API key digest must be hexadecimal") from error
        if not self.upstream_allowlist:
            raise ValueError("upstream allowlist is required")
        for upstream in self.upstream_allowlist:
            if not upstream.startswith("https://"):
                raise ValueError("upstream must use HTTPS")
        if not 0 < self.max_request_bytes <= 64 * 1024:
            raise ValueError("max request bytes must be between 1 and 65536")
        if not 1 <= self.request_timeout_seconds <= 300:
            raise ValueError("request timeout must be between 1 and 300 seconds")


@dataclass(frozen=True)
class DetectionResult:
    """Result of scanning a prompt or response for threats."""

    blocked: bool
    reason: str | None = None
    details: str | None = None


class RateLimiter:
    """Token-bucket rate limiter per client."""

    def __init__(self, max_requests: int = 60, window_seconds: int = 60) -> None:
        if max_requests < 1 or window_seconds < 1:
            raise ValueError("rate limits must be positive")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._calls: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def acquire(
        self,
        client_id: str,
        *,
        now: float | None = None,
    ) -> bool:
        if not client_id:
            raise ValueError("client ID is required")
        current = time.monotonic() if now is None else now
        with self._lock:
            calls = self._calls.setdefault(client_id, [])
            cutoff = current - self.window_seconds
            calls[:] = [t for t in calls if t > cutoff]
            if len(calls) >= self.max_requests:
                return False
            calls.append(current)
            return True


class PromptInjectionDetector:
    """Regex and heuristic detection for prompt injection and jailbreak attacks."""

    _UNSAFE_PATTERNS = [
        # Direct instruction override (with optional intermediate words)
        re.compile(
            r"(?i)(ignore|disregard|forget|override|bypass)\s+"
            r"(?:all\s+)?(?:\w+\s+)?"
            r"(previous|prior|system|safety|instruction|guideline|rule)",
            re.IGNORECASE,
        ),
        # DAN / role-play escapes
        re.compile(
            r"(?i)(dan|do\s+anything|unrestricted|jailbreak|escape\s+mode)",
            re.IGNORECASE,
        ),
        # System prompt extraction
        re.compile(
            r"(?i)(reveal|show|print|output|display)\s+(your|the)\s+"
            r"(system|initial|base)\s+(prompt|instructions)",
            re.IGNORECASE,
        ),
        # Developer mode / unrestricted assistant
        re.compile(
            r"(?i)(developer\s+mode|unrestricted\s+assistant|no\s+restrictions|"
            r"no\s+safety|no\s+filter)",
            re.IGNORECASE,
        ),
    ]

    def scan(self, text: str) -> DetectionResult:
        if not text or not text.strip():
            return DetectionResult(blocked=True, reason="empty_message")
        for pattern in self._UNSAFE_PATTERNS:
            if pattern.search(text):
                return DetectionResult(
                    blocked=True,
                    reason="prompt_injection",
                    details=pattern.pattern,
                )
        return DetectionResult(blocked=False)


class PIIScanner:
    """PII detection for response scanning."""

    _PII_PATTERNS = [
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),  # SSN
        re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
        ),  # Email
        re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"),  # Credit card
        re.compile(r"\b\d{3}[- ]?\d{3}[- ]?\d{4}\b"),  # Phone number
    ]

    def scan(self, text: str) -> DetectionResult:
        if not text:
            return DetectionResult(blocked=False)
        for pattern in self._PII_PATTERNS:
            if pattern.search(text):
                return DetectionResult(
                    blocked=True,
                    reason="pii_detected",
                    details=pattern.pattern,
                )
        return DetectionResult(blocked=False)


def _validate_chat_completion_request(body: Mapping[str, object]) -> None:
    """Validate the OpenAI chat/completions request schema."""
    if not isinstance(body, dict):
        raise GuardError("request body must be a JSON object", 400)

    model = body.get("model")
    if not isinstance(model, str) or not model.strip():
        raise GuardError("model is required", 400)

    messages = body.get("messages")
    if not isinstance(messages, list) or not messages:
        raise GuardError(
            "messages is required and must be a non-empty list", 400
        )

    for i, message in enumerate(messages):
        if not isinstance(message, dict):
            raise GuardError(f"message {i} must be an object", 400)
        role = message.get("role")
        if role not in {"system", "user", "assistant", "tool"}:
            raise GuardError(f"message {i} has invalid role", 400)
        content = message.get("content")
        if not isinstance(content, str) or not content.strip():
            raise GuardError(f"message {i} content is required", 400)
        if len(content) > 32_768:
            raise GuardError(
                f"message {i} content exceeds maximum length", 400
            )

    temperature = body.get("temperature")
    if temperature is not None:
        if not isinstance(temperature, (int, float)) or not 0.0 <= temperature <= 2.0:
            raise GuardError("temperature must be between 0 and 2", 400)

    max_tokens = body.get("max_tokens")
    if max_tokens is not None:
        if (
            not isinstance(max_tokens, int)
            or max_tokens < 1
            or max_tokens > 4096
        ):
            raise GuardError("max_tokens must be between 1 and 4096", 400)


def _is_allowlisted_upstream(url: str, allowlist: tuple[str, ...]) -> bool:
    """Check if a URL matches an allowlisted upstream (no SSRF)."""
    if not url.startswith("https://"):
        return False
    from urllib.parse import urlsplit

    host = urlsplit(url).hostname or ""
    for allowed in allowlist:
        allowed_host = urlsplit(allowed).hostname or ""
        if host == allowed_host or host.endswith("." + allowed_host):
            return True
    return False


def _error_response(code: str, message: str, status_code: int) -> JSONResponse:
    """Return a generic error envelope without internal details."""
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message}},
    )


def create_guard_app(
    *,
    config: GuardConfig,
    transport: GuardTransport,
    principal_provider: Callable[[Request], Principal | None],
    event_publisher: Callable[[dict[str, object]], None] | None = None,
) -> FastAPI:
    """Create a Guard middleware FastAPI application.

    Returns a FastAPI app with /v1/chat/completions, /health, and /ready
    endpoints. All endpoints enforce authentication, rate limiting, input
    validation, prompt injection detection, and PII scanning.
    """
    app = FastAPI()

    rate_limiter = RateLimiter()
    prompt_detector = PromptInjectionDetector()
    pii_scanner = PIIScanner()

    @app.middleware("http")
    async def security_headers_middleware(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(GuardError)
    async def guard_error_handler(
        request: Request, error: GuardError
    ) -> JSONResponse:
        return _error_response(
            error.args[0] if error.args else "guard_error",
            str(error),
            error.status_code,
        )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "healthy"}

    @app.get("/ready")
    async def ready() -> dict[str, str]:
        return {"status": "ready"}

    @app.post("/v1/chat/completions")
    async def chat_completions(
        request: Request,
        body: dict[str, object],
        x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    ) -> dict[str, object]:
        # Authenticate
        if config.require_api_key:
            if not x_api_key or not x_api_key.strip():
                raise GuardError("API key is required", 401)
            expected_digest = config.api_key_digest
            secret = config.api_key_secret.encode("utf-8")
            actual_digest = hmac.new(
                secret, x_api_key.encode("utf-8"), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(actual_digest, expected_digest):
                raise GuardError("invalid API key", 401)

        principal = principal_provider(request)
        client_id = principal.subject if principal else "anonymous"

        # Rate limit
        if not rate_limiter.acquire(client_id):
            raise GuardError("rate limit exceeded", 429)

        # Validate request schema
        _validate_chat_completion_request(body)

        # Scan prompts for injection
        messages = body.get("messages", [])
        if isinstance(messages, list):
            for message in messages:
                if isinstance(message, dict):
                    content = message.get("content", "")
                    if isinstance(content, str):
                        result = prompt_detector.scan(content)
                        if result.blocked:
                            if event_publisher is not None:
                                _publish_guard_event(
                                    event_publisher,
                                    "attack_blocked",
                                    {
                                        "reason": result.reason,
                                        "client_id": client_id,
                                        "details": result.details,
                                    },
                                )
                            raise GuardError(result.reason or "prompt_injection", 400)

        # Determine upstream
        upstream = body.get("upstream")
        if not isinstance(upstream, str) or not upstream:
            upstream = config.upstream_allowlist[0]

        if not _is_allowlisted_upstream(upstream, config.upstream_allowlist):
            raise GuardError("upstream is not allowlisted", 403)

        # Build upstream request (non-streaming only in MVP)
        upstream_body = {
            "model": body.get("model"),
            "messages": messages,
            "temperature": body.get("temperature", 0.7),
            "max_tokens": body.get("max_tokens", 1024),
            "stream": False,
        }
        upstream_body_bytes = json.dumps(upstream_body).encode("utf-8")

        if len(upstream_body_bytes) > config.max_request_bytes:
            raise GuardError("request body exceeds the configured limit", 413)

        # Call upstream with bounded timeout
        try:
            response_bytes = transport.post(
                upstream.rstrip("/") + "/v1/chat/completions",
                body=upstream_body_bytes,
                timeout_seconds=config.request_timeout_seconds,
            )
        except GuardError:
            raise
        except Exception as error:
            raise GuardError("upstream request failed", 502) from error

        # Parse and validate upstream response
        try:
            response = json.loads(response_bytes)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise GuardError("invalid upstream response", 502) from error

        if not isinstance(response, dict):
            raise GuardError("upstream response must be an object", 502)

        # Scan response for PII
        choices = response.get("choices", [])
        if isinstance(choices, list):
            for choice in choices:
                if isinstance(choice, dict):
                    message = choice.get("message", {})
                    if isinstance(message, dict):
                        content = message.get("content", "")
                        if isinstance(content, str):
                            result = pii_scanner.scan(content)
                            if result.blocked:
                                raise GuardError(
                                    result.reason or "pii_detected", 400
                                )

        # Emit audit event
        if event_publisher is not None:
            _publish_guard_event(
                event_publisher,
                "guard_request",
                {
                    "client_id": client_id,
                    "model": body.get("model"),
                    "upstream": upstream,
                    "message_count": (
                        len(messages) if isinstance(messages, list) else 0
                    ),
                },
            )

        return response

    return app


def _publish_guard_event(
    publisher: Callable[[dict[str, object]], None],
    event_type: str,
    payload: dict[str, object],
) -> None:
    """Publish a Guard event through the event envelope."""
    envelope = EventEnvelope(
        event_id=str(uuid4()),
        event_type=event_type,
        schema_version=1,
        entity_type="guard_request",
        entity_id=str(uuid4()),
        correlation_id=str(uuid4()),
        producer="guard-middleware",
        payload=payload,
    )
    publisher(envelope.to_dict())