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
from typing import Callable, Mapping, Protocol
import hashlib
import hmac
import json
import re
import time
import threading
from uuid import uuid4

from fastapi import FastAPI, Header, Request, Response
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


class GuardDetector(Protocol):
    """Adapter boundary for built-in or external prompt classifiers."""

    def scan(self, text: str) -> "DetectionResult":
        ...


@dataclass(frozen=True)
class GuardConfig:
    """Immutable Guard configuration.

    ``api_key_digest`` is the current BFF credential. During rotation, set
    ``previous_api_key_digest`` as well, deploy the new BFF key, then remove the
    previous digest. Both values are HMAC digests, never provider keys.
    """

    api_key_secret: str
    api_key_digest: str
    upstream_allowlist: tuple[str, ...]
    max_request_bytes: int = 64 * 1024
    request_timeout_seconds: int = 30
    require_api_key: bool = True
    previous_api_key_digest: str | None = None
    allowed_models: tuple[str, ...] = ()
    pii_action: str = "block"

    def __post_init__(self) -> None:
        if not self.api_key_secret:
            raise ValueError("API key secret is required")
        for name, digest in (
            ("API key digest", self.api_key_digest),
            ("previous API key digest", self.previous_api_key_digest),
        ):
            if digest is None:
                continue
            if len(digest) != 64:
                raise ValueError(
                    f"{name} must be a 64-character hex string"
                )
            try:
                int(digest, 16)
            except ValueError as error:
                raise ValueError(f"{name} must be hexadecimal") from error
        if not self.upstream_allowlist:
            raise ValueError("upstream allowlist is required")
        for upstream in self.upstream_allowlist:
            if not upstream.startswith("https://"):
                raise ValueError("upstream must use HTTPS")
        if not 0 < self.max_request_bytes <= 64 * 1024:
            raise ValueError("max request bytes must be between 1 and 65536")
        if not 1 <= self.request_timeout_seconds <= 300:
            raise ValueError("request timeout must be between 1 and 300 seconds")
        if self.pii_action not in {"block", "redact"}:
            raise ValueError("pii_action must be block or redact")
        if self.allowed_models and any(
            not isinstance(model, str) or not model.strip()
            for model in self.allowed_models
        ):
            raise ValueError("allowed models must be non-empty strings")


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
        # A claim that the safety layer is disabled is itself a jailbreak
        # attempt, even when it does not contain an instruction-override verb.
        re.compile(
            r"(?i)(safety|content)\s+filter\s+(?:is\s+)?(?:disabled|off)",
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
    """PII detection and bounded redaction for model responses.

    Detection is intentionally conservative and deterministic. It is a
    last-line control, not a claim that the regexes cover every jurisdiction or
    every personal-data category.
    """

    _PII_PATTERNS = (
        ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED:SSN]"),
        (
            "email",
            re.compile(
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
            ),
            "[REDACTED:EMAIL]",
        ),
        (
            "credit_card",
            re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"),
            "[REDACTED:CARD]",
        ),
        (
            "phone",
            re.compile(r"\b\d{3}[- ]?\d{3}[- ]?\d{4}\b"),
            "[REDACTED:PHONE]",
        ),
    )

    def scan(self, text: str) -> DetectionResult:
        if not text:
            return DetectionResult(blocked=False)
        for _label, pattern, _replacement in self._PII_PATTERNS:
            if pattern.search(text):
                return DetectionResult(
                    blocked=True,
                    reason="pii_detected",
                    details=pattern.pattern,
                )
        return DetectionResult(blocked=False)

    def redact(self, text: str) -> tuple[DetectionResult, str]:
        """Return the detection result and a redacted copy of ``text``."""

        if not text:
            return DetectionResult(blocked=False), text
        detected = False
        redacted = text
        for _label, pattern, replacement in self._PII_PATTERNS:
            if pattern.search(redacted):
                detected = True
                redacted = pattern.sub(replacement, redacted)
        return (
            DetectionResult(
                blocked=detected,
                reason="pii_detected" if detected else None,
            ),
            redacted,
        )


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

    top_p = body.get("top_p")
    if top_p is not None:
        if not isinstance(top_p, (int, float)) or not 0.0 <= top_p <= 1.0:
            raise GuardError("top_p must be between 0 and 1", 400)

    max_tokens = body.get("max_tokens")
    if max_tokens is not None:
        if (
            not isinstance(max_tokens, int)
            or max_tokens < 1
            or max_tokens > 4096
        ):
            raise GuardError("max_tokens must be between 1 and 4096", 400)


def _upstream_parts(url: str) -> tuple[str, int | None, str] | None:
    """Return a normalized (host, port, path) tuple or ``None``.

    Guard only accepts an HTTPS origin with no credentials, query, fragment, or
    non-root path. This prevents a caller from smuggling a different endpoint
    through the client-controlled ``upstream`` field while still matching an
    allowlisted hostname.
    """

    from urllib.parse import urlsplit

    if not isinstance(url, str) or not url.startswith("https://"):
        return None
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    if (
        parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
        or parts.path not in {"", "/"}
    ):
        return None
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return None
    if port not in {None, 443}:
        return None
    return host, port, "/"


def _is_allowlisted_upstream(url: str, allowlist: tuple[str, ...]) -> bool:
    """Check if a URL matches an allowlisted HTTPS origin (no SSRF)."""

    candidate = _upstream_parts(url)
    if candidate is None:
        return False
    host = candidate[0]
    for allowed in allowlist:
        allowed_parts = _upstream_parts(allowed)
        if allowed_parts is None:
            continue
        allowed_host = allowed_parts[0]
        if allowed_host.startswith("*."):
            # A wildcard must be explicit. An exact allowlist entry never
            # implies its subdomains.
            suffix = allowed_host[2:]
            if suffix and host.endswith("." + suffix):
                return True
        elif host == allowed_host:
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
    detector: GuardDetector | None = None,
) -> FastAPI:
    """Create a Guard middleware FastAPI application.

    Returns a FastAPI app with /v1/chat/completions, /health, and /ready
    endpoints. All endpoints enforce authentication, rate limiting, input
    validation, prompt injection detection, and PII scanning.
    """
    app = FastAPI()

    rate_limiter = RateLimiter()
    prompt_detector = detector or PromptInjectionDetector()
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
        http_response: Response,
        x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    ) -> dict[str, object]:
        # Authenticate. During key rotation both the current and the previous
        # digest are accepted, so the BFF can be redeployed without a Guard
        # outage. Both values are digests, not provider keys.
        if config.require_api_key:
            if not x_api_key or not x_api_key.strip():
                raise GuardError("API key is required", 401)
            secret = config.api_key_secret.encode("utf-8")
            actual_digest = hmac.new(
                secret, x_api_key.encode("utf-8"), hashlib.sha256
            ).hexdigest()
            accepted = [config.api_key_digest]
            if config.previous_api_key_digest:
                accepted.append(config.previous_api_key_digest)
            if not any(
                hmac.compare_digest(actual_digest, expected)
                for expected in accepted
            ):
                raise GuardError("invalid API key", 401)

        principal = principal_provider(request)
        client_id = principal.subject if principal else "anonymous"

        # Rate limit
        if not rate_limiter.acquire(client_id):
            raise GuardError("rate limit exceeded", 429)

        # Validate request schema
        _validate_chat_completion_request(body)

        if config.allowed_models:
            model = str(body.get("model", ""))
            if model not in config.allowed_models:
                raise GuardError("model is not allowlisted", 403)

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

        upstream_parts = _upstream_parts(upstream)
        if (
            upstream_parts is None
            or not _is_allowlisted_upstream(upstream, config.upstream_allowlist)
        ):
            raise GuardError("upstream is not allowlisted", 403)
        canonical_upstream = f"https://{upstream_parts[0]}"

        # Build upstream request (non-streaming only in MVP)
        upstream_body = {
            "model": body.get("model"),
            "messages": messages,
            "temperature": body.get("temperature", 0.7),
            "max_tokens": body.get("max_tokens", 1024),
            "stream": False,
        }
        if body.get("top_p") is not None:
            upstream_body["top_p"] = body["top_p"]
        upstream_body_bytes = json.dumps(upstream_body).encode("utf-8")

        if len(upstream_body_bytes) > config.max_request_bytes:
            raise GuardError("request body exceeds the configured limit", 413)

        # Call upstream with bounded timeout
        try:
            response_bytes = transport.post(
                canonical_upstream + "/v1/chat/completions",
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

        # Scan response for PII. ``block`` is the safe default. ``redact``
        # keeps the response usable while replacing detected values with typed
        # placeholders, and records that a transformation happened.
        choices = response.get("choices", [])
        redacted = False
        if isinstance(choices, list):
            for choice in choices:
                if not isinstance(choice, dict):
                    continue
                message = choice.get("message", {})
                if not isinstance(message, dict):
                    continue
                content = message.get("content", "")
                if not isinstance(content, str):
                    continue
                result, safe_content = pii_scanner.redact(content)
                if not result.blocked:
                    continue
                if config.pii_action == "block":
                    if event_publisher is not None:
                        _publish_guard_event(
                            event_publisher,
                            "response_blocked",
                            {
                                "reason": result.reason,
                                "client_id": client_id,
                                "model": body.get("model"),
                            },
                        )
                    raise GuardError(result.reason or "pii_detected", 400)
                message["content"] = safe_content
                redacted = True

        # Emit audit event
        if event_publisher is not None:
            _publish_guard_event(
                event_publisher,
                "guard_request",
                {
                    "client_id": client_id,
                    "model": body.get("model"),
                    "upstream": canonical_upstream,
                    "message_count": (
                        len(messages) if isinstance(messages, list) else 0
                    ),
                    "pii_redacted": redacted,
                },
            )

        if redacted:
            http_response.headers["X-ZeroTrace-PII-Redacted"] = "true"
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