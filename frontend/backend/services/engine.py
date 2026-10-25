"""Connection settings and HTTP client for the optional live engine.

The live engine is a separate loopback-only FastAPI service composed from the
real Recon/Intel/Guard modules. The browser never talks to it directly: Flask
holds the API key, validates that the engine URL is loopback, and forwards the
requests. That keeps the key out of the browser and out of the built UI.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)

DEFAULT_ENGINE_BASE_URL = "http://127.0.0.1:8765"
DEFAULT_ENGINE_API_KEY = "sk-zerotrace-local-engine-7f3c9a2b"
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
MAX_RESPONSE_BYTES = 1_048_576
MIN_API_KEY_LENGTH = 16
MAX_API_KEY_LENGTH = 512


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


# The engine is loopback-only. Disable environment proxies so the engine API
# key cannot be sent through an unrelated HTTP proxy, and refuse redirects so a
# compromised loopback service cannot bounce the key to another host.
_OPENER = build_opener(ProxyHandler({}), _NoRedirect)


class EngineError(Exception):
    """A safe, user-facing live-engine error."""

    def __init__(self, message: str, status_code: int = 502) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class StoredEngineSettings:
    base_url: str
    api_key: str
    mode: str
    updated_at: str

    def public(self) -> dict[str, object]:
        return {
            "baseUrl": self.base_url,
            "mode": self.mode,
            "apiKeyConfigured": bool(self.api_key),
            "apiKeyHint": _key_hint(self.api_key),
            "updatedAt": self.updated_at,
        }


def _key_hint(api_key: str) -> str | None:
    if len(api_key) < 8:
        return None
    return f"{api_key[:3]}...{api_key[-4:]}"


def validate_base_url(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        raise ValueError("Engine URL is required.")
    if len(raw) > 512:
        raise ValueError("Engine URL is too long.")
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError as error:
        raise ValueError("Engine URL is not valid.") from error
    if parts.scheme not in {"http", "https"}:
        raise ValueError("Engine URL must use http or https.")
    if parts.username is not None or parts.password is not None:
        raise ValueError("Engine URL must not contain credentials.")
    host = (parts.hostname or "").lower()
    if host not in LOOPBACK_HOSTS:
        raise ValueError(
            "Engine URL must point to loopback (127.0.0.1, ::1, or localhost)."
        )
    if parts.path not in {"", "/"}:
        raise ValueError("Engine URL must not contain a path.")
    if parts.query or parts.fragment:
        raise ValueError("Engine URL must not contain a query or fragment.")
    resolved_port = port or (443 if parts.scheme == "https" else 80)
    if not 1 <= resolved_port <= 65535:
        raise ValueError("Engine URL port is invalid.")
    display_host = f"[{host}]" if ":" in host else host
    return f"{parts.scheme}://{display_host}:{resolved_port}"


def validate_api_key(value: str) -> str:
    key = (value or "").strip()
    if not MIN_API_KEY_LENGTH <= len(key) <= MAX_API_KEY_LENGTH:
        raise ValueError(
            f"Engine API key must be between {MIN_API_KEY_LENGTH} and "
            f"{MAX_API_KEY_LENGTH} characters."
        )
    if any(character.isspace() or ord(character) < 32 for character in key):
        raise ValueError("Engine API key must not contain whitespace.")
    return key


def validate_mode(value: str) -> str:
    mode = (value or "").strip().lower()
    if mode not in {"demo", "live"}:
        raise ValueError("Mode must be demo or live.")
    return mode


class EngineSettingsStore:
    """Persist connection settings in a private JSON file."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def _defaults(self) -> StoredEngineSettings:
        return StoredEngineSettings(
            base_url=validate_base_url(
                os.environ.get("ZEROTRACE_ENGINE_BASE_URL", DEFAULT_ENGINE_BASE_URL)
            ),
            api_key=os.environ.get(
                "ZEROTRACE_ENGINE_API_KEY", DEFAULT_ENGINE_API_KEY
            ),
            mode=validate_mode(os.environ.get("ZEROTRACE_ENGINE_MODE", "demo")),
            updated_at="",
        )

    def load(self) -> StoredEngineSettings:
        defaults = self._defaults()
        try:
            payload = json.loads(self.path.read_text("utf-8"))
        except (OSError, ValueError):
            return defaults
        if not isinstance(payload, dict):
            return defaults
        try:
            base_url = validate_base_url(str(payload.get("baseUrl", defaults.base_url)))
            api_key = validate_api_key(str(payload.get("apiKey", defaults.api_key)))
            mode = validate_mode(str(payload.get("mode", defaults.mode)))
        except ValueError:
            return defaults
        updated_at = payload.get("updatedAt")
        return StoredEngineSettings(
            base_url=base_url,
            api_key=api_key,
            mode=mode,
            updated_at=updated_at if isinstance(updated_at, str) else "",
        )

    def save(self, base_url: str, api_key: str, mode: str) -> StoredEngineSettings:
        settings = StoredEngineSettings(
            base_url=validate_base_url(base_url),
            api_key=validate_api_key(api_key),
            mode=validate_mode(mode),
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(
            dir=self.path.parent, prefix=".engine-settings-", suffix=".json"
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "baseUrl": settings.base_url,
                        "apiKey": settings.api_key,
                        "mode": settings.mode,
                        "updatedAt": settings.updated_at,
                    },
                    handle,
                )
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.chmod(temporary, 0o600)
            except OSError:
                pass
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return settings


class EngineClient:
    """Minimal, bounded HTTP client for the live engine."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        default_headers: dict[str, str] | None = None,
    ) -> None:
        self.base_url = validate_base_url(base_url).rstrip("/")
        self.api_key = api_key
        self.default_headers = dict(default_headers or {})

    def metrics(self, *, timeout: float = 5.0) -> str:
        """Fetch the engine's Prometheus text exposition.

        The engine metrics route is intentionally separate from the JSON API.
        It is only reachable on loopback and the BFF re-exposes it behind the
        same bearer-token gate as its own metrics endpoint.
        """

        if not self.api_key:
            raise EngineError("Live engine API key is not configured.", 400)
        request = Request(
            f"{self.base_url}/metrics",
            headers={"X-API-Key": self.api_key, "Accept": "text/plain"},
            method="GET",
        )
        try:
            with _OPENER.open(request, timeout=timeout) as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
        except (HTTPError, URLError, TimeoutError, OSError) as error:
            raise EngineError(
                "Live engine metrics are unavailable.", 502
            ) from error
        if len(body) > MAX_RESPONSE_BYTES:
            raise EngineError("Live engine metrics response was too large.", 502)
        try:
            return body.decode("utf-8")
        except UnicodeDecodeError as error:
            raise EngineError(
                "Live engine returned invalid metrics.", 502
            ) from error

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, object] | None = None,
        *,
        timeout: float = 10.0,
        extra_headers: dict[str, str] | None = None,
    ) -> object:
        if not self.api_key:
            raise EngineError("Live engine API key is not configured.", 400)
        if not path.startswith("/api/v1/"):
            raise EngineError("Invalid engine path.", 400)
        data = None
        headers = {
            "Accept": "application/json",
            "X-API-Key": self.api_key,
            **self.default_headers,
        }
        if extra_headers:
            headers.update(extra_headers)
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(
            f"{self.base_url}{path}", data=data, headers=headers, method=method
        )
        try:
            with _OPENER.open(request, timeout=timeout) as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as error:
            body = error.read(MAX_RESPONSE_BYTES)
            message = _error_message(body)
            if error.code == 401:
                raise EngineError(
                    "Live engine rejected the configured API key.", 502
                ) from error
            if error.code >= 500:
                raise EngineError(
                    "Live engine could not complete the request.", 502
                ) from error
            raise EngineError(message, error.code) from error
        except (URLError, TimeoutError, OSError) as error:
            raise EngineError(
                "Live engine is unreachable. Start it with python -m scripts.live_engine.",
                502,
            ) from error
        if len(body) > MAX_RESPONSE_BYTES:
            raise EngineError("Live engine response was too large.", 502)
        try:
            return json.loads(body.decode("utf-8")) if body else {}
        except (UnicodeDecodeError, ValueError) as error:
            raise EngineError("Live engine returned an invalid response.", 502) from error


def _error_message(body: bytes) -> str:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return "Live engine rejected the request."
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict):
            message = error.get("message")
            if isinstance(message, str) and message.strip():
                return message.strip()[:300]
    return "Live engine rejected the request."
