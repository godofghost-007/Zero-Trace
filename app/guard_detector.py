"""Optional external prompt-injection detector adapter.

The built-in regex detector is deterministic and dependency-free. A deployment
that has a dedicated classifier can point Guard at an HTTPS endpoint that
accepts ``{"text": "..."}`` and returns ``{"blocked": true|false, "reason":
"..."}``. The adapter is fail-closed: a timeout, non-2xx response, malformed
body, or oversized response raises a Guard error instead of allowing the
request through.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from .guard import DetectionResult, GuardError

MAX_RESPONSE_BYTES = 64 * 1024


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


@dataclass(frozen=True)
class ExternalDetectorConfig:
    url: str
    api_key: str = ""
    timeout_seconds: int = 5
    max_response_bytes: int = MAX_RESPONSE_BYTES

    def __post_init__(self) -> None:
        parts = urlsplit(self.url)
        if (
            parts.scheme != "https"
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.fragment
        ):
            raise ValueError("external detector URL must be an HTTPS endpoint")
        if not 1 <= self.timeout_seconds <= 60:
            raise ValueError("external detector timeout is outside the range")
        if not 0 < self.max_response_bytes <= MAX_RESPONSE_BYTES:
            raise ValueError("external detector response limit is outside the range")


class HttpExternalDetector:
    """Bounded HTTPS adapter for an external classifier."""

    def __init__(
        self,
        config: ExternalDetectorConfig,
        *,
        opener=None,
    ) -> None:
        self.config = config
        self._opener = opener or build_opener(ProxyHandler({}), _NoRedirect)

    def scan(self, text: str) -> DetectionResult:
        body = json.dumps({"text": text}).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "ZeroTrace-Guard-Detector/1",
        }
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        request = Request(
            self.config.url,
            data=body,
            method="POST",
            headers=headers,
        )
        try:
            with self._opener.open(
                request, timeout=self.config.timeout_seconds
            ) as response:
                payload = response.read(self.config.max_response_bytes + 1)
        except (HTTPError, URLError, TimeoutError, OSError) as error:
            raise GuardError("external detector unavailable", 503) from error
        if len(payload) > self.config.max_response_bytes:
            raise GuardError("external detector response was too large", 503)
        try:
            result = json.loads(payload)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise GuardError("external detector returned invalid JSON", 503) from error
        if not isinstance(result, dict) or not isinstance(
            result.get("blocked"), bool
        ):
            raise GuardError("external detector returned an invalid result", 503)
        reason = result.get("reason")
        details = result.get("details")
        return DetectionResult(
            blocked=result["blocked"],
            reason=str(reason)[:128] if reason is not None else None,
            details=str(details)[:512] if details is not None else None,
        )
