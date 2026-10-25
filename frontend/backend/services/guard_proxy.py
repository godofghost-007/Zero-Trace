"""Server-side client for the loopback-only Guard reverse proxy.

The BFF never gives the provider key or the Guard credential to the browser.
It sends the user's chat payload to Guard over loopback, Guard authenticates the
BFF credential, inspects the prompt, and only then calls the allowlisted
provider.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import urlsplit

import requests

LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
MAX_GUARD_RESPONSE_BYTES = 2 * 1024 * 1024


class GuardProxyError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 502):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


def validate_guard_base_url(value: str) -> str:
    """Return a normalized loopback Guard origin or raise ``ValueError``."""

    raw = str(value or "").strip()
    if not raw:
        raise ValueError("ZEROTRACE_GUARD_PROXY_URL is required")
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as error:
        raise ValueError("ZEROTRACE_GUARD_PROXY_URL is not a valid URL") from error
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("ZEROTRACE_GUARD_PROXY_URL must use HTTP or HTTPS")
    if parsed.username or parsed.password:
        raise ValueError("ZEROTRACE_GUARD_PROXY_URL must not contain userinfo")
    if parsed.query or parsed.fragment:
        raise ValueError(
            "ZEROTRACE_GUARD_PROXY_URL must not contain a query or fragment"
        )
    if parsed.path not in {"", "/"}:
        raise ValueError("ZEROTRACE_GUARD_PROXY_URL must be an origin without a path")
    host = (parsed.hostname or "").lower().rstrip(".")
    if host not in LOOPBACK_HOSTS:
        raise ValueError("ZEROTRACE_GUARD_PROXY_URL must be a loopback address")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("ZEROTRACE_GUARD_PROXY_URL has an invalid port")
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc = f"{netloc}:{port}"
    return f"{parsed.scheme}://{netloc}"


@dataclass(frozen=True)
class GuardProxySettings:
    enabled: bool
    base_url: str
    api_key: str
    timeout_seconds: float = 30.0


class GuardProxyClient:
    def __init__(self, settings: GuardProxySettings):
        if not settings.enabled:
            raise GuardProxyError(
                "guard_disabled", "The Guard proxy is not enabled.", 503
            )
        self.base_url = validate_guard_base_url(settings.base_url)
        self.api_key = settings.api_key.strip()
        if len(self.api_key) < 16:
            raise GuardProxyError(
                "guard_misconfigured",
                "The BFF-to-Guard credential is not configured.",
                503,
            )
        if not 1 <= settings.timeout_seconds <= 120:
            raise GuardProxyError(
                "guard_misconfigured",
                "The Guard proxy timeout is outside the allowed range.",
                503,
            )
        self.timeout_seconds = settings.timeout_seconds

    def chat(self, payload: dict[str, object]) -> tuple[dict[str, object], dict[str, str]]:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "X-API-Key": self.api_key,
        }
        try:
            response = requests.post(
                f"{self.base_url}/v1/chat/completions",
                data=body,
                headers=headers,
                timeout=(3.05, self.timeout_seconds),
                allow_redirects=False,
                # The Guard URL is loopback-only. Do not let an environment
                # proxy receive the BFF-to-Guard credential.
                proxies={"http": None, "https": None},
            )
        except requests.RequestException as error:
            raise GuardProxyError(
                "guard_unavailable", "The Guard proxy is unavailable.", 503
            ) from error

        if 300 <= response.status_code < 400:
            raise GuardProxyError(
                "guard_redirect_rejected",
                "The Guard proxy returned a redirect.",
                502,
            )
        if response.status_code >= 400:
            message = "The Guard proxy rejected the request."
            code = "guard_rejected"
            try:
                error_body = response.json()
                error = error_body.get("error")
                if isinstance(error, dict):
                    message = str(error.get("message") or message)
                    code = str(error.get("code") or code)
            except (ValueError, AttributeError):
                pass
            raise GuardProxyError(code, message, response.status_code)

        if len(response.content) > MAX_GUARD_RESPONSE_BYTES:
            raise GuardProxyError(
                "guard_response_too_large",
                "The Guard response exceeded the allowed size.",
                502,
            )
        try:
            result = response.json()
        except ValueError as error:
            raise GuardProxyError(
                "guard_invalid_response",
                "The Guard proxy returned an invalid response.",
                502,
            ) from error
        if not isinstance(result, dict):
            raise GuardProxyError(
                "guard_invalid_response",
                "The Guard proxy returned an invalid response.",
                502,
            )
        headers_out = {}
        if response.headers.get("X-ZeroTrace-PII-Redacted", "").lower() == "true":
            headers_out["X-ZeroTrace-PII-Redacted"] = "true"
        return result, headers_out
