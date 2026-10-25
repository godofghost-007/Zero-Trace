"""HTTP transport for the Guard reverse proxy.

The provider credential is added here, on the server side. A browser or BFF
never receives it. The transport re-checks the upstream allowlist and refuses
redirects so an allowlisted host cannot bounce the request to an arbitrary
destination.
"""

from __future__ import annotations

from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from .guard import GuardError, _is_allowlisted_upstream

MAX_RESPONSE_BYTES = 1_048_576


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class HttpGuardTransport:
    """Bounded HTTPS transport with a server-side provider key."""

    def __init__(
        self,
        *,
        provider_api_key: str,
        upstream_allowlist: tuple[str, ...],
        max_response_bytes: int = MAX_RESPONSE_BYTES,
    ) -> None:
        if not provider_api_key:
            raise ValueError("provider API key is required")
        if not upstream_allowlist:
            raise ValueError("upstream allowlist is required")
        if not 0 < max_response_bytes <= MAX_RESPONSE_BYTES:
            raise ValueError("max response bytes is outside the allowed range")
        self._provider_api_key = provider_api_key
        self._allowlist = upstream_allowlist
        self._max_response_bytes = max_response_bytes
        # Ignore HTTP(S)_PROXY. The provider credential must go directly to the
        # allowlisted origin, never through an environment-configured proxy.
        self._opener = build_opener(ProxyHandler({}), _NoRedirect)

    def post(self, url: str, *, body: bytes, timeout_seconds: int) -> bytes:
        parts = urlsplit(url)
        try:
            port = parts.port
        except ValueError as error:
            raise GuardError("upstream is not allowlisted", 403) from error
        if (
            parts.scheme != "https"
            or parts.query
            or parts.fragment
            or parts.path != "/v1/chat/completions"
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or port not in {None, 443}
        ):
            raise GuardError("upstream is not allowlisted", 403)
        origin = f"https://{parts.hostname}"
        if not _is_allowlisted_upstream(origin, self._allowlist):
            raise GuardError("upstream is not allowlisted", 403)
        request = Request(
            url,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self._provider_api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "ZeroTrace-Guard/1",
            },
        )
        try:
            with self._opener.open(request, timeout=timeout_seconds) as response:
                payload = response.read(self._max_response_bytes + 1)
        except (HTTPError, URLError, TimeoutError, OSError) as error:
            raise GuardError("upstream request failed", 502) from error
        if len(payload) > self._max_response_bytes:
            raise GuardError("upstream response was too large", 502)
        return payload
