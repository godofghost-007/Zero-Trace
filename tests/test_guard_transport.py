import unittest
from unittest.mock import patch

from app.guard import GuardError
from app.guard_transport import HttpGuardTransport


class _Response:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, size: int = -1) -> bytes:
        return self.payload[:size] if size >= 0 else self.payload


class _Opener:
    def __init__(self, payload: bytes = b'{"ok":true}') -> None:
        self.payload = payload
        self.requests = []
        self.timeouts = []

    def open(self, request, timeout):
        self.requests.append(request)
        self.timeouts.append(timeout)
        return _Response(self.payload)


class HttpGuardTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.transport = HttpGuardTransport(
            provider_api_key="provider-secret",
            upstream_allowlist=("https://integrate.api.nvidia.com",),
        )

    def test_disallowed_urls_are_rejected_before_network(self) -> None:
        for url in (
            "https://evil.example/v1/chat/completions",
            "http://integrate.api.nvidia.com/v1/chat/completions",
            "https://integrate.api.nvidia.com:8443/v1/chat/completions",
            "https://integrate.api.nvidia.com/other",
            "https://integrate.api.nvidia.com/v1/chat/completions?x=1",
        ):
            with self.assertRaises(GuardError) as context:
                self.transport.post(url, body=b"{}", timeout_seconds=5)
            self.assertEqual(context.exception.status_code, 403, url)

    def test_provider_key_is_added_server_side(self) -> None:
        opener = _Opener()
        with patch.object(self.transport, "_opener", opener):
            result = self.transport.post(
                "https://integrate.api.nvidia.com/v1/chat/completions",
                body=b'{"model":"test"}',
                timeout_seconds=7,
            )
        self.assertEqual(result, b'{"ok":true}')
        self.assertEqual(len(opener.requests), 1)
        self.assertEqual(
            opener.requests[0].get_header("Authorization"),
            "Bearer provider-secret",
        )
        self.assertEqual(opener.timeouts, [7])

    def test_oversized_response_is_rejected(self) -> None:
        transport = HttpGuardTransport(
            provider_api_key="provider-secret",
            upstream_allowlist=("https://integrate.api.nvidia.com",),
            max_response_bytes=4,
        )
        with patch.object(transport, "_opener", _Opener(b"12345")):
            with self.assertRaises(GuardError) as context:
                transport.post(
                    "https://integrate.api.nvidia.com/v1/chat/completions",
                    body=b"{}",
                    timeout_seconds=5,
                )
        self.assertEqual(context.exception.status_code, 502)


if __name__ == "__main__":
    unittest.main()
