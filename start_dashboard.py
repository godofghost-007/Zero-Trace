from app.dashboard.server import create_dashboard_app
import http.server
import threading
import time
import hashlib
import hmac

# Configure with test credentials (same as tests)
secret = "test-secret-key-at-least-32-bytes"
api_key = "sk-test-1234567890abcdef"
digest = hmac.new(secret.encode("utf-8"), api_key.encode("utf-8"), hashlib.sha256).hexdigest()

from app.guard import GuardConfig
config = GuardConfig(
    api_key_secret=secret,
    api_key_digest=digest,
    upstream_allowlist=("https://api.openai.com",),
)

# Simple synthetic transport for the dashboard
class _SyntheticTransport:
    def post(self, url: str, *, body: bytes, timeout_seconds: int) -> bytes:
        import json
        return json.dumps({
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "created": 1234567890,
            "model": "gpt-3.5-turbo",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hello"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3},
        }).encode()

HandlerClass = create_dashboard_app(
    config=config,
    transport=_SyntheticTransport(),
    principal_provider=lambda req: __import__('app.security', fromlist=['Principal']).Principal(subject="test-client", role="viewer"),
)
server = http.server.HTTPServer(('127.0.0.1', 8766), HandlerClass)
print('SERVER_STARTED_ON_8766', flush=True)
t = threading.Thread(target=server.serve_forever, daemon=True)
t.start()
while True:
    time.sleep(60)