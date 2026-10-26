"""Run ZeroTrace Guard as a loopback-only OpenAI-compatible proxy.

The BFF (or a local application) calls Guard with the BFF credential. Guard
authenticates that credential, scans the prompt and response, and forwards the
request to the allowlisted model provider with the provider key that only Guard
holds.

Required environment:

* ``ZEROTRACE_GUARD_API_KEY_SECRET`` - HMAC secret shared with the BFF.
* ``ZEROTRACE_GUARD_API_KEY_DIGEST`` - digest of the BFF's Guard API key.
* ``ZEROTRACE_GUARD_PROVIDER_API_KEY`` - model provider key, server-side only.

Optional:

* ``ZEROTRACE_GUARD_PREVIOUS_API_KEY_DIGEST`` - accept the old key during rotation.
* ``ZEROTRACE_GUARD_UPSTREAM_ALLOWLIST`` - comma-separated HTTPS origins.
* ``ZEROTRACE_GUARD_ALLOWED_MODELS`` - comma-separated model IDs; empty allows
  any model on the allowlisted provider.
* ``ZEROTRACE_GUARD_PII_ACTION`` - ``block`` (default) or ``redact``.
* ``ZEROTRACE_GUARD_DETECTOR_URL`` - optional external classifier endpoint.
* ``ZEROTRACE_GUARD_DETECTOR_API_KEY`` - optional external classifier key.
* ``ZEROTRACE_GUARD_DETECTOR_TIMEOUT_SECONDS`` - external classifier timeout.
* ``ZEROTRACE_GUARD_HOST`` / ``ZEROTRACE_GUARD_PORT`` - must be loopback.
* ``ZEROTRACE_GUARD_AUDIT_LOG`` - optional JSON-lines audit file.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import threading

import uvicorn

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app.guard import GuardConfig, create_guard_app  # noqa: E402
from app.guard_detector import (  # noqa: E402
    ExternalDetectorConfig,
    HttpExternalDetector,
)
from app.guard_transport import HttpGuardTransport  # noqa: E402
from app.security import Principal  # noqa: E402
from app.settings import env_or_file  # noqa: E402

LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def _csv(name: str, default: str = "") -> tuple[str, ...]:
    raw = os.environ.get(name, default)
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def _audit_publisher(path: str | None):
    if not path:
        return None
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    lock = threading.Lock()

    def publish(event: dict[str, object]) -> None:
        line = json.dumps(event, separators=(",", ":"), ensure_ascii=False)
        with lock:
            with target.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")

    return publish


def main() -> int:
    secret = env_or_file("ZEROTRACE_GUARD_API_KEY_SECRET")
    digest = env_or_file("ZEROTRACE_GUARD_API_KEY_DIGEST")
    provider_key = env_or_file("ZEROTRACE_GUARD_PROVIDER_API_KEY")
    if not secret or not digest:
        print(
            "ZEROTRACE_GUARD_API_KEY_SECRET and "
            "ZEROTRACE_GUARD_API_KEY_DIGEST are required",
            file=sys.stderr,
        )
        return 2
    if not provider_key:
        print("ZEROTRACE_GUARD_PROVIDER_API_KEY is required", file=sys.stderr)
        return 2
    host = os.environ.get("ZEROTRACE_GUARD_HOST", "127.0.0.1").strip()
    if host not in LOOPBACK_HOSTS:
        print("Guard must bind to a loopback address", file=sys.stderr)
        return 2
    try:
        port = int(os.environ.get("ZEROTRACE_GUARD_PORT", "8766"))
    except ValueError:
        print("ZEROTRACE_GUARD_PORT must be an integer", file=sys.stderr)
        return 2
    if not 1 <= port <= 65535:
        print("ZEROTRACE_GUARD_PORT is outside the allowed range", file=sys.stderr)
        return 2

    allowlist = _csv(
        "ZEROTRACE_GUARD_UPSTREAM_ALLOWLIST",
        "https://integrate.api.nvidia.com",
    )
    config = GuardConfig(
        api_key_secret=secret,
        api_key_digest=digest,
        previous_api_key_digest=(
            os.environ.get("ZEROTRACE_GUARD_PREVIOUS_API_KEY_DIGEST", "").strip()
            or None
        ),
        upstream_allowlist=allowlist,
        allowed_models=_csv("ZEROTRACE_GUARD_ALLOWED_MODELS"),
        pii_action=os.environ.get("ZEROTRACE_GUARD_PII_ACTION", "block").strip(),
        require_api_key=(
            os.environ.get("ZEROTRACE_GUARD_REQUIRE_API_KEY", "true").lower()
            not in {"0", "false", "no"}
        ),
    )
    transport = HttpGuardTransport(
        provider_api_key=provider_key,
        upstream_allowlist=allowlist,
    )
    detector = None
    detector_url = env_or_file("ZEROTRACE_GUARD_DETECTOR_URL")
    if detector_url:
        try:
            detector_timeout = int(
                os.environ.get("ZEROTRACE_GUARD_DETECTOR_TIMEOUT_SECONDS", "5")
            )
        except ValueError:
            print(
                "ZEROTRACE_GUARD_DETECTOR_TIMEOUT_SECONDS must be an integer",
                file=sys.stderr,
            )
            return 2
        detector = HttpExternalDetector(
            ExternalDetectorConfig(
                url=detector_url,
                api_key=env_or_file("ZEROTRACE_GUARD_DETECTOR_API_KEY"),
                timeout_seconds=detector_timeout,
            )
        )
    app = create_guard_app(
        config=config,
        transport=transport,
        principal_provider=lambda request: Principal("bff", "service"),
        event_publisher=_audit_publisher(
            os.environ.get("ZEROTRACE_GUARD_AUDIT_LOG")
        ),
        detector=detector,
    )
    uvicorn.run(app, host=host, port=port, log_level="info", access_log=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
