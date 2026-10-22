"""Run one bounded scheduled-feed cycle against the live engine.

The live engine owns the allowlisted transport, retry policy, and persistence.
This operator helper only asks the engine to run a source through the same path
the background scheduler uses, then records the engine's status response.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENGINE = "http://127.0.0.1:8765"
DEFAULT_KEY = "sk-zerotrace-local-engine-7f3c9a2b"


def _request(
    base_url: str,
    api_key: str,
    method: str,
    path: str,
    *,
    timeout_seconds: int,
) -> dict[str, object]:
    request = Request(
        f"{base_url}{path}",
        method=method,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-API-Key": api_key,
        },
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            body = response.read(2 * 1024 * 1024 + 1)
    except HTTPError as error:
        detail = error.read(2000).decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {path} failed ({error.code}): {detail}") from error
    except URLError as error:
        raise RuntimeError(f"live engine is not reachable: {error.reason}") from error
    if len(body) > 2 * 1024 * 1024:
        raise RuntimeError("engine response exceeded the evidence limit")
    parsed = json.loads(body.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise RuntimeError("engine returned a non-object response")
    return parsed


def run(args: argparse.Namespace) -> dict[str, object]:
    base_url = args.engine_url.rstrip("/")
    started = time.monotonic()
    result = _request(
        base_url,
        args.api_key,
        "POST",
        f"/api/v1/intel/schedule/run?source={args.source}",
        timeout_seconds=args.timeout,
    )
    duration = round(time.monotonic() - started, 2)
    status = _request(
        base_url,
        args.api_key,
        "GET",
        "/api/v1/intel/schedule",
        timeout_seconds=20,
    )
    engine_status = _request(
        base_url,
        args.api_key,
        "GET",
        "/api/v1/engine/status",
        timeout_seconds=20,
    )
    evidence = {
        "ok": True,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "engine": base_url,
        "source": args.source,
        "durationSeconds": duration,
        "result": result,
        "schedule": status,
        "intel": engine_status.get("intel"),
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    return {
        "ok": True,
        "source": args.source,
        "durationSeconds": duration,
        "results": result.get("results"),
        "schedule": status.get("feeds", {}).get(args.source),
        "output": str(output),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", choices=("nvd", "epss", "kev"), required=True)
    parser.add_argument(
        "--engine-url", default=os.environ.get("ZEROTRACE_ENGINE_URL", DEFAULT_ENGINE)
    )
    parser.add_argument(
        "--api-key", default=os.environ.get("ZEROTRACE_ENGINE_API_KEY", DEFAULT_KEY)
    )
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "tasks" / "evidence" / "phase-16-intel-schedule.json",
    )
    args = parser.parse_args(argv)
    try:
        result = run(args)
    except Exception as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
