"""Small, dependency-free load test for a loopback ZeroTrace BFF.

By default the script starts an isolated Flask app with a temporary SQLite
database, so it never touches the local demo data. Pass ``--base-url`` to test
an already-running instance instead.

This is a smoke-level load test, not a capacity benchmark. It is designed to
catch accidental serialization, connection leaks, and gross latency regressions.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import statistics
import sys
import tempfile
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FRONTEND = PROJECT_ROOT / "frontend"
if str(FRONTEND) not in sys.path:
    sys.path.insert(0, str(FRONTEND))


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))
    return ordered[index]


def _start_embedded_app():
    from werkzeug.serving import make_server

    from backend import create_app

    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    temp = tempfile.TemporaryDirectory(
        prefix="zerotrace-load-", ignore_cleanup_errors=True
    )
    app = create_app(
        {
            "TESTING": False,
            "ENVIRONMENT": "development",
            "SECRET_KEY": "load-test-secret-key-at-least-32-bytes",
            "AUTH_REQUIRED": False,
            "DEMO_MODE": True,
            "AUTO_CREATE_SCHEMA": True,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{Path(temp.name) / 'load.db'}",
            "DATA_DIR": Path(temp.name),
            "AUDIT_DB_PATH": Path(temp.name) / "audit.sqlite",
            "FRONTEND_DIST": Path(temp.name) / "dist",
            "METRICS_ENABLED": True,
            "METRICS_TOKEN": "load-test-metrics-token",
            "LOG_LEVEL": "WARNING",
        }
    )
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, temp, app


def _request(url: str, timeout: float) -> tuple[int, float, str]:
    started = time.perf_counter()
    try:
        request = Request(url, headers={"Accept": "application/json"})
        with urlopen(request, timeout=timeout) as response:
            response.read(64 * 1024)
            return response.status, time.perf_counter() - started, ""
    except HTTPError as error:
        error.read(64 * 1024)
        return error.code, time.perf_counter() - started, ""
    except (URLError, TimeoutError, OSError) as error:
        return 0, time.perf_counter() - started, str(error)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url")
    parser.add_argument("--path", default="/api/v1/health")
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--max-error-rate", type=float, default=0.01)
    parser.add_argument("--max-p95-ms", type=float, default=1000.0)
    parser.add_argument("--fail", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.requests < 1 or args.concurrency < 1:
        print("requests and concurrency must be positive", file=sys.stderr)
        return 2

    server = thread = temp = app = None
    if args.base_url:
        base_url = args.base_url.rstrip("/")
    else:
        server, thread, temp, app = _start_embedded_app()
        base_url = f"http://127.0.0.1:{server.server_port}"
    url = base_url + args.path
    try:
        for _ in range(min(10, args.requests)):
            _request(url, args.timeout)
        started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            results = list(
                pool.map(
                    lambda _index: _request(url, args.timeout),
                    range(args.requests),
                )
            )
        elapsed = time.perf_counter() - started
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=5)
        if app is not None:
            from backend.extensions import db

            with app.app_context():
                db.session.remove()
                db.engine.dispose()
        if temp is not None:
            temp.cleanup()

    latencies = [duration for _status, duration, _error in results]
    statuses: dict[str, int] = {}
    errors = 0
    for status, _duration, error in results:
        key = str(status) if status else "network_error"
        statuses[key] = statuses.get(key, 0) + 1
        if status == 0 or status >= 500:
            errors += 1
    error_rate = errors / len(results) if results else 1.0
    p95_ms = _percentile(latencies, 0.95) * 1000
    report = {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "target": url,
        "embedded": server is not None,
        "requests": args.requests,
        "concurrency": args.concurrency,
        "elapsedSeconds": round(elapsed, 3),
        "throughputRequestsPerSecond": round(len(results) / elapsed, 2)
        if elapsed
        else 0.0,
        "statuses": statuses,
        "errorRate": round(error_rate, 4),
        "latencyMs": {
            "mean": round(statistics.fmean(latencies) * 1000, 2),
            "p50": round(_percentile(latencies, 0.50) * 1000, 2),
            "p95": round(p95_ms, 2),
            "p99": round(_percentile(latencies, 0.99) * 1000, 2),
            "max": round(max(latencies) * 1000, 2),
        },
        "thresholds": {
            "maxErrorRate": args.max_error_rate,
            "maxP95Ms": args.max_p95_ms,
        },
        "passed": error_rate <= args.max_error_rate and p95_ms <= args.max_p95_ms,
        "limitations": [
            "Embedded single-process Flask server, not the production Gunicorn topology.",
            "Temporary SQLite database, not PostgreSQL.",
            "Loopback only; no TLS, proxy, or network latency.",
            "Smoke-level evidence, not a capacity or saturation benchmark.",
        ],
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    if args.fail and not report["passed"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
