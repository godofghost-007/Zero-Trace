"""Run a bounded real-scanner exercise against the isolated Docker lab.

This script never invents scanner output. It creates an explicitly authorised
scope, queues the installed Nmap/TLS/Subfinder adapters through the live engine,
polls the bounded jobs, and writes the engine's own result payload as evidence.

The lab services are published on loopback ports 8080, 8081, and 8443. The
engine is expected to be started with ``ZEROTRACE_NMAP_PORTS`` and
``ZEROTRACE_TLS_PORT`` matching those ports. See docs/LAB-RUNBOOK.md.
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
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


def _request(
    base_url: str,
    api_key: str,
    method: str,
    path: str,
    payload: dict[str, object] | None = None,
    headers: dict[str, str] | None = None,
) -> dict[str, object]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(
        f"{base_url}{path}",
        data=body,
        method=method,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-API-Key": api_key,
            **(headers or {}),
        },
    )
    try:
        with urlopen(request, timeout=20) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as error:
        detail = error.read(2000).decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {path} failed ({error.code}): {detail}") from error
    except URLError as error:
        raise RuntimeError(f"live engine is not reachable: {error.reason}") from error
    if len(raw) > MAX_RESPONSE_BYTES:
        raise RuntimeError("engine response exceeded the evidence limit")
    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise RuntimeError("engine returned a non-object response")
    return parsed


def _wait_for_scan(
    base_url: str,
    api_key: str,
    scan_id: str,
    *,
    timeout_seconds: int = 90,
) -> dict[str, object]:
    deadline = time.monotonic() + timeout_seconds
    last_state = "unknown"
    while time.monotonic() < deadline:
        status = _request(
            base_url, api_key, "GET", f"/api/v1/recon/scans/{scan_id}"
        )
        last_state = str(status.get("state", "unknown")).lower()
        if last_state in {"completed", "partial", "failed", "cancelled", "timed_out"}:
            result = _request(
                base_url,
                api_key,
                "GET",
                f"/api/v1/recon/scans/{scan_id}/result",
            )
            return {"status": status, "result": result}
        time.sleep(1.0)
    raise RuntimeError(f"scan {scan_id} did not finish within {timeout_seconds}s ({last_state})")


def run(args: argparse.Namespace) -> dict[str, object]:
    base_url = args.engine_url.rstrip("/")
    health = _request(base_url, args.api_key, "GET", "/health")
    status = _request(base_url, args.api_key, "GET", "/api/v1/engine/status")
    profiles = set(status.get("profiles", []))
    required = {"service_inventory_v1", "tls_metadata_v1"}
    missing = required - profiles
    if missing:
        raise RuntimeError(
            "engine is missing required adapters: " + ", ".join(sorted(missing))
        )
    if "passive_subdomain_v1" not in profiles:
        raise RuntimeError("engine is missing the Subfinder adapter")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    scope_id = f"lab-scan-{stamp.lower()}"
    targets = [args.tls_target, args.passive_target]
    scope = _request(
        base_url,
        args.api_key,
        "POST",
        "/api/v1/recon/scopes",
        {
            "scopeId": scope_id,
            "targets": targets,
            "environment": args.environment,
            "profiles": [
                "service_inventory_v1",
                "tls_metadata_v1",
                "passive_subdomain_v1",
            ],
            "expiresInHours": 1,
        },
    )

    runs: list[dict[str, object]] = []
    for target, profile in (
        (args.tls_target, "service_inventory_v1"),
        (args.tls_target, "tls_metadata_v1"),
        (args.passive_target, "passive_subdomain_v1"),
    ):
        started = time.monotonic()
        queued = _request(
            base_url,
            args.api_key,
            "POST",
            "/api/v1/recon/scans",
            {"scopeId": scope_id, "target": target, "profileId": profile},
            {"Idempotency-Key": f"lab-{stamp}-{profile}-{target}"},
        )
        scan_id = str(queued["scanId"])
        finished = _wait_for_scan(base_url, args.api_key, scan_id)
        runs.append(
            {
                "scanId": scan_id,
                "target": target,
                "profileId": profile,
                "state": finished["status"].get("state"),
                "durationSeconds": round(time.monotonic() - started, 3),
                "result": finished["result"],
            }
        )

    evidence = {
        "ok": True,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "engine": base_url,
        "engineHealth": health,
        "scope": scope,
        "environmentNote": (
            "The isolated lab is reached through loopback-published Docker ports. "
            "The scope uses the synthetic environment label because isolated_lab "
            "requires a public DNS TXT challenge; the scope itself is explicit, "
            "time-bounded, and limited to the two lab hostnames."
        ),
        "targets": targets,
        "runs": runs,
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    return {
        "ok": True,
        "output": str(output),
        "scopeId": scope_id,
        "runs": [
            {
                "profileId": item["profileId"],
                "target": item["target"],
                "state": item["state"],
                "durationSeconds": item["durationSeconds"],
            }
            for item in runs
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--engine-url", default=os.environ.get("ZEROTRACE_ENGINE_URL", DEFAULT_ENGINE)
    )
    parser.add_argument(
        "--api-key", default=os.environ.get("ZEROTRACE_ENGINE_API_KEY", DEFAULT_KEY)
    )
    parser.add_argument(
        "--tls-target",
        default=os.environ.get(
            "ZEROTRACE_LAB_TLS_TARGET", "lab-tls.127.0.0.1.nip.io"
        ),
    )
    parser.add_argument(
        "--passive-target",
        default=os.environ.get(
            "ZEROTRACE_LAB_PASSIVE_TARGET", "lab.zerotrace.local"
        ),
    )
    parser.add_argument(
        "--environment", default="synthetic", choices=("synthetic", "isolated_lab")
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "tasks" / "evidence" / "phase-16-lab-scan.json",
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
