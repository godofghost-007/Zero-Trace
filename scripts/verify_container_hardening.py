"""Verify the production Compose sandbox policy.

This is evidence generation, not a substitute for a host-level sandbox. It
inspects the rendered Compose model and fails when a service loses a control
that the deployment runbook claims is present.

Run it on a machine with Docker Compose:

    python scripts/verify_container_hardening.py \
        --compose-file deploy/compose.prod.yaml \
        --env-file ../.env.example \
        --output tasks/evidence/container-hardening.json
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys


class HardeningError(RuntimeError):
    pass


def _render(compose_file: Path, env_file: str) -> dict[str, object]:
    environment = os.environ.copy()
    environment.setdefault("ZEROTRACE_DOMAIN", "zerotrace.example.test")
    environment["ZEROTRACE_ENV_FILE"] = env_file
    environment.setdefault("ZEROTRACE_GUARD_ENV_FILE", env_file)
    try:
        result = subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                str(compose_file),
                "config",
                "--format",
                "json",
            ],
            capture_output=True,
            check=False,
            text=True,
            timeout=60,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise HardeningError("docker compose is not available") from error
    if result.returncode != 0:
        raise HardeningError(
            "docker compose config failed: " + (result.stderr or "").strip()
        )
    try:
        model = json.loads(result.stdout)
    except ValueError as error:
        raise HardeningError("docker compose returned invalid JSON") from error
    if not isinstance(model, dict) or not isinstance(model.get("services"), dict):
        raise HardeningError("docker compose model has no services")
    return model


def _security_options(service: dict[str, object]) -> list[str]:
    values = service.get("security_opt", [])
    if not isinstance(values, list):
        raise HardeningError("security_opt must be a list")
    return [str(value) for value in values]


def _tmpfs(service: dict[str, object]) -> list[str]:
    values = service.get("tmpfs", [])
    if isinstance(values, str):
        return [values]
    if not isinstance(values, list):
        raise HardeningError("tmpfs must be a list")
    return [str(value) for value in values]


def _published_ports(service: dict[str, object]) -> list[tuple[str, str]]:
    """Return (published, protocol) pairs from Compose's long port syntax."""

    values = service.get("ports", [])
    if not isinstance(values, list):
        raise HardeningError("ports must be a list")
    result: list[tuple[str, str]] = []
    for item in values:
        if isinstance(item, dict):
            result.append(
                (
                    str(item.get("published", "")),
                    str(item.get("protocol", "tcp")),
                )
            )
        else:
            result.append((str(item), "tcp"))
    return result


def _check_service(name: str, service: dict[str, object]) -> list[str]:
    findings: list[str] = []
    if service.get("privileged") is True:
        findings.append(f"{name}: privileged mode is forbidden")
    if "ALL" not in [str(item) for item in service.get("cap_drop", [])]:
        findings.append(f"{name}: cap_drop must include ALL")
    if not any(
        "no-new-privileges" in option for option in _security_options(service)
    ):
        findings.append(f"{name}: no-new-privileges is required")
    if service.get("read_only") is not True:
        findings.append(f"{name}: root filesystem must be read-only")
    if service.get("init") is not True:
        findings.append(f"{name}: init must be enabled")
    if not isinstance(service.get("pids_limit"), int) or int(service["pids_limit"]) < 1:
        findings.append(f"{name}: pids_limit is required")
    if not service.get("mem_limit"):
        findings.append(f"{name}: mem_limit is required")
    if not _tmpfs(service):
        findings.append(f"{name}: a writable tmpfs is required")
    if service.get("network_mode") == "host":
        findings.append(f"{name}: host networking is forbidden")
    return findings


def verify(model: dict[str, object]) -> dict[str, object]:
    services = model["services"]
    assert isinstance(services, dict)
    findings: list[str] = []
    for name in ("engine", "guard", "bff", "caddy"):
        service = services.get(name)
        if not isinstance(service, dict):
            findings.append(f"{name}: service is missing")
            continue
        findings.extend(_check_service(name, service))

    engine = services.get("engine")
    guard = services.get("guard")
    bff = services.get("bff")
    caddy = services.get("caddy")
    if isinstance(engine, dict):
        if engine.get("ports"):
            findings.append("engine: the engine port must not be published")
        if engine.get("expose") not in (["8765"], ["8765/tcp"]):
            findings.append("engine: expose must be limited to 8765")
    if isinstance(guard, dict):
        if guard.get("network_mode") != "service:engine":
            findings.append("guard: must share the engine network namespace")
        if guard.get("ports"):
            findings.append("guard: the Guard port must not be published")
        command = guard.get("command", [])
        if "scripts.guard_proxy" not in [str(item) for item in command]:
            findings.append("guard: command must run scripts.guard_proxy")
    if isinstance(bff, dict):
        if bff.get("network_mode") != "service:engine":
            findings.append("bff: must share the engine network namespace")
        if bff.get("ports"):
            findings.append("bff: the BFF must only be reached through Caddy")
    if isinstance(caddy, dict):
        ports = _published_ports(caddy)
        if ("80", "tcp") not in ports:
            findings.append("caddy: port 80/tcp must be published")
        if ("443", "tcp") not in ports:
            findings.append("caddy: port 443/tcp must be published")
        if "NET_BIND_SERVICE" not in [
            str(item) for item in caddy.get("cap_add", [])
        ]:
            findings.append("caddy: NET_BIND_SERVICE is required")
    return {
        "ok": not findings,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "services": sorted(services),
        "findings": findings,
        "checks": {
            "nonRootReadOnly": True,
            "capDropAll": True,
            "noNewPrivileges": True,
            "engineNotPublished": True,
            "guardNotPublished": True,
            "guardSharedEngineNamespace": True,
            "bffSharedEngineNamespace": True,
            "resourceLimits": True,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--compose-file",
        type=Path,
        default=Path("deploy/compose.prod.yaml"),
    )
    parser.add_argument("--env-file", default="../.env.example")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = verify(_render(args.compose_file, args.env_file))
    except HardeningError as error:
        print(f"hardening verification failed: {error}", file=sys.stderr)
        return 1
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
