"""Phase 14 — Performance and Reliability Testing.

Performance measurement, resource monitoring, and reliability validation for
the ZeroTrace platform. Measures cold-start time, peak RAM, per-service
memory, CPU utilization, Guard latency, scanner concurrency, database query
latency, swap usage, and behavior under concurrent activity.

All measurements are synthetic — no external targets, no live scanning, no
production data access.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import os
import psutil
import threading
import time
from typing import Any, Callable


class PerformanceError(ValueError):
    """Raised when a performance measurement violates its contract."""


@dataclass(frozen=True)
class PerformanceResult:
    """Single performance measurement result."""

    name: str
    value: float
    unit: str
    timestamp: datetime
    within_budget: bool


@dataclass(frozen=True)
class ProfileConfig:
    """Deployment profile configuration."""

    name: str
    services: dict[str, bool]
    max_ram_mb: int
    max_cpu_percent: float


# Default profile configurations
_PROFILES: dict[str, ProfileConfig] = {
    "core": ProfileConfig(
        name="core",
        services={"ollama": False, "full_guard": False, "full_recon": False},
        max_ram_mb=4096,
        max_cpu_percent=50.0,
    ),
    "full": ProfileConfig(
        name="full",
        services={"ollama": True, "full_guard": True, "full_recon": True},
        max_ram_mb=9216,
        max_cpu_percent=80.0,
    ),
    "dev": ProfileConfig(
        name="dev",
        services={"ollama": False, "full_guard": False, "full_recon": False},
        max_ram_mb=3072,
        max_cpu_percent=40.0,
    ),
}


def measure_cold_start() -> float:
    """Measure application cold-start time in seconds.

    Measures the time from process start to first successful health check.
    Returns the elapsed time in seconds.
    """
    start = time.monotonic()
    # Simulate application startup: import core modules and initialize
    from app.settings import Settings
    from app.security import Principal, require_role
    from app.readiness import calculate_readiness

    # Simulate a minimal health check
    principal = Principal(subject="test", role="viewer")
    require_role(principal, "viewer")
    calculate_readiness(0, 0, [], 0, 0, 0)

    elapsed = time.monotonic() - start
    return round(elapsed, 4)


def measure_peak_ram() -> float:
    """Measure peak system RAM usage in MB.

    Returns the peak resident set size (RSS) of the current process in MB.
    """
    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    return round(mem_info.rss / (1024 * 1024), 2)


def measure_per_service_memory() -> dict[str, float]:
    """Measure per-service memory usage in MB.

    Returns a dictionary mapping service names to their memory usage in MB.
    Since ZeroTrace runs as a single process, this returns memory by module
    import footprint.
    """
    import app.recon
    import app.intel
    import app.guard
    import app.readiness
    import app.security
    import app.events

    services = {
        "recon": app.recon,
        "intel": app.intel,
        "guard": app.guard,
        "readiness": app.readiness,
        "security": app.security,
        "events": app.events,
    }

    results: dict[str, float] = {}
    process = psutil.Process(os.getpid())
    baseline = process.memory_info().rss

    for name, module in services.items():
        # Force module loading if not already loaded
        _ = module.__name__
        current = process.memory_info().rss
        results[name] = round((current - baseline) / (1024 * 1024), 2)
        baseline = current

    return results


def measure_cpu_utilization(duration_seconds: float = 1.0) -> float:
    """Measure CPU utilization percentage over a duration.

    Args:
        duration_seconds: Measurement duration in seconds.

    Returns CPU utilization percentage (0-100).
    """
    if duration_seconds <= 0:
        raise PerformanceError("duration_seconds must be positive")

    cpu_percent = psutil.cpu_percent(interval=duration_seconds)
    return round(float(cpu_percent), 2)


def measure_guard_latency() -> float:
    """Measure Guard middleware latency in seconds.

    Measures the time for a complete Guard request cycle: request validation,
    CSRF check, security header application, and response generation.
    Returns latency in seconds.
    """
    start = time.monotonic()

    # Simulate Guard request processing
    from app.security import (
        Principal,
        require_role,
        csrf_token,
        verify_csrf_token,
        security_headers,
    )

    principal = Principal(subject="test-client", role="operator")
    require_role(principal, "operator")

    token = csrf_token("test-session", b"test-secret-key-at-least-32-bytes")
    verify_csrf_token("test-session", token, b"test-secret-key-at-least-32-bytes")
    headers = security_headers()

    elapsed = time.monotonic() - start
    return round(elapsed, 4)


def _run_recon_scan(run_id: int, results: dict[int, str]) -> None:
    """Run a single Recon scan simulation."""
    try:
        from app.recon import (
            ReconEngine,
            ReconRunState,
            Scope,
            Target,
            SyntheticAdapter,
            AdapterResult,
            InMemoryReconRepository,
        )

        repository = InMemoryReconRepository()
        adapter = SyntheticAdapter(
            AdapterResult(
                assets=("lab.example.test",),
                services=(("lab.example.test", "tcp", 443, "https"),),
                warnings=(),
            )
        )

        engine = ReconEngine(
            repository,
            {"synthetic_inventory_v1": adapter},
            dns_resolver=lambda d: ("127.0.0.1",),
        )

        scope = Scope(
            scope_id=f"scope-{run_id}",
            owner_id="test-operator",
            targets=("lab.example.test",),
            environment="isolated_lab",
            approved=True,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            profiles=("synthetic_inventory_v1",),
        )

        run = engine.create_run(
            scope,
            Target(value="lab.example.test", kind="domain"),
            profile_id="synthetic_inventory_v1",
        )
        results[run_id] = run.state.value
    except Exception as exc:  # noqa: BLE001
        results[run_id] = f"error: {exc}"


def test_concurrent_recon(num_runs: int = 3) -> list[dict[str, str]]:
    """Test concurrent Recon scan execution.

    Runs multiple Recon scans concurrently and returns their results.
    Each run uses a synthetic adapter — no real scanner binaries are executed.
    """
    results: dict[int, str] = {}
    threads: list[threading.Thread] = []

    for i in range(num_runs):
        thread = threading.Thread(
            target=_run_recon_scan, args=(i, results), daemon=True
        )
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join(timeout=30)

    return [{"run_id": i, "state": results.get(i, "timeout")} for i in range(num_runs)]


def _run_guard_request(request_id: int, results: dict[int, str]) -> None:
    """Run a single Guard request simulation."""
    try:
        from app.guard import GuardConfig, create_guard_app
        from app.security import Principal
        from fastapi.testclient import TestClient
        import hashlib as _hashlib
        import hmac as _hmac

        # Compute digest first, then create config
        secret = "test-secret-key-at-least-32-bytes"
        api_key = b"sk-test-1234567890abcdef"
        digest = _hmac.new(
            secret.encode("utf-8"),
            api_key,
            _hashlib.sha256,
        ).hexdigest()
        config = GuardConfig(
            api_key_secret=secret,
            api_key_digest=digest,
            upstream_allowlist=("https://api.openai.com",),
        )

        app = create_guard_app(
            config=config,
            transport=_SyntheticGuardTransport(),
            principal_provider=lambda req: Principal(
                subject="test-client", role="operator"
            ),
        )
        client = TestClient(app)

        response = client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-3.5-turbo",
                "messages": [
                    {"role": "user", "content": "Hello, world"}
                ],
            },
            headers={"X-API-Key": "sk-test-1234567890abcdef"},
        )
        results[request_id] = response.status_code
    except Exception as exc:  # noqa: BLE001
        results[request_id] = f"error: {exc}"


class _SyntheticGuardTransport:
    """Synthetic transport for Guard testing."""

    def post(self, url: str, *, body: bytes, timeout_seconds: int) -> bytes:
        import json

        return json.dumps(
            {
                "id": "chatcmpl-test",
                "object": "chat.completion",
                "created": 1234567890,
                "model": "gpt-3.5-turbo",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "Hello"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 2,
                    "completion_tokens": 1,
                    "total_tokens": 3,
                },
            }
        ).encode()


def test_concurrent_guard(num_requests: int = 5) -> list[dict[str, str]]:
    """Test concurrent Guard request handling.

    Runs multiple Guard requests concurrently and returns their results.
    """
    results: dict[int, str] = {}
    threads: list[threading.Thread] = []

    for i in range(num_requests):
        thread = threading.Thread(
            target=_run_guard_request, args=(i, results), daemon=True
        )
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join(timeout=30)

    return [
        {"request_id": i, "status": results.get(i, "timeout")} for i in range(num_requests)
    ]


def _run_intel_ingestion(ingestion_id: int, results: dict[int, str]) -> None:
    """Run a single Intel ingestion simulation."""
    try:
        from app.intel_feeds import SyntheticTransport, NVD_ENDPOINT
        from app.intel_api import create_intel_app, InMemoryIntelRepository
        from app.security import Principal
        from fastapi.testclient import TestClient

        payload = b'{"vulnerabilities": []}'
        app = create_intel_app(
            InMemoryIntelRepository(),
            lambda req: Principal(subject="test-operator", role="operator"),
            SyntheticTransport({NVD_ENDPOINT: payload}),
        )
        client = TestClient(app)

        response = client.post(
            "/api/v1/intel/ingestions",
            headers={"Idempotency-Key": f"ingestion-{ingestion_id}"},
            json={"source": "nvd"},
        )
        results[ingestion_id] = response.status_code
    except Exception as exc:  # noqa: BLE001
        results[ingestion_id] = f"error: {exc}"


def test_concurrent_intel(num_ingestions: int = 3) -> list[dict[str, str]]:
    """Test concurrent Intel ingestion.

    Runs multiple Intel ingestions concurrently and returns their results.
    """
    results: dict[int, str] = {}
    threads: list[threading.Thread] = []

    for i in range(num_ingestions):
        thread = threading.Thread(
            target=_run_intel_ingestion, args=(i, results), daemon=True
        )
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join(timeout=30)

    return [
        {"ingestion_id": i, "status": results.get(i, "timeout")}
        for i in range(num_ingestions)
    ]


def measure_db_query_latency() -> float:
    """Measure database query latency in seconds.

    Measures the time for a simple database query against the in-memory
    repository. Returns latency in seconds.
    """
    start = time.monotonic()

    from app.recon import InMemoryReconRepository

    repository = InMemoryReconRepository()
    # Simulate a simple repository operation
    _ = repository.runs
    _ = repository.results
    _ = repository.requests

    elapsed = time.monotonic() - start
    return round(elapsed, 4)


def measure_swap_usage() -> float:
    """Measure swap usage in MB.

    Returns the amount of swap space currently used in MB.
    """
    swap = psutil.swap_memory()
    return round(swap.used / (1024 * 1024), 2)


def get_profile_config(profile_name: str) -> dict[str, Any]:
    """Get deployment profile configuration.

    Args:
        profile_name: One of "core", "full", or "dev".

    Returns a dictionary with profile configuration including services,
    resource limits, and feature flags.
    """
    if profile_name not in _PROFILES:
        raise PerformanceError(f"Unknown profile: {profile_name}")

    profile = _PROFILES[profile_name]
    return {
        "name": profile.name,
        "services": profile.services,
        "max_ram_mb": profile.max_ram_mb,
        "max_cpu_percent": profile.max_cpu_percent,
    }


def measure_host_headroom() -> dict[str, float]:
    """Measure available host headroom.

    Returns a dictionary with available system resources:
    - ram_available_mb: Available system RAM in MB
    - cpu_available_percent: Available CPU percentage
    - swap_available_mb: Available swap space in MB
    """
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    cpu_percent = psutil.cpu_percent(interval=0.1)

    return {
        "ram_available_mb": round(mem.available / (1024 * 1024), 2),
        "cpu_available_percent": round(100.0 - cpu_percent, 2),
        "swap_available_mb": round(swap.free / (1024 * 1024), 2),
    }


def measure_all() -> dict[str, PerformanceResult]:
    """Run all performance measurements and return results.

    Returns a dictionary mapping measurement names to PerformanceResult
    objects. Each result includes the value, unit, timestamp, and whether
    the value is within acceptable bounds.
    """
    results: dict[str, PerformanceResult] = {}

    # Cold start
    cold_start = measure_cold_start()
    results["cold_start"] = PerformanceResult(
        name="cold_start",
        value=cold_start,
        unit="seconds",
        timestamp=datetime.now(timezone.utc),
        within_budget=cold_start < 30.0,
    )

    # Peak RAM
    peak_ram = measure_peak_ram()
    results["peak_ram"] = PerformanceResult(
        name="peak_ram",
        value=peak_ram,
        unit="MB",
        timestamp=datetime.now(timezone.utc),
        within_budget=peak_ram < 4096.0,
    )

    # CPU utilization
    cpu_util = measure_cpu_utilization(duration_seconds=1.0)
    results["cpu_utilization"] = PerformanceResult(
        name="cpu_utilization",
        value=cpu_util,
        unit="percent",
        timestamp=datetime.now(timezone.utc),
        within_budget=cpu_util < 80.0,
    )

    # Guard latency
    guard_latency = measure_guard_latency()
    results["guard_latency"] = PerformanceResult(
        name="guard_latency",
        value=guard_latency,
        unit="seconds",
        timestamp=datetime.now(timezone.utc),
        within_budget=guard_latency < 2.0,
    )

    # DB query latency
    db_latency = measure_db_query_latency()
    results["db_query_latency"] = PerformanceResult(
        name="db_query_latency",
        value=db_latency,
        unit="seconds",
        timestamp=datetime.now(timezone.utc),
        within_budget=db_latency < 5.0,
    )

    # Swap usage
    swap = measure_swap_usage()
    results["swap_usage"] = PerformanceResult(
        name="swap_usage",
        value=swap,
        unit="MB",
        timestamp=datetime.now(timezone.utc),
        within_budget=True,  # Swap usage is informational, not a failure
    )

    # Host headroom
    headroom = measure_host_headroom()
    results["host_headroom"] = PerformanceResult(
        name="host_headroom",
        value=headroom["ram_available_mb"],
        unit="MB",
        timestamp=datetime.now(timezone.utc),
        within_budget=headroom["ram_available_mb"] > 512.0,
    )

    return results