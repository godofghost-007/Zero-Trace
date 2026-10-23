from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import threading
import time
from collections import defaultdict, deque
from typing import Callable, Mapping, Protocol
from urllib.parse import urlsplit
import xml.etree.ElementTree as ElementTree
from uuid import uuid4

from .events import EventEnvelope


class ReconError(ValueError):
    """Raised when a recon request or result violates a safety boundary."""


class ReconTimeoutError(ReconError):
    """Raised when a bounded scanner or connection exceeds its deadline."""


class ReconCancelledError(ReconError):
    """Raised when a scan is cancelled before completion."""


class ReconRunState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


@dataclass(frozen=True)
class Target:
    value: str
    kind: str

    def __post_init__(self) -> None:
        if self.kind != "domain":
            raise ReconError("unsupported target kind")
        normalized = _normalize_domain(self.value)
        object.__setattr__(self, "value", normalized)


@dataclass(frozen=True)
class Scope:
    scope_id: str
    owner_id: str
    targets: tuple[str, ...]
    environment: str
    approved: bool
    expires_at: datetime
    profiles: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.environment not in {"synthetic", "isolated_lab"}:
            raise ReconError("scope environment is not allowed")
        if not self.targets or not self.profiles:
            raise ReconError("scope targets and profiles are required")
        object.__setattr__(
            self,
            "targets",
            tuple(_normalize_domain(value) for value in self.targets),
        )
        if self.expires_at.tzinfo is None:
            raise ReconError("scope expiry must include timezone information")

    def require_target(self, target: Target, profile_id: str, now: datetime) -> None:
        if not self.approved:
            raise ReconError("scope is not approved")
        if _utc(now) >= self.expires_at:
            raise ReconError("scope has expired")
        if profile_id not in self.profiles:
            raise ReconError("profile is not approved for this scope")
        if target.value not in self.targets:
            raise ReconError("target is outside the approved scope")


@dataclass(frozen=True)
class ReconProfile:
    profile_id: str
    adapter_name: str
    timeout_seconds: int
    max_targets: int
    max_output_bytes: int
    max_results: int
    rate_limit_per_minute: int
    level: str = "normal"

    def __post_init__(self) -> None:
        if self.level not in {"normal", "medium", "high", "deep"}:
            raise ReconError("profile level is invalid")
        if min(
            self.timeout_seconds,
            self.max_targets,
            self.max_output_bytes,
            self.max_results,
            self.rate_limit_per_minute,
        ) < 1:
            raise ReconError("profile limits must be positive")


class ReconRateLimiter:
    def __init__(self) -> None:
        self._calls: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def acquire(
        self,
        scope_id: str,
        *,
        rate_per_minute: int,
        now: float | None = None,
    ) -> None:
        if rate_per_minute < 1:
            raise ReconError("rate limit must be positive")
        current = time.monotonic() if now is None else now
        with self._lock:
            calls = self._calls[scope_id]
            while calls and current - calls[0] >= 60.0:
                calls.popleft()
            if len(calls) >= rate_per_minute:
                raise ReconError("recon rate limit exceeded")
            calls.append(current)


PROFILES: Mapping[str, ReconProfile] = {
    "synthetic_inventory_v1": ReconProfile(
        "synthetic_inventory_v1", "synthetic", 30, 10, 64 * 1024, 100, 60
    ),
    "passive_subdomain_v1": ReconProfile(
        "passive_subdomain_v1", "subfinder", 120, 10, 2 * 1024 * 1024, 10_000, 60
    ),
    "passive_subdomain_normal_v1": ReconProfile(
        "passive_subdomain_normal_v1",
        "subfinder",
        120,
        10,
        2 * 1024 * 1024,
        10_000,
        60,
        level="normal",
    ),
    "passive_subdomain_medium_v1": ReconProfile(
        "passive_subdomain_medium_v1",
        "subfinder",
        300,
        10,
        4 * 1024 * 1024,
        25_000,
        30,
        level="medium",
    ),
    "passive_subdomain_high_v1": ReconProfile(
        "passive_subdomain_high_v1",
        "subfinder",
        600,
        10,
        8 * 1024 * 1024,
        50_000,
        10,
        level="high",
    ),
    "passive_subdomain_deep_v1": ReconProfile(
        "passive_subdomain_deep_v1",
        "subfinder",
        900,
        10,
        16 * 1024 * 1024,
        100_000,
        5,
        level="deep",
    ),
    "service_inventory_v1": ReconProfile(
        "service_inventory_v1", "nmap", 120, 100, 4 * 1024 * 1024, 10_000, 60
    ),
    "service_inventory_normal_v1": ReconProfile(
        "service_inventory_normal_v1",
        "nmap",
        120,
        100,
        4 * 1024 * 1024,
        10_000,
        60,
        level="normal",
    ),
    "service_inventory_medium_v1": ReconProfile(
        "service_inventory_medium_v1",
        "nmap",
        300,
        100,
        8 * 1024 * 1024,
        20_000,
        30,
        level="medium",
    ),
    "service_inventory_high_v1": ReconProfile(
        "service_inventory_high_v1",
        "nmap",
        900,
        100,
        16 * 1024 * 1024,
        50_000,
        10,
        level="high",
    ),
    "service_inventory_deep_v1": ReconProfile(
        "service_inventory_deep_v1",
        "nmap",
        1800,
        100,
        32 * 1024 * 1024,
        100_000,
        5,
        level="deep",
    ),
    "tls_metadata_v1": ReconProfile(
        "tls_metadata_v1", "tls", 15, 100, 64 * 1024, 1_000, 60
    ),
    "s3_read_only_v1": ReconProfile(
        "s3_read_only_v1", "s3_read_only", 30, 100, 64 * 1024, 1_000, 30
    ),
}

AUTHORIZATION_REQUIRED_LEVELS = frozenset({"high", "deep"})


def profile_requires_authorization(profile_id: str) -> bool:
    """Return whether a profile needs DNS TXT ownership verification."""

    profile = PROFILES.get(profile_id)
    return profile is not None and profile.level in AUTHORIZATION_REQUIRED_LEVELS


@dataclass(frozen=True)
class NormalizedService:
    asset: str
    protocol: str
    port: int
    product: str | None = None
    version: str | None = None
    tls_status: str | None = None

    def __post_init__(self) -> None:
        if not 1 <= self.port <= 65_535:
            raise ReconError("service port is invalid")
        if self.protocol not in {"tcp", "udp"}:
            raise ReconError("service protocol is invalid")


@dataclass(frozen=True)
class AdapterResult:
    assets: tuple[str, ...]
    services: tuple[
        tuple[str, str, int, str] | tuple[str, str, int, str, str | None],
        ...,
    ]
    warnings: tuple[str, ...]
    state: ReconRunState = ReconRunState.COMPLETED
    tls_findings: tuple[Mapping[str, str], ...] = ()


@dataclass(frozen=True)
class ReconResult:
    assets: tuple[str, ...]
    services: tuple[NormalizedService, ...]
    tls_findings: tuple[Mapping[str, str], ...] = ()
    inventory_delta: "InventoryDelta | None" = None


@dataclass(frozen=True)
class InventoryDelta:
    added_assets: tuple[str, ...] = ()
    removed_assets: tuple[str, ...] = ()
    added_services: tuple[tuple[str, str, int], ...] = ()
    removed_services: tuple[tuple[str, str, int], ...] = ()


@dataclass(frozen=True)
class ReconRun:
    run_id: str
    scope_id: str
    profile_id: str
    target: Target
    state: ReconRunState
    warnings: tuple[str, ...] = ()


class ReconAdapter(Protocol):
    def run(self, target: Target, profile: ReconProfile) -> AdapterResult:
        ...


class SyntheticAdapter:
    def __init__(self, result: AdapterResult) -> None:
        self.result = result
        self.calls = 0

    def run(self, target: Target, profile: ReconProfile) -> AdapterResult:
        self.calls += 1
        if len(self.result.assets) > profile.max_results:
            raise ReconError("adapter result limit exceeded")
        return self.result


class ReconRepository(Protocol):
    def create_run(
        self,
        run: ReconRun,
        request_hash: str,
        idempotency_key: str | None,
    ) -> ReconRun:
        ...

    def commit_results(self, run_id: str, result: ReconResult) -> None:
        ...


class InMemoryReconRepository:
    def __init__(self) -> None:
        self.runs: dict[str, ReconRun] = {}
        self.results: dict[str, ReconResult] = {}
        self.requests: dict[str, tuple[str, str]] = {}
        self.events: list[dict[str, object]] = []
        self.results_committed = False
        self.on_event: Callable[[dict[str, object]], None] | None = None
        self.latest_results: dict[tuple[str, str, str], ReconResult] = {}

    def create_run(
        self,
        run: ReconRun,
        request_hash: str,
        idempotency_key: str | None,
    ) -> ReconRun:
        if idempotency_key is not None:
            existing = self.requests.get(idempotency_key)
            if existing is not None:
                if existing[0] != request_hash:
                    raise ReconError("idempotency key was reused with a different request")
                return self.runs[existing[1]]
        self.runs[run.run_id] = run
        if idempotency_key is not None:
            self.requests[idempotency_key] = (request_hash, run.run_id)
        return run

    def commit_results(self, run_id: str, result: ReconResult) -> None:
        if run_id not in self.runs:
            raise ReconError("run does not exist")
        self.results[run_id] = result
        run = self.runs[run_id]
        self.latest_results[(run.scope_id, run.target.value, run.profile_id)] = result
        self.results_committed = True

    def update_run(self, run: ReconRun) -> None:
        self.runs[run.run_id] = run

    def publish_event(self, event: dict[str, object]) -> None:
        self.events.append(event)
        if self.on_event is not None:
            self.on_event(event)


class ReconEngine:
    def __init__(
        self,
        repository: InMemoryReconRepository,
        adapters: Mapping[str, ReconAdapter],
        *,
        event_publisher: Callable[[dict[str, object]], None] | None = None,
        rate_limiter: ReconRateLimiter | None = None,
        dns_resolver: Callable[[str], tuple[str, ...]] | None = None,
        max_concurrent_runs: int = 1,
        max_retries: int = 0,
        retry_delay_seconds: float = 0.1,
    ) -> None:
        self.repository = repository
        self.adapters = adapters
        self.event_publisher = event_publisher
        self._lock = threading.Lock()
        if max_concurrent_runs < 1:
            raise ReconError("concurrency limit must be positive")
        if max_retries < 0:
            raise ReconError("max_retries must be non-negative")
        if retry_delay_seconds < 0:
            raise ReconError("retry_delay_seconds must be non-negative")
        self.rate_limiter = rate_limiter or ReconRateLimiter()
        self.dns_resolver = dns_resolver
        self._concurrency = threading.BoundedSemaphore(max_concurrent_runs)
        self.max_retries = max_retries
        self.retry_delay_seconds = retry_delay_seconds

    def create_run(
        self,
        scope: Scope,
        target: Target,
        *,
        profile_id: str = "synthetic_inventory_v1",
        idempotency_key: str | None = None,
    ) -> ReconRun:
        profile = PROFILES.get(profile_id)
        if profile is None:
            raise ReconError("profile is not allowlisted")
        if len(scope.targets) > profile.max_targets:
            raise ReconError("scope exceeds the profile target limit")
        now = datetime.now(timezone.utc)
        scope.require_target(target, profile_id, now)
        adapter = self.adapters.get(profile_id) or self.adapters.get(profile.adapter_name)
        if adapter is None:
            raise ReconError("required recon adapter is unavailable")
        if profile.adapter_name in {"nmap", "tls", "s3_read_only"}:
            if self.dns_resolver is None:
                raise ReconError("DNS gate is unavailable for active profile")
            try:
                addresses = self.dns_resolver(target.value)
            except OSError as error:
                raise ReconError("target DNS resolution failed") from error
            if not addresses:
                raise ReconError("target DNS resolution returned no addresses")

        # Rate limiting is enforced BEFORE any run is created, so a rejected
        # request never leaves orphaned RUNNING state in the repository.
        self.rate_limiter.acquire(
            scope.scope_id,
            rate_per_minute=profile.rate_limit_per_minute,
        )

        request_hash = _request_hash(scope.scope_id, profile_id, target)
        with self._lock:
            run = ReconRun(str(uuid4()), scope.scope_id, profile_id, target, ReconRunState.RUNNING)
            existing = self.repository.create_run(run, request_hash, idempotency_key)
            if existing.run_id != run.run_id:
                return existing

        acquired = self._concurrency.acquire(blocking=False)
        if not acquired:
            failed = replace(
                run,
                state=ReconRunState.FAILED,
                warnings=("recon concurrency limit exceeded",),
            )
            self.repository.update_run(failed)
            return failed

        last_error: Exception | None = None
        try:
            for attempt in range(self.max_retries + 1):
                try:
                    adapter_result = adapter.run(target, profile)
                    normalized = _normalize_result(adapter_result, profile)
                    previous = self.repository.latest_results.get(
                        (scope.scope_id, target.value, profile_id)
                    )
                    normalized = replace(
                        normalized,
                        inventory_delta=_inventory_delta(previous, normalized),
                    )
                    completed = replace(
                        run,
                        state=adapter_result.state,
                        warnings=adapter_result.warnings,
                    )
                    self.repository.commit_results(run.run_id, normalized)
                    self.repository.update_run(completed)
                    if self.event_publisher is not None:
                        self.event_publisher(_scan_event(completed))
                    return completed
                except ReconTimeoutError:
                    timed_out = replace(
                        run,
                        state=ReconRunState.TIMED_OUT,
                        warnings=("recon execution timed out",),
                    )
                    self.repository.update_run(timed_out)
                    return timed_out
                except ReconCancelledError:
                    cancelled = replace(
                        run,
                        state=ReconRunState.CANCELLED,
                        warnings=("recon execution cancelled",),
                    )
                    self.repository.update_run(cancelled)
                    return cancelled
                except Exception as error:
                    last_error = error
                    if attempt < self.max_retries and self.retry_delay_seconds > 0:
                        time.sleep(self.retry_delay_seconds)
                    continue
        finally:
            self._concurrency.release()

        # All retries exhausted for transient failures
        failed = replace(
            run,
            state=ReconRunState.FAILED,
            warnings=(
                f"recon failure: {type(last_error).__name__}"
                if last_error is not None
                else "recon failure",
            ),
        )
        self.repository.update_run(failed)
        return failed


class CommandRunner(Protocol):
    def run(self, args: tuple[str, ...], timeout_seconds: int, max_output_bytes: int) -> bytes:
        ...


class SubprocessRunner:
    def run(self, args: tuple[str, ...], timeout_seconds: int, max_output_bytes: int) -> bytes:
        if not args or any("\x00" in argument for argument in args):
            raise ReconError("invalid subprocess arguments")
        executable = Path(args[0]).resolve()
        if not executable.is_file():
            raise ReconError("scanner executable is unavailable")
        process = subprocess.Popen(
            args,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            text=False,
            start_new_session=os.name != "nt",
            creationflags=(
                subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
            ),
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as error:
            if os.name == "nt":
                process.kill()
            else:
                os.killpg(process.pid, 9)
            process.communicate()
            raise ReconTimeoutError("scanner timed out") from error
        if len(stdout) > max_output_bytes:
            raise ReconError("scanner output exceeds the configured limit")
        if process.returncode != 0:
            raise ReconError("scanner exited unsuccessfully")
        return stdout


SUBFINDER_LEVEL_ARGUMENTS: Mapping[str, tuple[str, ...]] = {
    "normal": (),
    "medium": ("-all",),
    "high": ("-all", "-recursive"),
    "deep": ("-all", "-recursive", "-timeout", "60", "-max-time", "12"),
}


class SubfinderAdapter:
    def __init__(self, executable: str, runner: CommandRunner) -> None:
        self.executable = executable
        self.runner = runner

    def run(self, target: Target, profile: ReconProfile) -> AdapterResult:
        level_arguments = SUBFINDER_LEVEL_ARGUMENTS[profile.level]
        output = self.runner.run(
            (
                self.executable,
                "-d",
                target.value,
                *level_arguments,
                "-silent",
                "-json",
            ),
            profile.timeout_seconds,
            profile.max_output_bytes,
        )
        assets: list[str] = []
        warnings: list[str] = []
        for line in output.decode("utf-8", errors="replace").splitlines():
            try:
                record = json.loads(line)
                host = _normalize_domain(record["host"])
                if host not in assets:
                    assets.append(host)
            except (KeyError, TypeError, ValueError, ReconError):
                warnings.append("malformed passive-discovery record")
        state = ReconRunState.PARTIAL if warnings else ReconRunState.COMPLETED
        return AdapterResult(tuple(assets), (), tuple(warnings), state)


NMAP_LEVEL_ARGUMENTS: Mapping[str, tuple[str, ...]] = {
    "normal": ("--top-ports", "100"),
    "medium": ("-sV", "--top-ports", "1000"),
    "high": ("-sV", "-p-", "--version-light"),
    "deep": ("-sV", "-p-", "--version-all"),
}


class NmapAdapter:
    def __init__(
        self,
        executable: str,
        runner: CommandRunner,
        *,
        ports: str | None = None,
    ) -> None:
        self.executable = executable
        self.runner = runner
        self.ports = _validate_ports(ports)

    def run(self, target: Target, profile: ReconProfile) -> AdapterResult:
        if self.ports is not None and profile.level in {"normal", "medium"}:
            port_arguments = (
                ("-sV", "-p", self.ports)
                if profile.level == "medium"
                else ("-p", self.ports)
            )
        else:
            port_arguments = NMAP_LEVEL_ARGUMENTS[profile.level]
        output = self.runner.run(
            (
                self.executable,
                "-sT",
                *port_arguments,
                "-oX",
                "-",
                target.value,
            ),
            profile.timeout_seconds,
            profile.max_output_bytes,
        )
        try:
            root = ElementTree.fromstring(output)
        except ElementTree.ParseError as error:
            raise ReconError("scanner XML is malformed") from error
        services: list[
            tuple[str, str, int, str] | tuple[str, str, int, str, str | None]
        ] = []
        for port in root.findall(".//port"):
            state = port.find("state")
            service = port.find("service")
            if state is None or state.attrib.get("state") != "open":
                continue
            try:
                number = int(port.attrib["portid"])
            except (KeyError, ValueError) as error:
                raise ReconError("scanner port is malformed") from error
            name = "unknown" if service is None else service.attrib.get("name", "unknown")
            if profile.level == "normal":
                services.append(
                    (target.value, port.attrib.get("protocol", "tcp"), number, name)
                )
                continue
            product = "unknown" if service is None else service.attrib.get("product", name)
            version = None if service is None else service.attrib.get("version")
            services.append(
                (
                    target.value,
                    port.attrib.get("protocol", "tcp"),
                    number,
                    product,
                    version,
                )
            )
        warnings = ("no ports observed / may be filtered",) if not services else ()
        return AdapterResult((target.value,), tuple(services), warnings)


class ReadOnlyS3Adapter:
    def __init__(self, checker: Callable[[str], str]) -> None:
        self.checker = checker

    def run(self, target: Target, profile: ReconProfile) -> AdapterResult:
        status = self.checker(target.value)
        if status not in {"public_readable", "public_listable", "denied", "unknown", "transient_error"}:
            raise ReconError("invalid S3 check result")
        return AdapterResult((target.value,), (), (f"s3:{status}",))


class TLSAdapter:
    def __init__(
        self,
        connector: Callable[[str, int, int], Mapping[str, str]] | None = None,
        *,
        port: int = 443,
        verify: bool = True,
    ) -> None:
        if not 1 <= port <= 65_535:
            raise ReconError("TLS port is invalid")
        self.connector = connector or (
            lambda host, port, timeout: _connect_tls(
                host, port, timeout, verify=verify
            )
        )
        self.port = port
        self.verify = verify

    def run(self, target: Target, profile: ReconProfile) -> AdapterResult:
        try:
            finding = dict(self.connector(target.value, self.port, profile.timeout_seconds))
        except TimeoutError:
            return AdapterResult(
                (target.value,),
                (),
                ("tls:timeout",),
                ReconRunState.PARTIAL,
            )
        except OSError:
            return AdapterResult(
                (target.value,),
                (),
                ("tls:unreachable",),
                ReconRunState.PARTIAL,
            )
        required = {"subject", "issuer", "expires_at", "status"}
        if set(finding) != required or finding["status"] not in {
            "valid",
            "unverified",
            "expired",
            "expires_soon",
            "unknown",
        }:
            raise ReconError("TLS metadata is malformed")
        return AdapterResult((target.value,), (), (), tls_findings=(finding,))


def _normalize_result(result: AdapterResult, profile: ReconProfile) -> ReconResult:
    if len(result.assets) > profile.max_results or len(result.services) > profile.max_results:
        raise ReconError("result count exceeds the configured limit")
    assets = tuple(dict.fromkeys(_normalize_domain(asset) for asset in result.assets))
    services: list[NormalizedService] = []
    for item in result.services:
        if len(item) == 4:
            asset, protocol, port, product = item
            version = None
        elif len(item) == 5:
            asset, protocol, port, product, version = item
        else:
            raise ReconError("adapter service shape is invalid")
        services.append(NormalizedService(asset, protocol, port, product, version))
    return ReconResult(assets, tuple(services), result.tls_findings)


def _inventory_delta(
    previous: ReconResult | None, current: ReconResult
) -> InventoryDelta:
    if previous is None:
        return InventoryDelta(
            added_assets=current.assets,
            added_services=tuple(
                (service.asset, service.protocol, service.port)
                for service in current.services
            ),
        )
    previous_assets = set(previous.assets)
    current_assets = set(current.assets)
    previous_services = {
        (service.asset, service.protocol, service.port) for service in previous.services
    }
    current_services = {
        (service.asset, service.protocol, service.port) for service in current.services
    }
    return InventoryDelta(
        added_assets=tuple(sorted(current_assets - previous_assets)),
        removed_assets=tuple(sorted(previous_assets - current_assets)),
        added_services=tuple(sorted(current_services - previous_services)),
        removed_services=tuple(sorted(previous_services - current_services)),
    )


def _scan_event(run: ReconRun) -> dict[str, object]:
    return EventEnvelope(
        event_id=str(uuid4()),
        event_type="scan_status_changed",
        schema_version=1,
        entity_type="scan_run",
        entity_id=run.run_id,
        correlation_id=run.run_id,
        producer="recon-worker",
        scope_id=run.scope_id,
        payload={"state": run.state.value, "warningCount": len(run.warnings)},
    ).to_dict()


def _request_hash(
    scope_id: str,
    profile_id: str,
    target: Target,
) -> str:
    value = json.dumps(
        [scope_id, profile_id, target.value],
        separators=(",", ":"),
    )
    return hashlib.sha256(value.encode()).hexdigest()


def _validate_ports(value: str | None) -> str | None:
    if value is None:
        return None
    candidate = value.strip()
    if not candidate or len(candidate) > 128:
        raise ReconError("nmap port list is invalid")
    if any(character not in "0123456789,-" for character in candidate):
        raise ReconError("nmap port list is invalid")
    for part in candidate.split(","):
        if not part:
            raise ReconError("nmap port list is invalid")
        bounds = part.split("-", 1)
        try:
            numbers = [int(item) for item in bounds]
        except ValueError as error:
            raise ReconError("nmap port list is invalid") from error
        if any(not 1 <= number <= 65_535 for number in numbers):
            raise ReconError("nmap port list is invalid")
        if len(numbers) == 2 and numbers[0] > numbers[1]:
            raise ReconError("nmap port list is invalid")
    return candidate


def _normalize_domain(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReconError("domain is required")
    candidate = value.strip().lower().rstrip(".")
    parsed = urlsplit(f"//{candidate}")
    try:
        has_port = parsed.port is not None
    except ValueError as error:
        raise ReconError("domain target is malformed") from error
    if parsed.username or parsed.password or has_port or "/" in candidate:
        raise ReconError("domain target is malformed")
    if "*" in candidate or "." not in candidate:
        raise ReconError("domain target is malformed")
    if any(not label or not label.replace("-", "").isalnum() for label in candidate.split(".")):
        raise ReconError("domain target is malformed")
    return candidate


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ReconError("timestamp must include timezone information")
    return value.astimezone(timezone.utc)


def _connect_tls(
    host: str, port: int, timeout_seconds: int, *, verify: bool = True
) -> Mapping[str, str]:
    if verify:
        context = ssl.create_default_context()
    else:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout_seconds) as connection:
        with context.wrap_socket(connection, server_hostname=host) as secure:
            if verify:
                certificate = secure.getpeercert()
                subject = _certificate_name(certificate.get("subject", ()))
                issuer = _certificate_name(certificate.get("issuer", ()))
                not_after = certificate.get("notAfter")
            else:
                subject, issuer, not_after = _decode_unverified_certificate(
                    secure.getpeercert(binary_form=True)
                )
    if not subject or not issuer or not not_after:
        raise ReconError("TLS certificate metadata is incomplete")
    return {
        "subject": subject,
        "issuer": issuer,
        "expires_at": not_after,
        "status": "valid" if verify else "unverified",
    }


def _decode_unverified_certificate(der: bytes | None) -> tuple[str, str, str]:
    if not der:
        raise ReconError("TLS certificate metadata is incomplete")
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        certificate = x509.load_der_x509_certificate(der)
        common_names = {
            name: ", ".join(
                attribute.value
                for attribute in value
                if attribute.oid == NameOID.COMMON_NAME
            )
            for name, value in (
                ("subject", certificate.subject),
                ("issuer", certificate.issuer),
            )
        }
        not_after = certificate.not_valid_after_utc.strftime(
            "%b %d %H:%M:%S %Y GMT"
        )
    except Exception as error:
        raise ReconError("TLS certificate metadata is incomplete") from error
    if not common_names["subject"] or not common_names["issuer"] or not not_after:
        raise ReconError("TLS certificate metadata is incomplete")
    return common_names["subject"], common_names["issuer"], not_after


def _certificate_name(parts: object) -> str:
    if not isinstance(parts, tuple):
        return ""
    values: list[str] = []
    for group in parts:
        if isinstance(group, tuple):
            for key, value in group:
                if key == "commonName" and isinstance(value, str):
                    values.append(value)
    return ", ".join(values)
