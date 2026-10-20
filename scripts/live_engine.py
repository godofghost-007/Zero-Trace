"""Loopback-only live engine for the ZeroTrace admin UI.

This process composes the real Recon, Intel and Guard components from
``app/`` into a single FastAPI service. It is deliberately conservative:

- It binds to loopback only and authenticates every API call with an API key.
- Recon profiles are limited to adapters that are actually installed.
- The TLS profile performs a single bounded, read-only metadata read on 443
  for a target that an operator explicitly placed in an approved scope.
- Guard inspection uses the real prompt-injection and PII detectors; no
  upstream model is contacted.

Run it with::

    python -m scripts.live_engine

The Flask UI backend holds the API key and talks to this service server-side,
so the browser never receives the key.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import logging
import os
from pathlib import Path
import shutil
import socket
import sys
import threading

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
import uvicorn

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.guard import PIIScanner, PromptInjectionDetector  # noqa: E402
from app.integration import IntegratedReadinessState  # noqa: E402
from app.intel import ServiceDescriptor, correlate_service  # noqa: E402
from app.intel_api import (  # noqa: E402
    InMemoryIntelRepository,
    create_intel_app,
)
from app.intel_feeds import (  # noqa: E402
    CISA_KEV_ENDPOINT,
    EPSS_ENDPOINT,
    NVD_ENDPOINT,
    FeedError,
    RetryingFeedTransport,
    UrllibFeedTransport,
)
from app.live_store import LiveStore  # noqa: E402
from app.recon import (  # noqa: E402
    AdapterResult,
    InMemoryReconRepository,
    NmapAdapter,
    NormalizedService,
    PROFILES,
    ReconEngine,
    ReconError,
    SubfinderAdapter,
    SubprocessRunner,
    SyntheticAdapter,
    TLSAdapter,
)
from app.recon_api import ReconQueue, create_recon_app  # noqa: E402
from app.security import (  # noqa: E402
    AuthConfig,
    AuthorizationError,
    Principal,
    require_role,
    verify_api_key,
)

LOGGER = logging.getLogger("zerotrace.live_engine")
DEFAULT_API_KEY = "sk-zerotrace-local-engine-7f3c9a2b"
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
WEB_PORTS = {80, 443, 8080, 8081, 8443}
VENDOR_BY_PRODUCT = {
    "nginx": ("nginx", "nginx"),
    "apache": ("apache", "http_server"),
    "apache httpd": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "iis": ("microsoft", "internet_information_services"),
    "microsoft-iis": ("microsoft", "internet_information_services"),
    "openssh": ("openbsd", "openssh"),
    "openbsd": ("openbsd", "openssh"),
    "postgresql": ("postgresql", "postgresql"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "openssl": ("openssl", "openssl"),
}


def _database_path() -> Path:
    configured = os.environ.get("ZEROTRACE_LIVE_DB", "")
    return (
        Path(configured).expanduser()
        if configured
        else ROOT / "data" / "live-engine.sqlite3"
    )


def _is_exposed(service: NormalizedService) -> bool:
    product = (service.product or "").lower()
    return service.port in WEB_PORTS or any(
        marker in product for marker in ("http", "https", "tls", "ssl")
    )


def _service_descriptor(
    scope_id: str, service: NormalizedService
) -> ServiceDescriptor | None:
    raw_product = (service.product or "").strip().lower()
    if not raw_product:
        return None
    vendor, product = VENDOR_BY_PRODUCT.get(
        raw_product, (raw_product.split()[0], raw_product)
    )
    return ServiceDescriptor(
        service_id=(
            f"{scope_id}:{service.asset}:{service.protocol}:{service.port}"
        ),
        asset_id=service.asset,
        product=product,
        vendor=vendor,
        version=service.version,
        cpe=None,
        exposed=_is_exposed(service),
    )


def _correlate_repository(repository: InMemoryIntelRepository) -> None:
    """Rebuild deterministic findings from persisted services and facts."""

    findings: dict[str, object] = {}
    uncertain: list[object] = []
    facts = [
        fact for fact in repository.facts.values() if fact.cpe_names
    ]
    for service in sorted(
        repository.services.values(), key=lambda item: item.service_id
    ):
        for fact in sorted(facts, key=lambda item: item.cve_id):
            outcome = correlate_service(service, fact)
            if outcome.finding is not None:
                findings[
                    f"{service.service_id}:{fact.cve_id}"
                ] = outcome.finding
            elif outcome.uncertain is not None:
                uncertain.append(outcome.uncertain)
    repository.replace_findings(findings, uncertain)


def _sync_scan_services(
    queue: ReconQueue, repository: InMemoryIntelRepository
) -> None:
    for job in queue._jobs.values():
        if job.run is None:
            continue
        result = queue.repository.results.get(job.run.run_id)
        if result is None:
            continue
        for service in result.services:
            descriptor = _service_descriptor(job.scope.scope_id, service)
            if descriptor is not None:
                repository.add_service(descriptor)
    _correlate_repository(repository)


def _readiness_payload(
    queue: ReconQueue,
    repository: InMemoryIntelRepository,
    store: LiveStore,
    *,
    persist: bool = False,
) -> dict[str, object]:
    assets: set[str] = set()
    services: dict[tuple[str, str, int], NormalizedService] = {}
    for job in queue._jobs.values():
        if job.run is None:
            continue
        result = queue.repository.results.get(job.run.run_id)
        if result is None:
            continue
        assets.update(result.assets)
        for service in result.services:
            assets.add(service.asset)
            services[(service.asset, service.protocol, service.port)] = service

    findings = list(repository.findings.values())
    nvd_loaded = any(
        fact.source == "nvd" for fact in repository.facts.values()
    )
    intel_complete = nvd_loaded and all(
        not finding.priority.missing for finding in findings
    )
    guard = store.guard_counts()
    state = IntegratedReadinessState()
    state.record_recon(
        assets=assets,
        total_services=len(services),
        exposed_services=sum(
            1 for service in services.values() if _is_exposed(service)
        ),
    )
    state.record_findings(findings)
    state.intel_complete = intel_complete
    state.total_requests = guard["total"]
    state.unblocked_attacks = guard["unblocked"]
    result = state.calculate()
    payload: dict[str, object] = {
        "formulaVersion": result.formula_version,
        "score": result.score,
        "band": result.band,
        "coverage": result.coverage,
        "unknownComponents": list(result.unknown_components),
        "components": [
            {
                "name": component.name,
                "value": component.value,
                "numerator": component.numerator,
                "denominator": component.denominator,
                "status": component.status,
            }
            for component in result.components
        ],
        "inputs": {
            "assets": len(assets),
            "services": len(services),
            "exposedServices": sum(
                1 for service in services.values() if _is_exposed(service)
            ),
            "intelFacts": len(repository.facts),
            "findings": len(findings),
            "uncertainMatches": len(repository.uncertain_matches),
            "guardRequests": guard["total"],
            "unblockedAttacks": guard["unblocked"],
            "nvdLoaded": nvd_loaded,
        },
        "readiness": "known" if result.score is not None else "incomplete",
    }
    if persist:
        store.save_readiness(payload)
    return payload



@dataclass(frozen=True)
class EngineSettings:
    host: str = "127.0.0.1"
    port: int = 8765
    api_key: str = DEFAULT_API_KEY
    auth_secret: bytes = b""

    def __post_init__(self) -> None:
        if self.host not in LOOPBACK_HOSTS:
            raise ValueError("engine must bind to a loopback host")
        if not 1 <= self.port <= 65535:
            raise ValueError("engine port is invalid")
        if len(self.api_key) < 16:
            raise ValueError("engine API key must contain at least 16 characters")
        if len(self.auth_secret) < 32:
            raise ValueError("engine auth secret must contain at least 32 bytes")

    @classmethod
    def from_env(cls) -> "EngineSettings":
        api_key = os.environ.get("ZEROTRACE_ENGINE_API_KEY", DEFAULT_API_KEY)
        raw_secret = os.environ.get("ZEROTRACE_ENGINE_AUTH_SECRET", "").encode()
        secret = raw_secret or hashlib.sha256(
            b"zerotrace-local-engine:" + api_key.encode("utf-8")
        ).digest()
        raw_port = os.environ.get("ZEROTRACE_ENGINE_PORT", "8765")
        try:
            port = int(raw_port)
        except ValueError as error:
            raise ValueError("ZEROTRACE_ENGINE_PORT must be an integer") from error
        return cls(
            host=os.environ.get("ZEROTRACE_ENGINE_HOST", "127.0.0.1"),
            port=port,
            api_key=api_key,
            auth_secret=secret,
        )


class GuardInspectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1, max_length=8_000)


def _configured_adapters() -> dict[str, object]:
    adapters: dict[str, object] = {
        "synthetic_inventory_v1": SyntheticAdapter(
            AdapterResult(
                assets=("lab.example.test",),
                services=(("lab.example.test", "tcp", 443, "https"),),
                warnings=(),
            )
        ),
        "tls_metadata_v1": TLSAdapter(),
    }
    runner = SubprocessRunner()
    nmap = shutil.which("nmap")
    if nmap:
        adapters["service_inventory_v1"] = NmapAdapter(nmap, runner)
    subfinder = shutil.which("subfinder")
    if subfinder:
        adapters["passive_subdomain_v1"] = SubfinderAdapter(subfinder, runner)
    return adapters


def _dns_resolver(host: str) -> tuple[str, ...]:
    return tuple(socket.gethostbyname_ex(host)[2])


def create_live_engine(
    settings: EngineSettings,
    *,
    store: LiveStore | None = None,
    feed_transport: object | None = None,
) -> FastAPI:
    repository = InMemoryReconRepository()
    adapters = _configured_adapters()
    engine = ReconEngine(repository, adapters, dns_resolver=_dns_resolver)
    store = store or LiveStore(_database_path())

    intel_repository = InMemoryIntelRepository()
    transport = feed_transport or RetryingFeedTransport(UrllibFeedTransport())

    def persist_intel() -> None:
        store.save_intel_state(
            facts=intel_repository.facts.values(),
            epss_records=intel_repository.epss_records,
            kev_records=intel_repository.kev_records,
            ingestions=intel_repository.ingestions,
            idempotency=intel_repository.idempotency,
        )

    intel_repository.on_change = persist_intel
    persisted = store.load_intel_state()
    intel_repository.hydrate(
        facts=persisted["facts"],  # type: ignore[arg-type]
        epss_records=persisted["epss"],  # type: ignore[arg-type]
        kev_records=persisted["kev"],  # type: ignore[arg-type]
        ingestions=persisted["ingestions"],  # type: ignore[arg-type]
        idempotency=persisted["idempotency"],  # type: ignore[arg-type]
    )

    def scan_completed(job: object) -> None:
        _sync_scan_services(queue, intel_repository)
        intel_repository.notify_change()

    queue = ReconQueue(
        engine,
        repository,
        persistence=store,
        on_scan_complete=scan_completed,
    )
    _sync_scan_services(queue, intel_repository)
    persist_intel()

    auth_config = AuthConfig(settings.auth_secret, settings.auth_secret)
    expected_digest = auth_config.api_key_digest(settings.api_key)

    def principal_provider(request: Request) -> Principal | None:
        provided = request.headers.get("X-API-Key", "")
        if not verify_api_key(provided, expected_digest, auth_config):
            return None
        return Principal("local-operator", "operator")

    def actor(request: Request, role: str) -> Principal:
        return require_role(principal_provider(request), role)

    stop_worker = threading.Event()

    def scan_worker() -> None:
        while not stop_worker.is_set():
            try:
                queue.run_pending()
            except Exception:  # pragma: no cover - defensive worker isolation
                LOGGER.exception("recon worker iteration failed")
            stop_worker.wait(0.5)

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        thread = threading.Thread(
            target=scan_worker, name="zerotrace-recon-worker", daemon=True
        )
        thread.start()
        try:
            yield
        finally:
            stop_worker.set()
            thread.join(timeout=5)

    app = FastAPI(title="ZeroTrace live engine", lifespan=lifespan)

    recon_app = create_recon_app(queue, principal_provider)
    intel_app = create_intel_app(intel_repository, principal_provider, transport)
    app.router.routes.extend(recon_app.routes)
    app.router.routes.extend(intel_app.routes)

    @app.exception_handler(AuthorizationError)
    async def authorization_error(
        request: Request, error: AuthorizationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=error.status_code,
            content={
                "error": {
                    "code": "authorization_error",
                    "message": str(error),
                }
            },
        )

    @app.exception_handler(ReconError)
    async def recon_error(request: Request, error: ReconError) -> JSONResponse:
        status = 409 if "idempotency" in str(error) else 400
        return JSONResponse(
            status_code=status,
            content={"error": {"code": "recon_error", "message": str(error)}},
        )

    @app.exception_handler(FeedError)
    async def feed_error(request: Request, error: FeedError) -> JSONResponse:
        status = 409 if "idempotency" in str(error) else 400
        return JSONResponse(
            status_code=status,
            content={"error": {"code": "intel_error", "message": str(error)}},
        )

    @app.exception_handler(Exception)
    async def unhandled_error(request: Request, error: Exception) -> JSONResponse:
        LOGGER.exception("unhandled engine error", exc_info=error)
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "internal_error",
                    "message": "The live engine could not complete the request.",
                }
            },
        )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "healthy"}

    @app.get("/ready")
    async def ready() -> dict[str, object]:
        storage_ok = store.ping()
        return {
            "status": "ready" if storage_ok else "degraded",
            "checks": {
                "recon": "ok",
                "intel": "ok",
                "guard": "ok",
                "storage": "ok" if storage_ok else "degraded",
                "worker": "stopped" if stop_worker.is_set() else "running",
            },
        }

    @app.get("/api/v1/engine/status")
    async def engine_status(request: Request) -> dict[str, object]:
        current = actor(request, "viewer")
        scopes = [
            scope
            for scope in queue._scopes.values()
            if scope.owner_id == current.subject
        ]
        jobs = [
            job
            for job in queue._jobs.values()
            if job.scope.owner_id == current.subject
        ]
        guard = store.guard_counts()
        readiness = _readiness_payload(queue, intel_repository, store)
        return {
            "service": "zerotrace-live-engine",
            "mode": "live",
            "time": datetime.now(timezone.utc).isoformat(),
            "storage": "sqlite",
            "adapters": sorted(adapters.keys()),
            "profiles": sorted(
                profile_id
                for profile_id in PROFILES
                if profile_id in adapters
            ),
            "scopes": len(scopes),
            "scans": len(jobs),
            "intel": {
                "facts": len(intel_repository.facts),
                "findings": len(intel_repository.findings),
                "uncertainMatches": len(intel_repository.uncertain_matches),
                "kevRecords": len(intel_repository.kev_records),
                "epssRecords": len(intel_repository.epss_records),
                "feeds": {
                    "nvd": NVD_ENDPOINT,
                    "epss": EPSS_ENDPOINT,
                    "kev": CISA_KEV_ENDPOINT,
                },
            },
            "guard": {
                "mode": "inspect-only",
                "detector": "regex-heuristic-v1",
                "piiScanner": True,
                "upstreamConfigured": False,
                "inspectionRequests": guard["total"],
                "unblockedRequests": guard["unblocked"],
            },
            "readiness": {
                "score": readiness["score"],
                "band": readiness["band"],
                "coverage": readiness["coverage"],
                "status": readiness["readiness"],
            },
        }

    @app.get("/api/v1/engine/readiness")
    async def engine_readiness(request: Request) -> dict[str, object]:
        actor(request, "viewer")
        return _readiness_payload(
            queue, intel_repository, store, persist=True
        )

    @app.get("/api/v1/recon/scans")
    async def list_scans(request: Request) -> dict[str, object]:
        current = actor(request, "viewer")
        items = [
            {
                "scanId": job.scan_id,
                "scopeId": job.scope.scope_id,
                "target": job.target.value,
                "profileId": job.profile_id,
                "state": str(job.state),
            }
            for job in queue._jobs.values()
            if job.scope.owner_id == current.subject
        ]
        return {"items": items}

    @app.post("/api/v1/guard/inspect")
    async def guard_inspect(
        request: Request, payload: GuardInspectRequest
    ) -> dict[str, object]:
        actor(request, "viewer")
        prompt = PromptInjectionDetector().scan(payload.text)
        pii = PIIScanner().scan(payload.text)
        store.record_guard_event(
            blocked=prompt.blocked,
            reason=prompt.reason,
            pii_blocked=pii.blocked,
        )
        return {
            "blocked": prompt.blocked,
            "reason": prompt.reason,
            "details": prompt.details,
            "pii": {
                "blocked": pii.blocked,
                "reason": pii.reason,
            },
            "mode": "inspect-only",
        }

    return app


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("ZEROTRACE_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    settings = EngineSettings.from_env()
    LOGGER.info("starting live engine on %s:%s", settings.host, settings.port)
    uvicorn.run(
        create_live_engine(settings),
        host=settings.host,
        port=settings.port,
        log_level=os.environ.get("ZEROTRACE_LOG_LEVEL", "info").lower(),
    )


if __name__ == "__main__":
    main()
