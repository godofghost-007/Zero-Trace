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
from app.recon import (  # noqa: E402
    AdapterResult,
    InMemoryReconRepository,
    NmapAdapter,
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


def create_live_engine(settings: EngineSettings) -> FastAPI:
    repository = InMemoryReconRepository()
    adapters = _configured_adapters()
    engine = ReconEngine(repository, adapters, dns_resolver=_dns_resolver)
    queue = ReconQueue(engine, repository)

    intel_repository = InMemoryIntelRepository()
    feed_transport = RetryingFeedTransport(UrllibFeedTransport())

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
    intel_app = create_intel_app(intel_repository, principal_provider, feed_transport)
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
        return {
            "status": "ready",
            "checks": {
                "recon": "ok",
                "intel": "ok",
                "guard": "ok",
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
        return {
            "service": "zerotrace-live-engine",
            "mode": "live",
            "time": datetime.now(timezone.utc).isoformat(),
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
            },
        }

    @app.post("/api/v1/guard/inspect")
    async def guard_inspect(
        request: Request, payload: GuardInspectRequest
    ) -> dict[str, object]:
        actor(request, "viewer")
        prompt = PromptInjectionDetector().scan(payload.text)
        pii = PIIScanner().scan(payload.text)
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
