from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Protocol
from uuid import uuid4

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from .intel import ServiceDescriptor, VulnerabilityFact, match_service
from .intel_feeds import (
    CISA_KEV_ENDPOINT,
    EPSS_ENDPOINT,
    NVD_ENDPOINT,
    FeedError,
    FeedTransport,
    KevFeed,
    NvdFeed,
    merge_intel_signals,
    sync_epss,
    sync_nvd,
)
from .security import AuthorizationError, Principal, require_role


SOURCE_ENDPOINTS = {
    "nvd": NVD_ENDPOINT,
    "epss": EPSS_ENDPOINT,
    "kev": CISA_KEV_ENDPOINT,
}


class IngestionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str = Field(pattern="^(nvd|epss|kev)$")


class IntelNotFoundError(FeedError):
    pass


@dataclass(frozen=True)
class Ingestion:
    ingestion_id: str
    source: str
    state: str
    fact_count: int
    error: str | None = None


class InMemoryIntelRepository:
    def __init__(self) -> None:
        self.facts: dict[str, VulnerabilityFact] = {}
        self.services: dict[str, ServiceDescriptor] = {}
        self.findings: dict[str, object] = {}
        self.uncertain_matches: list[object] = []
        self.epss_records = ()
        self.kev_records = ()
        self.ingestions: dict[str, Ingestion] = {}
        self.idempotency: dict[str, tuple[str, str]] = {}
        self.on_change: Callable[[], None] | None = None

    def add_service(self, service: ServiceDescriptor) -> None:
        self.services[service.service_id] = service

    def hydrate(
        self,
        *,
        facts: tuple[VulnerabilityFact, ...] = (),
        epss_records: tuple[object, ...] = (),
        kev_records: tuple[object, ...] = (),
        ingestions: dict[str, Ingestion] | None = None,
        idempotency: dict[str, tuple[str, str]] | None = None,
    ) -> None:
        """Restore a previously persisted feed snapshot."""

        self.facts = {fact.cve_id: fact for fact in facts}
        self.epss_records = tuple(epss_records)
        self.kev_records = tuple(kev_records)
        self.ingestions = dict(ingestions or {})
        self.idempotency = dict(idempotency or {})

    def replace_findings(
        self,
        findings: dict[str, object],
        uncertain_matches: list[object],
    ) -> None:
        self.findings = findings
        self.uncertain_matches = uncertain_matches

    def notify_change(self) -> None:
        if self.on_change is not None:
            self.on_change()


class IntelPersistence(Protocol):
    def save_fact(self, fact: VulnerabilityFact) -> str:
        ...


def ingest_source(
    repository: InMemoryIntelRepository,
    transport: FeedTransport,
    source: str,
    *,
    idempotency_key: str,
    persistence: IntelPersistence | None = None,
    retrieved_at: datetime | None = None,
) -> Ingestion:
    """Run one bounded feed ingestion.

    This is shared by the HTTP endpoint and the scheduled worker so both paths
    enforce the same allowlist, idempotency, persistence, and failure semantics.
    """

    if not idempotency_key or not idempotency_key.strip():
        raise AuthorizationError("Idempotency-Key is required", 400)
    endpoint = SOURCE_ENDPOINTS.get(source)
    if endpoint is None:
        raise FeedError("feed source is not allowlisted")
    request_hash = source
    existing = repository.idempotency.get(idempotency_key)
    if existing is not None:
        if existing[0] != request_hash:
            raise FeedError("idempotency key was reused with a different request")
        return repository.ingestions[existing[1]]
    ingestion_id = str(uuid4())
    try:
        if source == "nvd":
            sync_result = sync_nvd(
                transport,
                retrieved_at=retrieved_at or datetime.now(timezone.utc),
                last_known_good=tuple(repository.facts.values()),
            )
            facts = merge_intel_signals(
                sync_result.facts, repository.epss_records, repository.kev_records
            )
            for fact in facts:
                repository.facts[fact.cve_id] = fact
                if persistence is not None:
                    persistence.save_fact(fact)
                for service in repository.services.values():
                    finding = match_service(service, fact)
                    if finding is not None:
                        repository.findings[
                            f"{service.service_id}:{fact.cve_id}"
                        ] = finding
            count = len(facts)
        else:
            if source == "epss":
                repository.epss_records = sync_epss(transport)
                facts = merge_intel_signals(
                    tuple(repository.facts.values()),
                    repository.epss_records,
                    repository.kev_records,
                )
                repository.facts = {fact.cve_id: fact for fact in facts}
                count = len(repository.epss_records)
            else:
                response = transport.get(endpoint)
                repository.kev_records = KevFeed().parse(response.body)
                facts = merge_intel_signals(
                    tuple(repository.facts.values()),
                    repository.epss_records,
                    repository.kev_records,
                )
                repository.facts = {fact.cve_id: fact for fact in facts}
                count = len(repository.kev_records)
        ingestion = Ingestion(ingestion_id, source, "completed", count)
    except FeedError as error:
        ingestion = Ingestion(ingestion_id, source, "failed", 0, str(error))
    repository.ingestions[ingestion_id] = ingestion
    repository.idempotency[idempotency_key] = (request_hash, ingestion_id)
    repository.notify_change()
    return ingestion


def create_intel_app(
    repository: InMemoryIntelRepository,
    principal_provider: Callable[[Request], Principal | None],
    transport: FeedTransport,
    persistence: IntelPersistence | None = None,
    read_repository: object | None = None,
) -> FastAPI:
    app = FastAPI()

    @app.exception_handler(AuthorizationError)
    async def authorization_error(request: Request, error: AuthorizationError) -> JSONResponse:
        return JSONResponse(
            status_code=error.status_code,
            content={"error": {"code": "authorization_error", "message": str(error)}},
        )

    @app.exception_handler(FeedError)
    async def feed_error(request: Request, error: FeedError) -> JSONResponse:
        if isinstance(error, IntelNotFoundError):
            status = 404
        else:
            status = 409 if "idempotency" in str(error) else 400
        return JSONResponse(
            status_code=status,
            content={"error": {"code": "intel_error", "message": str(error)}},
        )

    def actor(request: Request, role: str) -> Principal:
        return require_role(principal_provider(request), role)

    @app.post("/api/v1/intel/ingestions", status_code=202)
    async def ingest(
        request: Request,
        payload: IngestionRequest,
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, str | int]:
        actor(request, "operator")
        if idempotency_key is None:
            raise AuthorizationError("Idempotency-Key is required", 400)
        ingestion = ingest_source(
            repository,
            transport,
            payload.source,
            idempotency_key=idempotency_key,
            persistence=persistence,
        )
        return {
            "ingestionId": ingestion.ingestion_id,
            "state": ingestion.state,
            "factCount": ingestion.fact_count,
        }

    @app.get("/api/v1/intel/ingestions/{ingestion_id}")
    async def ingestion_status(request: Request, ingestion_id: str) -> dict[str, object]:
        actor(request, "viewer")
        ingestion = repository.ingestions.get(ingestion_id)
        if ingestion is None:
            raise FeedError("ingestion was not found")
        return ingestion.__dict__

    @app.get("/api/v1/intel/status")
    async def intel_status(request: Request) -> dict[str, object]:
        actor(request, "viewer")
        return {
            "mode": "live-engine",
            "facts": len(repository.facts),
            "findings": len(repository.findings),
            "uncertainMatches": len(repository.uncertain_matches),
            "services": len(repository.services),
            "kevRecords": len(repository.kev_records),
            "epssRecords": len(repository.epss_records),
            "feeds": {
                "nvd": NVD_ENDPOINT,
                "epss": EPSS_ENDPOINT,
                "kev": CISA_KEV_ENDPOINT,
            },
        }

    @app.get("/api/v1/findings")
    async def list_findings(request: Request) -> dict[str, object]:
        actor(request, "viewer")
        try:
            page = int(request.query_params.get("page", "1"))
            page_size = int(request.query_params.get("pageSize", "20"))
        except ValueError as error:
            raise FeedError("pagination values are invalid") from error
        if not 1 <= page or not 1 <= page_size <= 100:
            raise FeedError("pagination values are invalid")
        if read_repository is not None:
            return read_repository.list_findings(
                actor.subject,
                page=page,
                page_size=page_size,
            )
        items = list(repository.findings.values())
        start = (page - 1) * page_size
        return {
            "items": items[start:start + page_size],
            "pagination": {
                "page": page,
                "pageSize": page_size,
                "totalItems": len(items),
                "totalPages": (len(items) + page_size - 1) // page_size,
            },
        }

    @app.get("/api/v1/findings/{finding_id}")
    async def get_finding(request: Request, finding_id: str) -> object:
        principal = actor(request, "viewer")
        if read_repository is not None:
            finding = read_repository.get_finding(principal.subject, finding_id)
            if finding is None:
                raise IntelNotFoundError("finding was not found")
            return finding
        finding = repository.findings.get(finding_id)
        if finding is None:
            raise IntelNotFoundError("finding was not found")
        return finding

    @app.get("/api/v1/uncertain-matches")
    async def list_uncertain_matches(request: Request) -> dict[str, object]:
        principal = actor(request, "viewer")
        try:
            page = int(request.query_params.get("page", "1"))
            page_size = int(request.query_params.get("pageSize", "20"))
        except ValueError as error:
            raise FeedError("pagination values are invalid") from error
        if not 1 <= page or not 1 <= page_size <= 100:
            raise FeedError("pagination values are invalid")
        if read_repository is not None:
            return read_repository.list_uncertain_matches(
                principal.subject, page=page, page_size=page_size
            )
        start = (page - 1) * page_size
        items = repository.uncertain_matches
        return {
            "items": items[start:start + page_size],
            "pagination": {
                "page": page,
                "pageSize": page_size,
                "totalItems": len(items),
                "totalPages": (len(items) + page_size - 1) // page_size,
            },
        }

    return app
