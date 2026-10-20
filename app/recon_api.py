from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import threading

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from .recon import (
    InMemoryReconRepository,
    ReconEngine,
    ReconError,
    ReconRun,
    ReconRunState,
    Scope,
    Target,
)
from .recon_authorization import AuthorizationRegistry, AuthorizationVerificationError
from .security import AuthorizationError, Principal, require_role


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scopeId: str = Field(min_length=1, max_length=128)
    target: str = Field(min_length=1, max_length=253)
    profileId: str = Field(min_length=1, max_length=64)


class ScopeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scopeId: str = Field(
        min_length=1,
        max_length=96,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    )
    targets: tuple[str, ...] = Field(min_length=1, max_length=10)
    environment: str = Field(
        default="synthetic", pattern="^(synthetic|isolated_lab)$"
    )
    profiles: tuple[str, ...] = Field(min_length=1, max_length=4)
    expiresInHours: int = Field(default=24, ge=1, le=168)


class AuthorizationChallengeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str = Field(min_length=1, max_length=253)


class AuthorizationVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challengeId: str = Field(min_length=1, max_length=128)
    profileIds: tuple[str, ...] = Field(min_length=1, max_length=4)


@dataclass
class _QueuedScan:
    scan_id: str
    scope: Scope
    target: Target
    profile_id: str
    idempotency_key: str | None
    state: str = ReconRunState.QUEUED
    run: ReconRun | None = None


class ReconQueue:
    def __init__(
        self,
        engine: ReconEngine,
        repository: InMemoryReconRepository,
        authorization_registry: AuthorizationRegistry | None = None,
        persistence: object | None = None,
    ) -> None:
        self.engine = engine
        self.repository = repository
        self._scopes: dict[str, Scope] = {}
        self._scope_authorizations: dict[str, str] = {}
        self.authorization_registry = authorization_registry
        self.persistence = persistence
        self._jobs: dict[str, _QueuedScan] = {}
        self._idempotency: dict[str, tuple[str, str]] = {}
        self._lock = threading.Lock()

    def add_scope(self, scope: Scope, authorization_id: str | None = None) -> None:
        self._scopes[scope.scope_id] = scope
        if authorization_id is not None:
            self._scope_authorizations[scope.scope_id] = authorization_id

    def enqueue(
        self,
        scope: Scope,
        target: Target,
        profile_id: str,
        idempotency_key: str | None,
    ) -> _QueuedScan:
        request_fingerprint = f"{scope.scope_id}:{target.value}:{profile_id}"
        with self._lock:
            if idempotency_key is not None:
                existing = self._idempotency.get(idempotency_key)
                if existing is not None:
                    if existing[0] != request_fingerprint:
                        raise ReconError(
                            "idempotency key was reused with a different request"
                        )
                    return self._jobs[existing[1]]
            job = _QueuedScan(
                scan_id=self._new_scan_id(),
                scope=scope,
                target=target,
                profile_id=profile_id,
                idempotency_key=idempotency_key,
            )
            self._jobs[job.scan_id] = job
            if idempotency_key is not None:
                self._idempotency[idempotency_key] = (
                    request_fingerprint,
                    job.scan_id,
                )
            return job

    def get(self, scan_id: str) -> _QueuedScan | None:
        return self._jobs.get(scan_id)

    def run_pending(self) -> None:
        for job in tuple(self._jobs.values()):
            if job.state != ReconRunState.QUEUED:
                continue
            job.state = ReconRunState.RUNNING
            job.run = self.engine.create_run(
                job.scope,
                job.target,
                profile_id=job.profile_id,
                idempotency_key=job.idempotency_key,
            )
            if self.persistence is not None and job.run.state in {
                ReconRunState.COMPLETED,
                ReconRunState.PARTIAL,
                ReconRunState.FAILED,
                ReconRunState.TIMED_OUT,
                ReconRunState.CANCELLED,
            }:
                result = self.repository.results.get(job.run.run_id)
                if result is not None:
                    self.persistence.commit_results(
                        job.run.run_id,
                        job.scope.scope_id,
                        job.run.state.value,
                        result.assets,
                        tuple(
                            (service.asset, service.protocol, service.port, service.product or "unknown")
                            for service in result.services
                        ),
                        job.run.warnings,
                        result.inventory_delta,
                    )
            job.state = job.run.state

    def cancel(self, scan_id: str) -> _QueuedScan:
        job = self._jobs.get(scan_id)
        if job is None:
            raise KeyError(scan_id)
        if job.state == ReconRunState.QUEUED:
            job.state = ReconRunState.CANCELLED
        return job

    def _new_scan_id(self) -> str:
        from uuid import uuid4

        return str(uuid4())


def create_recon_app(
    queue: ReconQueue,
    principal_provider: Callable[[Request], Principal | None],
    read_repository: object | None = None,
) -> FastAPI:
    app = FastAPI()

    def principal(request: Request, role: str) -> Principal:
        return require_role(principal_provider(request), role)

    @app.exception_handler(AuthorizationError)
    async def authorization_error(
        request: Request, error: AuthorizationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=error.status_code,
            content={"error": {"code": "authorization_error", "message": str(error)}},
        )

    @app.exception_handler(ReconError)
    async def recon_error(request: Request, error: ReconError) -> JSONResponse:
        status = 409 if "idempotency" in str(error) else 400
        return JSONResponse(
            status_code=status,
            content={"error": {"code": "recon_error", "message": str(error)}},
        )

    def scope_view(scope: Scope) -> dict[str, object]:
        return {
            "scopeId": scope.scope_id,
            "targets": list(scope.targets),
            "environment": scope.environment,
            "profiles": list(scope.profiles),
            "approved": scope.approved,
            "expiresAt": scope.expires_at.isoformat(),
        }

    @app.get("/api/v1/recon/scopes")
    async def list_scopes(request: Request) -> dict[str, object]:
        actor = principal(request, "viewer")
        scopes = [
            scope_view(scope)
            for scope in queue._scopes.values()
            if scope.owner_id == actor.subject
        ]
        return {"items": sorted(scopes, key=lambda item: str(item["scopeId"]))}

    @app.post("/api/v1/recon/scopes", status_code=201)
    async def create_scope(
        request: Request, payload: ScopeRequest
    ) -> dict[str, object]:
        actor = principal(request, "operator")
        existing = queue._scopes.get(payload.scopeId)
        if existing is not None and existing.owner_id != actor.subject:
            raise AuthorizationError("Authorization denied", 403)
        scope = Scope(
            scope_id=payload.scopeId,
            owner_id=actor.subject,
            targets=payload.targets,
            environment=payload.environment,
            approved=True,
            expires_at=datetime.now(timezone.utc)
            + timedelta(hours=payload.expiresInHours),
            profiles=payload.profiles,
        )
        queue.add_scope(scope)
        return scope_view(scope)

    @app.post("/api/v1/recon/scans", status_code=202)
    async def create_scan(
        request: Request,
        payload: ScanRequest,
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, str]:
        actor = principal(request, "operator")
        scope = queue._scopes.get(payload.scopeId)
        if scope is None or scope.owner_id != actor.subject:
            raise AuthorizationError("Authorization denied", 403)
        target = Target(payload.target, "domain")
        scope.require_target(target, payload.profileId, datetime.now(timezone.utc))
        if scope.environment == "isolated_lab":
            authorization_id = queue._scope_authorizations.get(scope.scope_id)
            if queue.authorization_registry is None or authorization_id is None:
                raise AuthorizationError("Authorization denied", 403)
            try:
                queue.authorization_registry.authorize(
                    authorization_id,
                    owner_id=actor.subject,
                    target=target.value,
                    profile_id=payload.profileId,
                )
            except AuthorizationVerificationError as error:
                raise AuthorizationError("Authorization denied", 403) from error
        job = queue.enqueue(scope, target, payload.profileId, idempotency_key)
        return {"scanId": job.scan_id, "state": job.state}

    @app.post("/api/v1/recon/authorizations/challenges", status_code=201)
    async def create_authorization_challenge(
        request: Request, payload: AuthorizationChallengeRequest
    ) -> dict[str, str]:
        actor = principal(request, "operator")
        if queue.authorization_registry is None:
            raise HTTPException(status_code=503, detail="authorization unavailable")
        challenge = queue.authorization_registry.create_challenge(
            payload.domain, actor.subject
        )
        return {
            "challengeId": challenge.challenge_id,
            "recordName": challenge.record_name,
            "token": challenge.token,
            "expiresAt": challenge.expires_at.isoformat(),
        }

    @app.post("/api/v1/recon/authorizations", status_code=201)
    async def verify_authorization(
        request: Request, payload: AuthorizationVerifyRequest
    ) -> dict[str, str]:
        actor = principal(request, "operator")
        if queue.authorization_registry is None:
            raise HTTPException(status_code=503, detail="authorization unavailable")
        try:
            authorization = queue.authorization_registry.verify_challenge(
                payload.challengeId,
                owner_id=actor.subject,
                profile_ids=payload.profileIds,
            )
        except AuthorizationVerificationError as error:
            raise AuthorizationError("Authorization denied", 403) from error
        return {
            "authorizationId": authorization.authorization_id,
            "target": authorization.target,
            "expiresAt": authorization.expires_at.isoformat(),
        }

    @app.get("/api/v1/recon/scans/{scan_id}")
    async def get_scan(request: Request, scan_id: str) -> dict[str, str]:
        actor = principal(request, "viewer")
        job = queue.get(scan_id)
        if job is None:
            raise HTTPException(status_code=404, detail="scan not found")
        if job.scope.owner_id != actor.subject:
            raise AuthorizationError("Authorization denied", 403)
        return {"scanId": scan_id, "state": job.state}

    @app.get("/api/v1/recon/scans/{scan_id}/result")
    async def get_scan_result(
        request: Request, scan_id: str
    ) -> dict[str, object]:
        actor = principal(request, "viewer")
        job = queue.get(scan_id)
        if job is None:
            raise HTTPException(status_code=404, detail="scan not found")
        if job.scope.owner_id != actor.subject:
            raise AuthorizationError("Authorization denied", 403)
        result = (
            queue.repository.results.get(job.run.run_id)
            if job.run is not None
            else None
        )
        return {
            "scanId": scan_id,
            "state": job.state,
            "target": job.target.value,
            "profileId": job.profile_id,
            "assets": list(result.assets) if result is not None else [],
            "services": [
                {
                    "asset": service.asset,
                    "protocol": service.protocol,
                    "port": service.port,
                    "product": service.product,
                    "version": service.version,
                    "tlsStatus": service.tls_status,
                }
                for service in (result.services if result is not None else ())
            ],
            "tlsFindings": [
                dict(finding)
                for finding in (result.tls_findings if result is not None else ())
            ],
            "warnings": list(job.run.warnings) if job.run is not None else [],
        }

    @app.post("/api/v1/recon/scans/{scan_id}/cancel")
    async def cancel_scan(request: Request, scan_id: str) -> dict[str, str]:
        actor = principal(request, "operator")
        job = queue.get(scan_id)
        if job is None or job.scope.owner_id != actor.subject:
            raise AuthorizationError("Authorization denied", 403)
        cancelled = queue.cancel(scan_id)
        return {"scanId": scan_id, "state": cancelled.state}

    @app.get("/api/v1/assets")
    async def list_assets(request: Request) -> dict[str, list[str]]:
        actor = principal(request, "viewer")
        if read_repository is not None:
            return {"assets": [
                item["identifier"]
                for item in read_repository.list_assets(actor.subject)
            ]}
        assets = {
            asset
            for run_id, result in queue.repository.results.items()
            if queue._scopes[queue.repository.runs[run_id].scope_id].owner_id
            == actor.subject
            for asset in result.assets
        }
        return {"assets": sorted(assets)}

    @app.get("/api/v1/assets/{asset_id}")
    async def get_asset(request: Request, asset_id: str) -> dict[str, str]:
        actor = principal(request, "viewer")
        if read_repository is not None:
            asset = read_repository.get_asset(actor.subject, asset_id)
            if asset is not None:
                return asset
            raise HTTPException(status_code=404, detail="asset not found")
        for run_id, result in queue.repository.results.items():
            scope = queue._scopes[queue.repository.runs[run_id].scope_id]
            if scope.owner_id == actor.subject and asset_id in result.assets:
                return {"assetId": asset_id}
        raise HTTPException(status_code=404, detail="asset not found")

    return app
