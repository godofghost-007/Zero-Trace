from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import logging
import threading
import time
from typing import Protocol

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from .recon import (
    InMemoryReconRepository,
    NormalizedService,
    PROFILES,
    ReconEngine,
    ReconError,
    ReconResult,
    ReconRun,
    ReconRunState,
    Scope,
    Target,
    profile_requires_authorization,
)
from .recon_authorization import AuthorizationRegistry, AuthorizationVerificationError
from .scan_schedule import ScanScheduleRegistry
from .security import AuthorizationError, Principal, require_role
from .target_policy import TargetPolicy, TargetPolicyError

LOGGER = logging.getLogger("zerotrace.recon_api")
TERMINAL_STATES = {
    ReconRunState.COMPLETED,
    ReconRunState.PARTIAL,
    ReconRunState.FAILED,
    ReconRunState.TIMED_OUT,
    ReconRunState.CANCELLED,
}


class QueuePersistence(Protocol):
    """Durable store contract used by the local live engine."""

    def save_scope(self, scope: Scope) -> None:
        ...

    def load_scopes(self) -> list[Scope]:
        ...

    def save_scan(self, **kwargs: object) -> None:
        ...

    def load_scans(self) -> list[dict[str, object]]:
        ...


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
    authorizationId: str | None = Field(default=None, min_length=1, max_length=128)


class AuthorizationChallengeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str = Field(min_length=1, max_length=253)


class AuthorizationVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challengeId: str = Field(min_length=1, max_length=128)
    profileIds: tuple[str, ...] = Field(min_length=1, max_length=4)


class ScheduleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scopeId: str = Field(min_length=1, max_length=128)
    target: str = Field(min_length=1, max_length=253)
    profileId: str = Field(min_length=1, max_length=64)
    intervalSeconds: int = Field(ge=300, le=604800)


@dataclass
class _QueuedScan:
    scan_id: str
    scope: Scope
    target: Target
    profile_id: str
    idempotency_key: str | None
    state: ReconRunState = ReconRunState.QUEUED
    run: ReconRun | None = None


class ReconQueue:
    def __init__(
        self,
        engine: ReconEngine,
        repository: InMemoryReconRepository,
        authorization_registry: AuthorizationRegistry | None = None,
        persistence: QueuePersistence | None = None,
        on_scan_complete: Callable[[_QueuedScan], None] | None = None,
        max_queue_depth: int = 50,
        target_cooldown_seconds: float = 0,
        target_policy: TargetPolicy | None = None,
    ) -> None:
        if max_queue_depth < 1:
            raise ReconError("queue depth must be positive")
        if target_cooldown_seconds < 0:
            raise ReconError("target cooldown must be non-negative")
        self.engine = engine
        self.repository = repository
        self.target_policy = target_policy or TargetPolicy()
        self._scopes: dict[str, Scope] = {}
        self._scope_authorizations: dict[str, str] = {}
        self.authorization_registry = authorization_registry
        self.persistence = persistence
        self.on_scan_complete = on_scan_complete
        self.max_queue_depth = max_queue_depth
        self.target_cooldown_seconds = target_cooldown_seconds
        self._last_enqueue: dict[str, float] = {}
        self._jobs: dict[str, _QueuedScan] = {}
        self._idempotency: dict[str, tuple[str, str]] = {}
        self._lock = threading.Lock()
        if self.persistence is not None:
            self._restore()

    def add_scope(self, scope: Scope, authorization_id: str | None = None) -> None:
        self._scopes[scope.scope_id] = scope
        if authorization_id is not None:
            self._scope_authorizations[scope.scope_id] = authorization_id
        if self.persistence is not None:
            self.persistence.save_scope(scope)

    def _check_target_policy(self, value: str) -> None:
        try:
            self.target_policy.check(value)
        except TargetPolicyError as error:
            raise ReconError(str(error)) from error

    def enqueue(
        self,
        scope: Scope,
        target: Target,
        profile_id: str,
        idempotency_key: str | None,
    ) -> _QueuedScan:
        self._check_target_policy(target.value)
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
            active = sum(
                1
                for queued in self._jobs.values()
                if queued.state in {ReconRunState.QUEUED, ReconRunState.RUNNING}
            )
            if active >= self.max_queue_depth:
                raise ReconError("recon queue is full")
            if self.target_cooldown_seconds > 0:
                last = self._last_enqueue.get(target.value)
                now = time.monotonic()
                if last is not None and now - last < self.target_cooldown_seconds:
                    raise ReconError("target is cooling down")
            job = _QueuedScan(
                scan_id=self._new_scan_id(),
                scope=scope,
                target=target,
                profile_id=profile_id,
                idempotency_key=idempotency_key,
            )
            self._jobs[job.scan_id] = job
            self._last_enqueue[target.value] = time.monotonic()
            if idempotency_key is not None:
                self._idempotency[idempotency_key] = (
                    request_fingerprint,
                    job.scan_id,
                )
            self._persist_scan(job)
            return job

    def get(self, scan_id: str) -> _QueuedScan | None:
        return self._jobs.get(scan_id)

    def run_pending(self) -> None:
        for job in tuple(self._jobs.values()):
            if job.state != ReconRunState.QUEUED:
                continue
            job.state = ReconRunState.RUNNING
            self._persist_scan(job)
            job.run = self.engine.create_run(
                job.scope,
                job.target,
                profile_id=job.profile_id,
                idempotency_key=job.idempotency_key,
            )
            job.state = job.run.state
            self._persist_scan(job)
            if job.state in TERMINAL_STATES and self.on_scan_complete is not None:
                try:
                    self.on_scan_complete(job)
                except Exception:  # pragma: no cover - keep the worker alive
                    LOGGER.exception("scan completion hook failed")

    def cancel(self, scan_id: str) -> _QueuedScan:
        job = self._jobs.get(scan_id)
        if job is None:
            raise KeyError(scan_id)
        if job.state == ReconRunState.QUEUED:
            job.state = ReconRunState.CANCELLED
            self._persist_scan(job)
        return job

    def _persist_scan(self, job: _QueuedScan) -> None:
        if self.persistence is None:
            return
        result = (
            self.repository.results.get(job.run.run_id)
            if job.run is not None
            else None
        )
        self.persistence.save_scan(
            scan_id=job.scan_id,
            run_id=None if job.run is None else job.run.run_id,
            scope_id=job.scope.scope_id,
            target=job.target.value,
            profile_id=job.profile_id,
            state=str(job.state),
            warnings=() if job.run is None else job.run.warnings,
            assets=() if result is None else result.assets,
            services=(
                ()
                if result is None
                else tuple(
                    {
                        "asset": service.asset,
                        "protocol": service.protocol,
                        "port": service.port,
                        "product": service.product,
                        "version": service.version,
                        "tlsStatus": service.tls_status,
                    }
                    for service in result.services
                )
            ),
            tls_findings=(
                () if result is None else tuple(dict(item) for item in result.tls_findings)
            ),
        )

    def _restore(self) -> None:
        assert self.persistence is not None
        for scope in self.persistence.load_scopes():
            self._scopes[scope.scope_id] = scope
        for row in self.persistence.load_scans():
            scope_id = str(row["scopeId"])
            scope = self._scopes.get(scope_id)
            if scope is None:
                LOGGER.warning("ignoring persisted scan with unknown scope %s", scope_id)
                continue
            target = Target(str(row["target"]), "domain")
            state = ReconRunState(str(row["state"]))
            job = _QueuedScan(
                scan_id=str(row["scanId"]),
                scope=scope,
                target=target,
                profile_id=str(row["profileId"]),
                idempotency_key=None,
                state=state,
            )
            run_id = row.get("runId")
            warnings = tuple(str(item) for item in row.get("warnings", []))
            if run_id is not None:
                run = ReconRun(
                    run_id=str(run_id),
                    scope_id=scope.scope_id,
                    profile_id=job.profile_id,
                    target=target,
                    state=state,
                    warnings=warnings,
                )
                job.run = run
                self.repository.runs[run.run_id] = run
                services = tuple(
                    NormalizedService(
                        asset=str(item["asset"]),
                        protocol=str(item["protocol"]),
                        port=int(item["port"]),  # type: ignore[arg-type]
                        product=(
                            None
                            if item.get("product") is None
                            else str(item["product"])
                        ),
                        version=(
                            None
                            if item.get("version") is None
                            else str(item["version"])
                        ),
                        tls_status=(
                            None
                            if item.get("tlsStatus") is None
                            else str(item["tlsStatus"])
                        ),
                    )
                    for item in row.get("services", [])
                    if isinstance(item, dict)
                )
                result = ReconResult(
                    assets=tuple(str(item) for item in row.get("assets", [])),
                    services=services,
                    tls_findings=tuple(
                        dict(item)
                        for item in row.get("tlsFindings", [])
                        if isinstance(item, dict)
                    ),
                )
                self.repository.results[run.run_id] = result
                self.repository.latest_results[
                    (scope.scope_id, target.value, job.profile_id)
                ] = result
            if state in {ReconRunState.QUEUED, ReconRunState.RUNNING}:
                warning = "engine restarted before the scan completed"
                if job.run is not None:
                    job.run = replace(
                        job.run,
                        state=ReconRunState.FAILED,
                        warnings=job.run.warnings + (warning,),
                    )
                    self.repository.runs[job.run.run_id] = job.run
                job.state = ReconRunState.FAILED
                self._persist_scan(job)
            self._jobs[job.scan_id] = job

    def _new_scan_id(self) -> str:
        from uuid import uuid4

        return str(uuid4())


def create_recon_app(
    queue: ReconQueue,
    principal_provider: Callable[[Request], Principal | None],
    read_repository: object | None = None,
    schedule_registry: ScanScheduleRegistry | None = None,
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
        unknown = [
            profile_id
            for profile_id in payload.profiles
            if profile_id not in PROFILES
        ]
        if unknown:
            raise ReconError("profile is not allowlisted")
        for target in payload.targets:
            queue._check_target_policy(target)
        requires_authorization = payload.environment == "isolated_lab" or any(
            profile_requires_authorization(profile_id)
            for profile_id in payload.profiles
        )
        if requires_authorization and payload.environment != "isolated_lab":
            raise AuthorizationError("Authorization denied", 403)
        if requires_authorization:
            if queue.authorization_registry is None or payload.authorizationId is None:
                raise AuthorizationError("Authorization denied", 403)
            try:
                for target in payload.targets:
                    for profile_id in payload.profiles:
                        queue.authorization_registry.authorize(
                            payload.authorizationId,
                            owner_id=actor.subject,
                            target=target,
                            profile_id=profile_id,
                        )
            except AuthorizationVerificationError as error:
                raise AuthorizationError("Authorization denied", 403) from error
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
        queue.add_scope(scope, payload.authorizationId)
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
        if (
            profile_requires_authorization(payload.profileId)
            and scope.environment != "isolated_lab"
        ):
            raise AuthorizationError("Authorization denied", 403)
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

    @app.get("/api/v1/recon/schedules")
    async def list_schedules(request: Request) -> dict[str, object]:
        actor = principal(request, "viewer")
        if schedule_registry is None:
            return {"items": [], "enabled": False}
        return {
            "items": [
                schedule.view()
                for schedule in schedule_registry.list(actor.subject)
            ],
            "enabled": True,
        }

    @app.post("/api/v1/recon/schedules", status_code=201)
    async def create_schedule(
        request: Request, payload: ScheduleRequest
    ) -> dict[str, object]:
        actor = principal(request, "operator")
        if schedule_registry is None:
            raise HTTPException(status_code=503, detail="schedules unavailable")
        schedule = schedule_registry.create(
            owner_id=actor.subject,
            scope_id=payload.scopeId,
            target=payload.target,
            profile_id=payload.profileId,
            interval_seconds=payload.intervalSeconds,
        )
        return schedule.view()

    @app.post("/api/v1/recon/schedules/{schedule_id}/run")
    async def run_schedule(
        request: Request, schedule_id: str
    ) -> dict[str, object]:
        actor = principal(request, "operator")
        if schedule_registry is None:
            raise HTTPException(status_code=503, detail="schedules unavailable")
        return schedule_registry.run_now(schedule_id, actor.subject)

    @app.delete("/api/v1/recon/schedules/{schedule_id}")
    async def disable_schedule(
        request: Request, schedule_id: str
    ) -> dict[str, object]:
        actor = principal(request, "operator")
        if schedule_registry is None:
            raise HTTPException(status_code=503, detail="schedules unavailable")
        return schedule_registry.disable(schedule_id, actor.subject).view()

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
