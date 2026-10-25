"""Pre-approved, bounded scan schedules for Recon.

A schedule is not a way to bypass authorization. It can only be created by an
operator for a target and profile that are already inside an approved, unexpired
scope. Every due run re-checks the scope, target policy, profile level, and DNS
authorization before it is queued. A failed re-check disables the schedule
instead of silently retrying outside the approved boundary.

High and Deep profiles still require an ``isolated_lab`` scope and a verified
DNS TXT authorization. Normal and Medium schedules can run against a synthetic
scope without DNS TXT, exactly like an interactive scan.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Protocol
from uuid import uuid4

from .recon import (
    PROFILES,
    ReconError,
    Scope,
    Target,
    profile_requires_authorization,
)
from .recon_authorization import (
    AuthorizationRegistry,
    AuthorizationVerificationError,
)
from .security import AuthorizationError
from .target_policy import TargetPolicy, TargetPolicyError

MIN_INTERVAL_SECONDS = 300
MAX_INTERVAL_SECONDS = 7 * 24 * 60 * 60
RETRY_DELAY_SECONDS = 60


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ReconError("schedule time must include timezone information")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class ScanSchedule:
    schedule_id: str
    owner_id: str
    scope_id: str
    target: str
    profile_id: str
    interval_seconds: int
    enabled: bool
    next_run_at: datetime
    created_at: datetime
    authorization_id: str | None = None
    last_run_at: datetime | None = None
    last_scan_id: str | None = None
    last_state: str | None = None
    last_error: str | None = None
    runs: int = 0

    def __post_init__(self) -> None:
        if not self.schedule_id or not self.owner_id or not self.scope_id:
            raise ReconError("schedule identity is required")
        if not self.target or not self.profile_id:
            raise ReconError("schedule target and profile are required")
        if self.profile_id not in PROFILES:
            raise ReconError("schedule profile is not allowlisted")
        if not MIN_INTERVAL_SECONDS <= self.interval_seconds <= MAX_INTERVAL_SECONDS:
            raise ReconError("schedule interval is outside the allowed range")
        object.__setattr__(self, "next_run_at", _utc(self.next_run_at))
        object.__setattr__(self, "created_at", _utc(self.created_at))
        if self.last_run_at is not None:
            object.__setattr__(self, "last_run_at", _utc(self.last_run_at))
        if self.runs < 0:
            raise ReconError("schedule run count is invalid")

    def view(self) -> dict[str, object]:
        return {
            "scheduleId": self.schedule_id,
            "scopeId": self.scope_id,
            "target": self.target,
            "profileId": self.profile_id,
            "intervalSeconds": self.interval_seconds,
            "enabled": self.enabled,
            "nextRunAt": self.next_run_at.isoformat(),
            "createdAt": self.created_at.isoformat(),
            "lastRunAt": (
                None if self.last_run_at is None else self.last_run_at.isoformat()
            ),
            "lastScanId": self.last_scan_id,
            "lastState": self.last_state,
            "lastError": self.last_error,
            "runs": self.runs,
        }


class SchedulePersistence(Protocol):
    def save_scan_schedule(self, schedule: ScanSchedule) -> None:
        ...

    def load_scan_schedules(self) -> list[ScanSchedule]:
        ...

    def delete_scan_schedule(self, schedule_id: str) -> None:
        ...


class ScheduleQueue(Protocol):
    _scopes: dict[str, Scope]
    _scope_authorizations: dict[str, str]
    authorization_registry: AuthorizationRegistry | None

    def enqueue(
        self,
        scope: Scope,
        target: Target,
        profile_id: str,
        idempotency_key: str | None,
    ) -> object:
        ...


class ScanScheduleRegistry:
    """In-process schedule registry backed by the live store."""

    def __init__(
        self,
        queue: ScheduleQueue,
        *,
        persistence: SchedulePersistence | None = None,
        target_policy: TargetPolicy | None = None,
    ) -> None:
        self.queue = queue
        self.persistence = persistence
        self.target_policy = target_policy or TargetPolicy()
        self._schedules: dict[str, ScanSchedule] = {}
        if self.persistence is not None:
            for schedule in self.persistence.load_scan_schedules():
                self._schedules[schedule.schedule_id] = schedule

    def _check_target(self, value: str) -> str:
        try:
            return self.target_policy.check(value)
        except TargetPolicyError as error:
            raise ReconError(str(error)) from error

    def _authorization_id(self, scope: Scope) -> str | None:
        return self.queue._scope_authorizations.get(scope.scope_id)

    def _verify_scope(
        self, scope: Scope, target: Target, profile_id: str, now: datetime
    ) -> str | None:
        scope.require_target(target, profile_id, now)
        requires_authorization = profile_requires_authorization(profile_id)
        if requires_authorization and scope.environment != "isolated_lab":
            raise AuthorizationError("Authorization denied", 403)
        if scope.environment != "isolated_lab":
            return None
        authorization_id = self._authorization_id(scope)
        if self.queue.authorization_registry is None or authorization_id is None:
            raise AuthorizationError("Authorization denied", 403)
        try:
            self.queue.authorization_registry.authorize(
                authorization_id,
                owner_id=scope.owner_id,
                target=target.value,
                profile_id=profile_id,
            )
        except AuthorizationVerificationError as error:
            raise AuthorizationError("Authorization denied", 403) from error
        return authorization_id

    def create(
        self,
        *,
        owner_id: str,
        scope_id: str,
        target: str,
        profile_id: str,
        interval_seconds: int,
        now: datetime | None = None,
    ) -> ScanSchedule:
        current = _utc(now or datetime.now(timezone.utc))
        scope = self.queue._scopes.get(scope_id)
        if scope is None or scope.owner_id != owner_id:
            raise AuthorizationError("Authorization denied", 403)
        normalized = self._check_target(target)
        target_value = Target(normalized, "domain")
        authorization_id = self._verify_scope(
            scope, target_value, profile_id, current
        )
        schedule = ScanSchedule(
            schedule_id=str(uuid4()),
            owner_id=owner_id,
            scope_id=scope_id,
            target=normalized,
            profile_id=profile_id,
            interval_seconds=interval_seconds,
            enabled=True,
            next_run_at=current + timedelta(seconds=interval_seconds),
            created_at=current,
            authorization_id=authorization_id,
        )
        self._schedules[schedule.schedule_id] = schedule
        self._persist(schedule)
        return schedule

    def list(self, owner_id: str) -> list[ScanSchedule]:
        return sorted(
            (
                schedule
                for schedule in self._schedules.values()
                if schedule.owner_id == owner_id
            ),
            key=lambda schedule: (schedule.next_run_at, schedule.schedule_id),
        )

    def get(self, schedule_id: str) -> ScanSchedule | None:
        return self._schedules.get(schedule_id)

    def disable(self, schedule_id: str, owner_id: str) -> ScanSchedule:
        schedule = self._schedules.get(schedule_id)
        if schedule is None or schedule.owner_id != owner_id:
            raise AuthorizationError("Authorization denied", 403)
        schedule = replace(schedule, enabled=False)
        self._schedules[schedule_id] = schedule
        self._persist(schedule)
        return schedule

    def run_due(self, now: datetime | None = None) -> list[dict[str, object]]:
        current = _utc(now or datetime.now(timezone.utc))
        results: list[dict[str, object]] = []
        for schedule in tuple(self._schedules.values()):
            if not schedule.enabled or schedule.next_run_at > current:
                continue
            results.append(self._run_one(schedule, current))
        return results

    def run_now(self, schedule_id: str, owner_id: str) -> dict[str, object]:
        schedule = self._schedules.get(schedule_id)
        if schedule is None or schedule.owner_id != owner_id:
            raise AuthorizationError("Authorization denied", 403)
        if not schedule.enabled:
            raise ReconError("schedule is disabled")
        return self._run_one(schedule, datetime.now(timezone.utc))

    def _run_one(
        self, schedule: ScanSchedule, current: datetime
    ) -> dict[str, object]:
        scope = self.queue._scopes.get(schedule.scope_id)
        if scope is None or scope.owner_id != schedule.owner_id:
            return self._fail(schedule, "scope is no longer available", current)
        try:
            self._check_target(schedule.target)
            target = Target(schedule.target, "domain")
            self._verify_scope(scope, target, schedule.profile_id, current)
            job = self.queue.enqueue(
                scope,
                target,
                schedule.profile_id,
                idempotency_key=(
                    f"schedule:{schedule.schedule_id}:"
                    f"{schedule.next_run_at.isoformat()}"
                ),
            )
        except AuthorizationError as error:
            updated = replace(
                schedule,
                enabled=False,
                last_run_at=current,
                last_state="blocked",
                last_error=str(error),
            )
            self._schedules[schedule.schedule_id] = updated
            self._persist(updated)
            return {"scheduleId": schedule.schedule_id, "state": "blocked"}
        except ReconError as error:
            message = str(error)
            # Queue pressure is transient; authorization and scope failures are
            # permanent until an operator intervenes.
            transient = "queue is full" in message or "cooling down" in message
            updated = replace(
                schedule,
                enabled=schedule.enabled if transient else False,
                next_run_at=(
                    current + timedelta(seconds=RETRY_DELAY_SECONDS)
                    if transient
                    else schedule.next_run_at
                ),
                last_run_at=current,
                last_state="deferred" if transient else "blocked",
                last_error=message,
            )
            self._schedules[schedule.schedule_id] = updated
            self._persist(updated)
            return {
                "scheduleId": schedule.schedule_id,
                "state": updated.last_state,
            }
        scan_id = str(getattr(job, "scan_id", ""))
        updated = replace(
            schedule,
            next_run_at=current + timedelta(seconds=schedule.interval_seconds),
            last_run_at=current,
            last_scan_id=scan_id,
            last_state="queued",
            last_error=None,
            runs=schedule.runs + 1,
        )
        self._schedules[schedule.schedule_id] = updated
        self._persist(updated)
        return {
            "scheduleId": schedule.schedule_id,
            "state": "queued",
            "scanId": scan_id,
        }

    def _fail(
        self, schedule: ScanSchedule, message: str, current: datetime
    ) -> dict[str, object]:
        updated = replace(
            schedule,
            enabled=False,
            last_run_at=current,
            last_state="blocked",
            last_error=message,
        )
        self._schedules[schedule.schedule_id] = updated
        self._persist(updated)
        return {"scheduleId": schedule.schedule_id, "state": "blocked"}

    def _persist(self, schedule: ScanSchedule) -> None:
        if self.persistence is not None:
            self.persistence.save_scan_schedule(schedule)
