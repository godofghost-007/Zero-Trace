from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import StrEnum
import json
from typing import Callable, Mapping
from uuid import UUID


EVENT_TYPES = {
    "asset_created",
    "asset_updated",
    "vuln_matched",
    "attack_blocked",
    "vuln_patched",
    "scan_status_changed",
    "proposal_status_changed",
    "guard_request",
}
MAX_PAYLOAD_BYTES = 64 * 1024
SENSITIVE_FIELD_NAMES = {
    "api_key",
    "apikey",
    "password",
    "raw_prompt",
    "raw_response",
    "scanner_secret",
    "secret",
    "token",
}


class InvalidEventError(ValueError):
    """Raised when an event violates the cross-module event contract."""


class EventState(StrEnum):
    PENDING = "pending"
    PROCESSING = "processing"
    PUBLISHED = "published"
    FAILED = "failed"
    DEAD_LETTER = "dead_letter"


@dataclass(frozen=True)
class EventEnvelope:
    event_id: str
    event_type: str
    schema_version: int
    entity_type: str
    entity_id: str
    correlation_id: str
    producer: str
    payload: Mapping[str, object]
    scope_id: str | None = None
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        for field_name in (
            "event_id",
            "event_type",
            "entity_type",
            "entity_id",
            "correlation_id",
            "producer",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise InvalidEventError(f"{field_name} is required")
            if len(value) > 255:
                raise InvalidEventError(f"{field_name} is too long")
        try:
            UUID(self.event_id)
            UUID(self.correlation_id)
        except ValueError as error:
            raise InvalidEventError("event and correlation IDs must be UUIDs") from error
        if self.event_type not in EVENT_TYPES:
            raise InvalidEventError("event_type is not allowlisted")
        if not isinstance(self.schema_version, int) or self.schema_version < 1:
            raise InvalidEventError("schema_version must be positive")
        if self.scope_id is not None and (
            not isinstance(self.scope_id, str) or not self.scope_id.strip()
        ):
            raise InvalidEventError("scope_id must be a non-empty string")
        if self.occurred_at.tzinfo is None:
            raise InvalidEventError("occurred_at must include timezone information")
        if not isinstance(self.payload, Mapping):
            raise InvalidEventError("payload must be an object")
        _validate_payload(self.payload)
        try:
            payload_size = len(
                json.dumps(
                    self.payload,
                    separators=(",", ":"),
                    ensure_ascii=True,
                    allow_nan=False,
                )
            )
        except (TypeError, ValueError) as error:
            raise InvalidEventError("payload must be JSON serializable") from error
        if payload_size > MAX_PAYLOAD_BYTES:
            raise InvalidEventError("payload exceeds the maximum size")

    def to_dict(self) -> dict[str, object]:
        return {
            "eventId": self.event_id,
            "eventType": self.event_type,
            "schemaVersion": self.schema_version,
            "entityType": self.entity_type,
            "entityId": self.entity_id,
            "scopeId": self.scope_id,
            "occurredAt": self.occurred_at.isoformat(),
            "correlationId": self.correlation_id,
            "producer": self.producer,
            "payload": dict(self.payload),
        }


@dataclass(frozen=True)
class OutboxRecord:
    event: EventEnvelope
    state: EventState
    attempts: int
    created_at: datetime
    updated_at: datetime
    next_attempt_at: datetime
    published_at: datetime | None = None
    dead_letter_reason: str | None = None


class InMemoryOutbox:
    """Deterministic test repository mirroring the PostgreSQL outbox contract."""

    def __init__(
        self,
        max_attempts: int = 5,
        base_retry_seconds: int = 5,
        max_retry_seconds: int = 300,
    ) -> None:
        if (
            max_attempts < 1
            or base_retry_seconds < 1
            or max_retry_seconds < base_retry_seconds
        ):
            raise ValueError("retry settings must be positive")
        self.max_attempts = max_attempts
        self.base_retry_seconds = base_retry_seconds
        self.max_retry_seconds = max_retry_seconds
        self._records: dict[str, OutboxRecord] = {}
        self._processed: set[tuple[str, str]] = set()

    def append(self, envelope: EventEnvelope, now: datetime | None = None) -> OutboxRecord:
        timestamp = _utc(now)
        existing = self._records.get(envelope.event_id)
        if existing is not None:
            if existing.event != envelope:
                raise InvalidEventError("event_id cannot be reused with a different event")
            return existing
        record = OutboxRecord(
            event=envelope,
            state=EventState.PENDING,
            attempts=0,
            created_at=timestamp,
            updated_at=timestamp,
            next_attempt_at=timestamp,
        )
        self._records[envelope.event_id] = record
        return record

    def append_and_publish(
        self,
        envelope: EventEnvelope,
        publisher: Callable[[str], None],
        now: datetime | None = None,
    ) -> OutboxRecord:
        self.append(envelope, now=now)
        return self.publish(envelope.event_id, publisher, now=now)

    def publish(
        self,
        event_id: str,
        publisher: Callable[[str], None],
        now: datetime | None = None,
    ) -> OutboxRecord:
        record = self._records[event_id]
        timestamp = _utc(now)
        if record.state == EventState.PUBLISHED:
            return record
        if record.state == EventState.DEAD_LETTER:
            return record
        if record.state not in (EventState.PENDING, EventState.FAILED):
            raise RuntimeError("event is not publishable in its current state")
        if timestamp < record.next_attempt_at:
            raise RuntimeError("event retry is not due")
        try:
            publisher(event_id)
        except Exception as error:
            attempts = record.attempts + 1
            is_dead_letter = attempts >= self.max_attempts
            delay = min(
                self.max_retry_seconds,
                self.base_retry_seconds * 2 ** (attempts - 1),
            )
            updated = replace(
                record,
                state=(
                    EventState.DEAD_LETTER
                    if is_dead_letter
                    else EventState.FAILED
                ),
                attempts=attempts,
                updated_at=timestamp,
                next_attempt_at=timestamp + timedelta(seconds=delay),
                dead_letter_reason=(
                    f"publisher failure: {type(error).__name__}"
                    if is_dead_letter
                    else None
                ),
            )
            self._records[event_id] = updated
            return updated
        updated = replace(
            record,
            state=EventState.PUBLISHED,
            attempts=record.attempts + 1,
            updated_at=timestamp,
            published_at=timestamp,
        )
        self._records[event_id] = updated
        return updated

    def process_once(
        self,
        consumer_name: str,
        envelope: EventEnvelope,
        handler: Callable[[EventEnvelope], None],
    ) -> bool:
        key = (consumer_name, envelope.event_id)
        if key in self._processed:
            return False
        handler(envelope)
        self._processed.add(key)
        return True

    def mark_processing(self, event_id: str, now: datetime | None = None) -> OutboxRecord:
        record = self._records[event_id]
        if record.state not in (EventState.PENDING, EventState.FAILED):
            raise RuntimeError("event is not available for processing")
        updated = replace(record, state=EventState.PROCESSING, updated_at=_utc(now))
        self._records[event_id] = updated
        return updated

    def reconcile(
        self, now: datetime, processing_timeout: timedelta
    ) -> tuple[list[str], list[str]]:
        timestamp = _utc(now)
        due = [
            event_id
            for event_id, record in self._records.items()
            if record.state in (EventState.PENDING, EventState.FAILED)
            and record.next_attempt_at <= timestamp
        ]
        stale = [
            event_id
            for event_id, record in self._records.items()
            if record.state == EventState.PROCESSING
            and record.updated_at + processing_timeout <= timestamp
        ]
        return due, stale

    def state(self, event_id: str) -> EventState:
        return self._records[event_id].state


def _validate_payload(value: object) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise InvalidEventError("payload keys must be strings")
            normalized_key = key.lower().replace("-", "_")
            if normalized_key in SENSITIVE_FIELD_NAMES:
                raise InvalidEventError(f"payload field {key} is prohibited")
            _validate_payload(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            _validate_payload(nested)
    elif not isinstance(value, (str, int, float, bool)) and value is not None:
        raise InvalidEventError("payload contains a non-JSON value")


def _utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if value.tzinfo is None:
        raise ValueError("timestamps must include timezone information")
    return value.astimezone(timezone.utc)
