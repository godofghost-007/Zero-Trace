import json
from datetime import datetime, timezone
from typing import Any, Callable

from .events import EventEnvelope, EventState, InvalidEventError


class PostgresOutbox:
    """Transactional outbox operations for worker delivery."""

    def __init__(self, connection_factory: Callable[[], Any]) -> None:
        self.connection_factory = connection_factory

    def append(self, event: EventEnvelope) -> None:
        with self.connection_factory() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO event_outbox
                        (event_id, event_type, schema_version, entity_type,
                         entity_id, correlation_id, payload, status)
                    VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, 'pending')
                    ON CONFLICT (event_type, entity_id, correlation_id)
                    DO NOTHING
                    """,
                    (
                        event.event_id,
                        event.event_type,
                        event.schema_version,
                        event.entity_type,
                        event.entity_id,
                        event.correlation_id,
                        json.dumps(event.to_dict()["payload"]),
                    ),
                )
            connection.commit()

    def claim_due(self, *, limit: int = 100) -> list[dict[str, object]]:
        if not 1 <= limit <= 1_000:
            raise ValueError("outbox batch limit is invalid")
        with self.connection_factory() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT event_id, event_type, schema_version, entity_type,
                           entity_id, correlation_id, payload
                    FROM event_outbox
                    WHERE status IN ('pending', 'failed')
                    ORDER BY created_at, event_id
                    LIMIT %s
                    FOR UPDATE SKIP LOCKED
                    """,
                    (limit,),
                )
                rows = cursor.fetchall()
                cursor.execute(
                    """
                    UPDATE event_outbox
                    SET status = 'processing', attempts = attempts + 1
                    WHERE event_id = ANY(%s)
                    """,
                    ([row[0] for row in rows],),
                )
            connection.commit()
        return [
            {
                "event_id": str(row[0]),
                "event_type": row[1],
                "schema_version": row[2],
                "entity_type": row[3],
                "entity_id": row[4],
                "correlation_id": str(row[5]),
                "payload": row[6],
            }
            for row in rows
        ]

    def mark_published(self, event_id: str) -> None:
        self._update_state(event_id, "published")

    def mark_failed(self, event_id: str, reason: str) -> None:
        if not reason or len(reason) > 255:
            raise ValueError("failure reason is invalid")
        with self.connection_factory() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE event_outbox
                    SET status = CASE WHEN attempts >= 5
                                     THEN 'dead_letter' ELSE 'failed' END,
                        dead_letter_reason = CASE WHEN attempts >= 5
                                                  THEN %s ELSE NULL END
                    WHERE event_id = %s
                    """,
                    (reason, event_id),
                )
            connection.commit()

    def claim_processed(self, consumer_name: str, event_id: str) -> bool:
        if not consumer_name or not event_id:
            raise ValueError("consumer and event identifiers are required")
        with self.connection_factory() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO processed_events (consumer_name, event_id)
                    VALUES (%s, %s)
                    ON CONFLICT (consumer_name, event_id) DO NOTHING
                    """,
                    (consumer_name, event_id),
                )
                claimed = cursor.rowcount == 1
            connection.commit()
        return claimed

    def _update_state(self, event_id: str, state: str) -> None:
        if state != EventState.PUBLISHED:
            raise InvalidEventError("unsupported outbox state update")
        with self.connection_factory() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE event_outbox
                    SET status = 'published', published_at = CURRENT_TIMESTAMP
                    WHERE event_id = %s
                    """,
                    (event_id,),
                )
            connection.commit()


class RedisStreamsPublisher:
    """Small adapter around a Redis-compatible client's XADD operation."""

    def __init__(self, client: Any, stream: str = "zerotrace.events") -> None:
        if not stream or len(stream) > 128:
            raise ValueError("stream name is invalid")
        self.client = client
        self.stream = stream

    def publish(self, event: dict[str, object]) -> str:
        payload = json.dumps(event, separators=(",", ":"), ensure_ascii=True)
        if len(payload.encode("utf-8")) > 64 * 1024:
            raise ValueError("event exceeds stream payload limit")
        return str(self.client.xadd(self.stream, {"event": payload}, maxlen=100_000))


class RedisStreamsConsumer:
    """Redis Streams consumer-group boundary with explicit acknowledgement."""

    def __init__(
        self,
        client: Any,
        *,
        stream: str = "zerotrace.events",
        group: str = "zerotrace.workers",
        consumer: str = "worker-1",
    ) -> None:
        if not stream or len(stream) > 128:
            raise ValueError("stream name is invalid")
        if not group or len(group) > 128 or not consumer or len(consumer) > 128:
            raise ValueError("consumer group identity is invalid")
        self.client = client
        self.stream = stream
        self.group = group
        self.consumer = consumer

    def ensure_group(self) -> None:
        self.client.xgroup_create(self.stream, self.group, id="0", mkstream=True)

    def read(self, *, count: int = 100, block_ms: int = 1_000) -> list[dict[str, str]]:
        if not 1 <= count <= 1_000 or not 1 <= block_ms <= 30_000:
            raise ValueError("stream read bounds are invalid")
        batches = self.client.xreadgroup(
            self.group,
            self.consumer,
            {self.stream: ">"},
            count=count,
            block=block_ms,
        )
        return [
            {"message_id": str(message_id), "event": fields["event"]}
            for _, messages in batches
            for message_id, fields in messages
        ]

    def read_pending(self, *, count: int = 100) -> list[dict[str, str]]:
        if not 1 <= count <= 1_000:
            raise ValueError("stream read count is invalid")
        batches = self.client.xreadgroup(
            self.group,
            self.consumer,
            {self.stream: "0"},
            count=count,
            block=1,
        )
        return [
            {"message_id": str(message_id), "event": fields["event"]}
            for _, messages in batches
            for message_id, fields in messages
        ]

    def claim_stale(
        self, *, min_idle_ms: int = 5_000, count: int = 100
    ) -> list[dict[str, str]]:
        if min_idle_ms < 1 or not 1 <= count <= 1_000:
            raise ValueError("pending-message bounds are invalid")
        next_id, messages, _deleted = self.client.xautoclaim(
            self.stream,
            self.group,
            self.consumer,
            min_idle_ms,
            "0-0",
            count=count,
        )
        return [
            {"message_id": str(message_id), "event": fields["event"]}
            for message_id, fields in messages
        ]

    def acknowledge(self, message_id: str) -> int:
        if not message_id:
            raise ValueError("message identifier is required")
        return int(self.client.xack(self.stream, self.group, message_id))


class RedisStreamsWorker:
    def __init__(
        self,
        consumer: RedisStreamsConsumer,
        handler: Callable[[dict[str, str]], None],
    ) -> None:
        self.consumer = consumer
        self.handler = handler

    def recover_pending(self) -> int:
        processed = 0
        messages = self.consumer.read_pending()
        messages.extend(self.consumer.claim_stale())
        seen: set[str] = set()
        for message in messages:
            if message["message_id"] in seen:
                continue
            seen.add(message["message_id"])
            if self._process(message):
                processed += 1
        return processed

    def process_once(self) -> bool:
        messages = self.consumer.read(count=1, block_ms=1)
        return bool(messages) and self._process(messages[0])

    def _process(self, message: dict[str, str]) -> bool:
        try:
            self.handler(message)
        except Exception:
            return False
        self.consumer.acknowledge(message["message_id"])
        return True
