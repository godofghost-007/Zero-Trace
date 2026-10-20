from datetime import datetime, timedelta, timezone
import unittest
from uuid import uuid4

from app.events import (
    EventEnvelope,
    EventState,
    InMemoryOutbox,
    InvalidEventError,
)


def event(**overrides: object) -> EventEnvelope:
    values = {
        "event_id": str(uuid4()),
        "event_type": "asset_created",
        "schema_version": 1,
        "entity_type": "asset",
        "entity_id": "asset_demo_1",
        "correlation_id": str(uuid4()),
        "producer": "test-fixture",
        "payload": {"asset_kind": "synthetic"},
    }
    values.update(overrides)
    return EventEnvelope(**values)


class EventContractTests(unittest.TestCase):
    def test_event_envelope_is_serializable_and_versioned(self) -> None:
        envelope = event()

        serialized = envelope.to_dict()

        self.assertEqual(serialized["schemaVersion"], 1)
        self.assertEqual(serialized["eventType"], "asset_created")
        self.assertEqual(serialized["payload"], {"asset_kind": "synthetic"})

    def test_event_rejects_sensitive_payload_fields(self) -> None:
        with self.assertRaises(InvalidEventError):
            event(payload={"api_key": "not-a-real-key"})

        with self.assertRaises(InvalidEventError):
            event(payload={"nested": {"raw_prompt": "synthetic text"}})

    def test_event_rejects_unknown_event_type_and_oversized_payload(self) -> None:
        with self.assertRaises(InvalidEventError):
            event(event_type="arbitrary_command")

        with self.assertRaises(InvalidEventError):
            event(payload={"facts": "x" * 70_000})


class OutboxReliabilityTests(unittest.TestCase):
    def test_append_commits_before_publisher_is_called(self) -> None:
        outbox = InMemoryOutbox()
        observed_states: list[EventState] = []
        envelope = event()

        outbox.append_and_publish(
            envelope,
            lambda event_id: observed_states.append(outbox.state(event_id)),
        )

        self.assertEqual(observed_states, [EventState.PENDING])
        self.assertEqual(outbox.state(envelope.event_id), EventState.PUBLISHED)

    def test_failed_publish_retries_with_bounded_backoff_then_dead_letters(self) -> None:
        outbox = InMemoryOutbox(max_attempts=2, base_retry_seconds=5)
        envelope = event()

        outbox.append(envelope)
        first = outbox.publish(
            envelope.event_id,
            lambda _: (_ for _ in ()).throw(RuntimeError("down")),
        )
        second = outbox.publish(
            envelope.event_id,
            lambda _: (_ for _ in ()).throw(RuntimeError("down")),
            now=first.next_attempt_at,
        )

        self.assertEqual(first.state, EventState.FAILED)
        self.assertEqual(first.next_attempt_at - first.updated_at, timedelta(seconds=5))
        self.assertEqual(second.state, EventState.DEAD_LETTER)
        self.assertEqual(second.dead_letter_reason, "publisher failure: RuntimeError")

    def test_retry_backoff_has_a_configured_upper_bound(self) -> None:
        outbox = InMemoryOutbox(
            max_attempts=4,
            base_retry_seconds=5,
            max_retry_seconds=6,
        )
        envelope = event()
        outbox.append(envelope)

        first = outbox.publish(
            envelope.event_id,
            lambda _: (_ for _ in ()).throw(RuntimeError("down")),
        )
        second = outbox.publish(
            envelope.event_id,
            lambda _: (_ for _ in ()).throw(RuntimeError("down")),
            now=first.next_attempt_at,
        )

        self.assertEqual(second.next_attempt_at - second.updated_at, timedelta(seconds=6))

    def test_duplicate_consumer_event_is_a_no_op(self) -> None:
        outbox = InMemoryOutbox()
        envelope = event()
        handled: list[str] = []

        outbox.append(envelope)
        first = outbox.process_once("readiness-worker", envelope, lambda _: handled.append("done"))
        second = outbox.process_once("readiness-worker", envelope, lambda _: handled.append("duplicate"))

        self.assertTrue(first)
        self.assertFalse(second)
        self.assertEqual(handled, ["done"])

    def test_failed_consumer_handler_is_not_marked_processed(self) -> None:
        outbox = InMemoryOutbox()
        envelope = event()

        outbox.append(envelope)
        with self.assertRaisesRegex(RuntimeError, "handler failed"):
            outbox.process_once(
                "readiness-worker",
                envelope,
                lambda _: (_ for _ in ()).throw(RuntimeError("handler failed")),
            )

        self.assertTrue(
            outbox.process_once("readiness-worker", envelope, lambda _: None)
        )

    def test_reconcile_returns_due_and_stale_records(self) -> None:
        now = datetime(2026, 10, 17, tzinfo=timezone.utc)
        outbox = InMemoryOutbox()
        due = event()
        stale = event()
        outbox.append(due, now=now - timedelta(minutes=5))
        outbox.append(stale, now=now - timedelta(minutes=10))
        outbox.mark_processing(stale.event_id, now=now - timedelta(minutes=10))

        due_ids, stale_ids = outbox.reconcile(now=now, processing_timeout=timedelta(minutes=5))

        self.assertIn(due.event_id, due_ids)
        self.assertIn(stale.event_id, stale_ids)
