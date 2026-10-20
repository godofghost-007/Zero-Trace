import unittest
from unittest.mock import MagicMock
from uuid import uuid4

from app.events import EventEnvelope
from app.events_pg import (
    PostgresOutbox,
    RedisStreamsConsumer,
    RedisStreamsPublisher,
    RedisStreamsWorker,
)


class EventPersistenceTests(unittest.TestCase):
    def test_outbox_append_is_parameterized_and_committed(self) -> None:
        connection = MagicMock()
        connection.__enter__.return_value = connection
        repository = PostgresOutbox(lambda: connection)
        event = EventEnvelope(
            str(uuid4()), "asset_created", 1, "asset", "asset-1",
            str(uuid4()), "test", {"asset": "asset-1"},
        )

        repository.append(event)

        connection.commit.assert_called_once()
        statement = connection.cursor.return_value.__enter__.return_value.execute.call_args.args[0]
        self.assertIn("INSERT INTO event_outbox", statement)
        self.assertIn("%s", statement)

    def test_stream_publisher_bounds_payload_and_calls_xadd(self) -> None:
        client = MagicMock()
        client.xadd.return_value = "1-0"
        publisher = RedisStreamsPublisher(client)

        result = publisher.publish({"eventType": "asset_created"})

        self.assertEqual(result, "1-0")
        client.xadd.assert_called_once()

    def test_stream_consumer_creates_group_reads_and_acknowledges(self) -> None:
        client = MagicMock()
        client.xreadgroup.return_value = [
            ("zerotrace.events", [("1-0", {"event": "{\"eventType\":\"asset_created\"}"})])
        ]
        client.xack.return_value = 1
        consumer = RedisStreamsConsumer(client)

        consumer.ensure_group()
        messages = consumer.read()
        acknowledged = consumer.acknowledge("1-0")

        self.assertEqual(messages, [{"message_id": "1-0", "event": "{\"eventType\":\"asset_created\"}"}])
        self.assertEqual(acknowledged, 1)
        client.xgroup_create.assert_called_once()
        client.xack.assert_called_once_with("zerotrace.events", "zerotrace.workers", "1-0")

    def test_worker_recovers_pending_and_does_not_ack_failed_messages(self) -> None:
        client = MagicMock()
        client.xreadgroup.side_effect = [
            [("zerotrace.events", [("1-0", {"event": "pending"})])],
            [("zerotrace.events", [("1-0", {"event": "pending"})])],
        ]
        client.xautoclaim.return_value = ("0-0", [], [])
        client.xack.return_value = 1
        consumer = RedisStreamsConsumer(client)
        calls = 0

        def handler(message: dict[str, str]) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("crash window")

        worker = RedisStreamsWorker(consumer, handler)

        self.assertEqual(worker.recover_pending(), 0)
        self.assertEqual(worker.recover_pending(), 1)
        client.xack.assert_called_once_with("zerotrace.events", "zerotrace.workers", "1-0")
