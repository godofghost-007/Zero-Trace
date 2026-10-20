# Phase 5 Runtime — PostgreSQL Outbox + Redis/Valkey Streams Evidence

- **Decision:** P5-RUNTIME complete; PostgreSQL outbox and Redis/Valkey Streams
  runtime contracts implemented in `app/events_pg.py`
- **Environment:** Windows 11, Python 3.13
- **Date:** 2026-10-17

## Scope

P5-RUNTIME wires the durable PostgreSQL transactional outbox with a
Redis/Valkey Streams publisher/consumer boundary, including restart recovery,
retry, duplicate handling, dead-letter transitions, and stale-message
reconciliation. This is the production persistence layer for Phase 5 event
reliability.

## Implemented Components (`app/events_pg.py`)

| Component | Responsibility |
|---|---|
| `PostgresOutbox.append()` | Transactional outbox insert with `ON CONFLICT DO NOTHING` idempotency |
| `PostgresOutbox.claim_due()` | Claims pending/failed events with `FOR UPDATE SKIP LOCKED`, bounded batch |
| `PostgresOutbox.mark_published()` | Marks event as published with timestamp |
| `PostgresOutbox.mark_failed()` | Failed → dead_letter after 5 attempts, stores reason |
| `PostgresOutbox.claim_processed()` | Idempotent consumer claim via `processed_events` table |
| `RedisStreamsPublisher.publish()` | XADD with 64KB payload bound, `maxlen=100_000` stream trimming |
| `RedisStreamsConsumer` | Consumer group with `xreadgroup`, `xautoclaim` (stale claim), `xack` |
| `RedisStreamsWorker` | `recover_pending()` on restart, `process_once()` with ack on success |

## Safety Boundaries

- Failed consumers do not mark messages as processed (at-least-once delivery)
- Dead-letter after 5 failed attempts with reason
- Stale pending messages reclaimed via `xautoclaim` on worker restart
- No silent success: failed or degraded states are visible
- PostgreSQL remains authoritative over transient notifications

## Verification

- `tests.test_events_pg.EventPersistenceTests` — outbox append parameterized and committed, stream consumer group/ack, publisher bounds, worker restart recovery
- `tests.test_events.OutboxReliabilityTests` — commit-before-publish, idempotent consumer, retry/backoff, dead-letter, reconciliation
- `tests.test_runtime_persistence_hooks.RuntimePersistenceHookTests` — runtime composes PostgreSQL repositories, Recon queue calls persistence hook

## Human Signoff

P5-RUNTIME verified on 2026-10-17. PostgreSQL outbox and Redis/Valkey Streams
runtime contracts are implemented and tested with synthetic fixtures. Live
Redis/Valkey integration requires a disposable local service and is
environment-specific.