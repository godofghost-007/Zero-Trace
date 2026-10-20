# Phase 5 Evidence — Event and Persistence Reliability

- **Decision:** PASS
- **Commit / diff:** Working tree diff; no commit was requested
- **Environment:** Windows 11, Python 3.13.5, Docker Engine 29.4.3,
  Compose v5.1.3, Python 3.13.5
- **Reviewer:** Human review required
- **Date:** 2026-10-17

## Scope

Phase 5 implements the event envelope and delivery state model aligned with
the existing PostgreSQL outbox and processed-event migrations. Tests use
synthetic data and a deterministic in-memory repository. No external targets,
customer data, production data, Redis service, or real credentials were used.

## Required criteria and evidence

| Criterion | Status | Evidence | Notes |
|---|---|---|---|
| Event envelope and schema version | PASS | `test_event_envelope_is_serializable_and_versioned` passed | `EventEnvelope` emits the versioned camelCase contract |
| Payload validation and sensitive-data boundary | PASS | `test_event_rejects_sensitive_payload_fields` and `test_event_rejects_unknown_event_type_and_oversized_payload` passed | Rejects secret-like fields, unknown event types, non-JSON values, and payloads over 64 KiB |
| Commit-before-publish | PASS | `test_append_commits_before_publisher_is_called` passed | Publisher observes a durable pending record before success is marked published |
| Idempotent consumers | PASS | `test_duplicate_consumer_event_is_a_no_op` passed | Duplicate `(consumer, event_id)` processing does not rerun the handler |
| Failure is not silent success | PASS | `test_failed_consumer_handler_is_not_marked_processed` passed | Handler failure leaves the event retryable |
| Retry and backoff | PASS | `test_failed_publish_retries_with_bounded_backoff_then_dead_letters` and `test_retry_backoff_has_a_configured_upper_bound` passed | Exponential delay is capped by configured maximum |
| Dead-letter behavior | PASS | `test_failed_publish_retries_with_bounded_backoff_then_dead_letters` passed | Exhausted attempts become `dead_letter` with a reason |
| Reconciliation | PASS | `test_reconcile_returns_due_and_stale_records` passed | Due pending/failed and stale processing records are surfaced |
| Existing migration contract | PASS | `py -m unittest tests.test_migrations -v` passed both tests | `0001_foundation.sql` and `0002_event_reliability.sql` remain unchanged |
| Full repository tests | PASS | `py -m unittest discover -s tests -v` passed all 36 tests | Includes Phase 0–4 regression coverage |
| Python sources compile | PASS | `py -m compileall -q app scripts` completed successfully |  |
| Compose profiles validate | PASS | Core, full, and dev config returned `core=0 full=0 dev=0` |  |
| Diff has no whitespace errors | PASS | `git diff --check` completed successfully |  |

## Implementation notes

- [app/events.py](../../app/events.py) contains the contract and deterministic
  outbox test repository.
- The implementation preserves the existing PostgreSQL schema states:
  `pending`, `processing`, `published`, `failed`, and `dead_letter`.
- Event payloads are bounded and reject API keys, passwords, tokens, raw
  prompts/responses, and scanner secrets.
- The repository intentionally does not claim PostgreSQL transaction or Redis
  Streams integration from in-memory tests.

## Exceptions and unresolved risks

- PostgreSQL-backed repository integration and Redis Streams publication are
  not yet wired; those require a service integration slice and failure
  testing.
- Consumer side effects must remain idempotent at their owning boundary;
  recording `processed_events` alone cannot make an inherently non-idempotent
  external side effect safe.
- A stale `processing` record is surfaced for reconciliation; reclaim policy
  and operator metrics remain follow-up work.

## Decision

- [x] Phase 5 implementation criteria have reproducible evidence.
- [x] Human has reviewed and signed the Phase 5 gate.
- [x] Phase 6 is authorized.

**Human signoff:** User approved Phase 5 and acknowledged the documented
PostgreSQL/Redis integration limitations on 2026-10-17.
