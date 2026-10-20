# Phase 2 Evidence — Skeleton and Core Domain

## Scope

Phase 2 establishes the smallest runnable application foundation:
configuration validation, explicit errors, stable logging, health endpoints,
and a PostgreSQL foundation migration. Recon, Intel, Guard, authentication,
event consumers, scoring, dashboards, and production deployment remain out of
scope.

## Gate results

| Gate | Result | Evidence |
|---|---|---|
| App starts with a health response | PASS | `py -m app` returned HTTP 200 from `/health` with `{"status":"healthy","checks":{}}`. |
| Invalid configuration fails clearly | PASS | Foundation tests verify missing `ZEROTRACE_ENV` and `DATABASE_URL` raise `ConfigurationError`; settings representation redacts the database URL. |
| Disposable migrations apply idempotently | PASS | `py scripts/run_migrations.py` completed twice against the Compose PostgreSQL service; the database contains `0001_foundation` and `0002_event_reliability`. |
| Event reliability contract is represented | PASS | `0002_event_reliability.sql` adds `processed_events`, `dead_letter_reason`, status/attempt/schema-version/published-state checks, and the pending-event index. |
| Foundation tests pass | PASS | `py -m unittest discover -s tests -v` passed all 7 tests. |
| Python sources compile | PASS | `py -m compileall -q app scripts` completed successfully. |
| Compose profiles validate | PASS | `docker compose --profile core config --quiet`, `full`, and `dev` all completed successfully. |
| Worktree has no whitespace errors | PASS | `git diff --check` completed successfully. |

## Runtime notes

- PostgreSQL is bound to `127.0.0.1:5432` for local migration execution and is
  not exposed on external interfaces.
- Migration history is forward-only: the original `0001_foundation` migration
  remains immutable, and reliability additions are applied by
  `0002_event_reliability`.
- `/ready` currently reports HTTP 503 with PostgreSQL `unknown`. The health
  primitive and degraded response are intentional; wiring a live dependency
  probe is a follow-up foundation increment.
- The Compose password is development-only placeholder data and must not be
  reused outside local development.

## Exit decision

**Phase 2 implementation gates: PASS.**

Human signoff is still required before Phase 3 begins. No feature module work
may start before that signoff.
