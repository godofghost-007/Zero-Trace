# ADR-004: Recon Safety Controls — Rate Limiting, Retry, DNS Gate, Concurrency

## Status
Accepted

## Date
2026-10-17

## Context

Phase 6 (Recon MVP) implements authorized scan scopes, fixed scanner profiles,
normalized observations, and lifecycle states. The Phase 0–7 completion
hardening work identified `P6-SAFETY` as in_progress: "Enforce Recon
rate/concurrency, retry, DNS-gate, and inventory-delta controls."

Review of `app/recon.py` revealed two issues:

1. **Rate limiter placed after run creation**: In `ReconEngine.create_run`,
   the `ReconRateLimiter.acquire()` was called after the run was already
   created in the repository. If rate limiting failed, the run was left in
   `RUNNING` state forever — an orphaned run with no completion path.

2. **No retry logic for transient failures**: The engine ran each adapter
   exactly once. Transient failures (network blips, temporary scanner issues)
   immediately marked the run as FAILED with no retry opportunity.

## Decision

Fix both issues in `app/recon.py`:

1. **Rate limiter before run creation**: Move
   `self.rate_limiter.acquire()` to before the repository `create_run` call,
   so a rejected request never leaves orphaned RUNNING state. Rate limiting
   is now the first enforcement check after scope/profile/target validation.

2. **Configurable retry logic**: Add `max_retries` (default 0) and
   `retry_delay_seconds` (default 0.1) parameters to `ReconEngine.__init__`.
   Transient adapter exceptions are retried up to `max_retries` times with the
   configured delay. `ReconTimeoutError` and `ReconCancelledError` remain
   non-retryable and produce `TIMED_OUT` / `CANCELLED` states respectively.
   When all retries are exhausted, the run is marked `FAILED`.

3. **Concurrency failure returns FAILED run**: When
   `max_concurrent_runs` is reached, the run is marked `FAILED` with a
   "recon concurrency limit exceeded" warning rather than raising an
   unhandled exception.

## Alternatives Considered

### Keep rate limiter after run creation, mark run as FAILED on rejection
Would leave a FAILED run in the repository for rejected requests, polluting
the run history with runs that never executed. Rejected — checking before
creation is cleaner.

### Retry on all exceptions including timeouts and cancellations
Timeouts and cancellations are terminal states by definition; retrying them
would mask real problems. Rejected — only transient `Exception` subclasses are
retried.

### Unbounded retries
Could cause a run to hang indefinitely on a persistently failing adapter.
Rejected — `max_retries` is bounded with a default of 0 (no retries unless
explicitly configured).

## Consequences

- Rate limit rejections no longer leave orphaned RUNNING runs.
- Transient adapter failures can be automatically retried when `max_retries > 0`.
- Timeout and cancellation remain explicit, non-retryable terminal states.
- Concurrency limit exceeded returns a FAILED run with a clear warning.
- 4 new safety tests pass; full suite is 145 tests, all green.
- No new dependencies; no network access; no external targets.
- P6-LAB (real scanner execution against authorized isolated lab) remains
  blocked pending separate human authorization.