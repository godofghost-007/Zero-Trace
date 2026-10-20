# Phase 6 Evidence — Recon MVP

- **Decision:** READY FOR HUMAN SIGNOFF for implementation and synthetic
  operational contract; live-lab execution remains separately blocked
- **Commit / diff:** Working tree diff; no commit was requested
- **Environment:** Windows 11, Python 3.13.5, Docker Engine 29.4.3,
  Compose v5.1.3, Python 3.13.5
- **Reviewer:** Human review required
- **Date:** 2026-10-17

## Scope

Phase 6 implements the approved `recon-boundary` contract with fixed
Subfinder, Nmap, TLS, and read-only S3 adapter boundaries. Scope and profile
validation occurs before adapter execution. Tests use synthetic data and fake
runners/connectors only. No external target, customer data, production data,
real credential, or live lab target was scanned.

Remediation remains outside Recon: a later phase may generate a
schema-validated Python proposal for user review, but this implementation does
not execute remediation.

## Required criteria and evidence

| Criterion | Status | Evidence | Notes |
|---|---|---|---|
| Approved scope and profile enforcement | PASS | `test_expired_scope_is_rejected_before_adapter_execution` and `test_target_outside_scope_and_unknown_profile_are_rejected` passed | Expired, out-of-scope, and unknown profiles fail before adapter calls |
| Fixed safe scanner profiles | PASS | `test_subfinder_uses_fixed_arguments_and_keeps_malformed_records_visible` and Nmap adapter test passed | Caller supplies profile ID only; adapter owns argument arrays |
| No shell interpolation/unrestricted flags | PASS | Reviewed `SubprocessRunner` and fixed adapter arguments; no `shell=True`, `os.system`, `eval`, upload, or delete paths found | Real process execution remains isolated-lab-only |
| Subprocess timeout and output bounds | PASS | `SubprocessRunner` enforces argument validation, timeout, process-group setup, output cap, and non-zero exit failure | No live process was launched during tests |
| Cancellation and partial/failure visibility | PASS | `test_timeout_and_cancellation_are_explicit_states`, malformed Subfinder, and failed adapter tests passed | States remain distinct from completed |
| Nmap parsing and zero-port semantics | PASS | `test_nmap_parses_only_open_services_and_reports_zero_ports` passed | Closed ports are omitted; empty findings warn “may be filtered” |
| TLS metadata boundary | PASS | `test_tls_adapter_preserves_certificate_metadata` passed | Uses Python `ssl.create_default_context` in the real connector; fake connector in tests |
| S3 safety boundary | PASS | `test_read_only_s3_adapter_accepts_statuses_but_has_no_write_interface` passed | Public/read/list/denied/unknown/transient statuses only; no write/delete methods |
| Result persistence before event | PASS | `test_successful_run_normalizes_results_and_publishes_after_commit` passed | Publisher observes committed results |
| Idempotency | PASS | Duplicate and changed-request idempotency tests passed | Same key replays; changed request is rejected |
| Rate limiter checked before run creation | PASS | `tests.test_recon_safety.RateLimiterPlacementTests.test_rate_limit_failure_does_not_leave_orphaned_run` | Rate limit rejection leaves no orphaned RUNNING run |
| Concurrency limit exceeded marks FAILED | PASS | `tests.test_recon_safety.ConcurrencyLimitTests.test_concurrency_limit_exceeded_marks_failed` | Returns FAILED run with “recon concurrency limit exceeded” warning |
| Transient failures retried | PASS | `tests.test_recon_safety.RetryLogicTests.test_transient_failures_are_retried_before_marking_failed` | Configurable `max_retries` with `retry_delay_seconds` backoff |
| Exhausted retries mark FAILED | PASS | `tests.test_recon_safety.RetryLogicTests.test_exhausted_retries_mark_run_failed` | All retries exhausted → FAILED, not silent success |
| Full repository tests | PASS | `py -m unittest discover -s tests -v` — 145 tests passed | Includes Phase 0–6 regression coverage, Recon safety controls, API/persistence, authorization, and integration coverage |
| Python sources compile | PASS | `py -m compileall -q app scripts` completed successfully | |
| Compose profiles validate | PASS | Core, full, and dev config returned `core=0 full=0 dev=0` | |
| Diff has no whitespace errors | PASS | `git diff --check` completed successfully | |

## Implementation notes

- [app/recon.py](../../app/recon.py) contains scope/profile contracts,
  normalized findings, lifecycle orchestration, fixed scanner arguments,
  bounded subprocess execution, strict JSON/XML parsing, TLS metadata, and
  read-only S3 status handling. Safety controls include rate limiting before
  run creation, bounded concurrency, configurable retry for transient failures,
  DNS gating before active profiles, and inventory-delta computation.
- [tests/test_recon.py](../../tests/test_recon.py) contains synthetic contract,
  negative, parsing, lifecycle, idempotency, and ordering tests.
- [tests/test_recon_safety.py](../../tests/test_recon_safety.py) contains safety
  control tests: rate limiter placement, concurrency limit, retry logic.
- [app/recon_pg.py](../../app/recon_pg.py) persists canonical assets, services,
  observations, run state, and the event outbox using parameterized SQL in one
  transaction.
- [migrations/0003_recon.sql](../../migrations/0003_recon.sql) defines the
  forward-only Recon schema and constraints.
- [app/recon_api.py](../../app/recon_api.py) exposes role-checked scan
  submission, polling, cancellation, asset listing, and asset detail routes.
- [app/recon_authorization.py](../../app/recon_authorization.py) implements
  exact-domain, single-use DNS TXT challenges, bounded system DNS/allowlisted
  DoH resolvers, and authorization checks before isolated-lab queueing.
- API tests use a synthetic adapter and deterministic queue draining; no
  network target is contacted.
- Python subprocess execution follows the standard-library documented sequence
  argument form with `shell=False`; see
  <https://docs.python.org/3/library/subprocess.html#subprocess.Popen>.
- TLS execution uses the standard library default SSL context and peer
  certificate access; see
  <https://docs.python.org/3/library/ssl.html#ssl.create_default_context>.
- No migration file was changed.
- Recon rate and bounded-concurrency controls, DNS gating before active scans,
  retry handling, and inventory-delta/shadow-IT persistence are covered by
  synthetic and repository persistence contracts.

## Safety control fixes (Phase 6 completion hardening)

1. **Rate limiter moved before run creation**: `ReconRateLimiter.acquire()` is
   now called before `repository.create_run()`, so a rate-limit rejection never
   leaves an orphaned RUNNING run in the repository.
2. **Retry logic added**: `ReconEngine` accepts `max_retries` (default 0) and
   `retry_delay_seconds` (default 0.1). Transient adapter exceptions are
   retried; `ReconTimeoutError` and `ReconCancelledError` remain terminal.
3. **Concurrency limit returns FAILED**: When `max_concurrent_runs` is
   reached, the run is marked `FAILED` with a clear warning instead of
   raising an unhandled exception.

## P6-LAB — Real Scanner Execution (Blocked)

Per the Project Documentation v2.0 (Section 11.1), the designated controlled
lab/test domain is `testsite.zerotrace.local`. P6-LAB requires real Subfinder
and Nmap execution against this explicitly authorized isolated lab target.

**Status: BLOCKED** — pending:
1. Confirmation that `subfinder` and `nmap` binaries are installed on this
   Windows machine (they were not detected during Phase 0 environment
   inspection)
2. Confirmation that `testsite.zerotrace.local` resolves and is an isolated
   lab (not production, public, or customer)
3. Human authorization for real scanner subprocess execution

**Not replaced by synthetic evidence.** All Phase 6 contract tests pass with
synthetic/fake adapters only; no external target was scanned.

## Exceptions and unresolved risks

- P6-LAB real scanner execution remains blocked pending the above items.
- A real scanner execution against an explicitly authorized isolated lab is
  still an operational gate and is not replaced by synthetic evidence.
- The S3 adapter receives an injected read-only checker. A provider-specific
  client, credential lifecycle, and cloud authorization review remain
  separately gated.
- The HTTP factory accepts the existing validated `Principal` abstraction;
  production identity/session wiring remains an integration boundary.
- Automated DNS tests use injected synthetic records; no public DNS provider
  or target was contacted.

## Decision

- [x] Phase 6 implementation criteria have reproducible synthetic evidence.
- [x] Disposable PostgreSQL and Valkey service health are verified.
- [x] Active-profile DNS gating and inventory-delta persistence contracts are
  covered by `tests.test_recon` and `tests.test_recon_persistence`.
- [x] Test-only admin authorization harness is environment-gated, synthetic-
  target-only, short-lived, and covered by `tests.test_test_authorization`.
- [ ] Explicitly authorized isolated-lab scanner execution is verified.
- [x] Human has reviewed and approved the Phase 6 gate with the isolated-lab
      execution exception retained.
- [x] Phase 7 is authorized.

**Human signoff:** Approved with exceptions on 2026-10-17. The approval does
not authorize scanning any target; an explicitly authorized isolated lab is
still required for real scanner execution.
