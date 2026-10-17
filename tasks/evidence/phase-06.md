# Phase 6 Evidence — Recon MVP

- **Decision:** PASS for implementation and operational contract; human signoff pending
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
| Full repository tests | PASS | `py -m unittest discover -s tests -v` — 55 tests passed | Includes Phase 0–5 regression coverage and Recon API/persistence tests |
| Python sources compile | PASS | `py -m compileall -q app scripts` completed successfully | |
| Compose profiles validate | PASS | Core, full, and dev config returned `core=0 full=0 dev=0` | |
| Diff has no whitespace errors | PASS | `git diff --check` completed successfully | |

## Implementation notes

- [app/recon.py](../../app/recon.py) contains scope/profile contracts,
  normalized findings, lifecycle orchestration, fixed scanner arguments,
  bounded subprocess execution, strict JSON/XML parsing, TLS metadata, and
  read-only S3 status handling.
- [tests/test_recon.py](../../tests/test_recon.py) contains synthetic contract,
  negative, parsing, lifecycle, idempotency, and ordering tests.
- [app/recon_pg.py](../../app/recon_pg.py) persists canonical assets, services,
  observations, run state, and the event outbox using parameterized SQL in one
  transaction.
- [migrations/0003_recon.sql](../../migrations/0003_recon.sql) defines the
  forward-only Recon schema and constraints.
- [app/recon_api.py](../../app/recon_api.py) exposes role-checked scan
  submission, polling, cancellation, asset listing, and asset detail routes.
- API tests use a synthetic adapter and deterministic queue draining; no
  network target is contacted.
- Python subprocess execution follows the standard-library documented sequence
  argument form with `shell=False`; see
  <https://docs.python.org/3/library/subprocess.html#subprocess.Popen>.
- TLS execution uses the standard library default SSL context and peer
  certificate access; see
  <https://docs.python.org/3/library/ssl.html#ssl.create_default_context>.
- No migration file was changed.

## Exceptions and unresolved risks

- No real Subfinder/Nmap process or live TLS/S3 target was executed in this
  phase. An explicitly authorized isolated-lab integration run is required
  before operational deployment.
- PostgreSQL schema application against a disposable live database remains an
  environment verification item; repository contract tests use a mocked
  connection.
- The S3 adapter receives an injected read-only checker. A provider-specific
  client, credential lifecycle, and cloud authorization review remain
  separately gated.
- The HTTP factory accepts the existing validated `Principal` abstraction;
  production identity/session wiring remains an integration boundary.

## Decision

- [x] Phase 6 implementation criteria have reproducible evidence.
- [ ] Human has reviewed and signed the Phase 6 gate.
- [ ] Phase 7 is authorized.

**Human signoff:** Pending
