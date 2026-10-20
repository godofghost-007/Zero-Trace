# Phase 14 Evidence — Integration and End-to-End Validation

## Decision

Phase 14 is **implemented and reproducible** as a synthetic end-to-end
harness covering Recon → Intel → Guard → Readiness → remediation proposal →
verification. Duplicate, retry, restart, upstream-outage, partial-failure, and
tamper scenarios are exercised without a real scanner, external target, feed,
or model call.

The machine-readable run is
[phase-14-e2e.json](phase-14-e2e.json).

## Environment

- Windows 11, Python 3.13.5
- Synthetic Recon adapter and synthetic Guard transport
- SQLite temporary store for restart persistence
- No network access during the harness

## Date

2026-10-21

## Required criteria and evidence

| Criterion | Status | Evidence |
|---|---|---|
| Recon → Intel → Guard → readiness → proposal → verification | PASS | `python -m scripts.phase14_e2e`; Recon completed with one asset/service, exact-CPE finding, Guard 200/400, readiness score `27.6` / band `Critical`, proposal validation `[]`, approved |
| Duplicate scan is idempotent | PASS | Second request with the same key reused the run; adapter calls `1` |
| Bounded retry recovers a transient failure | PASS | Flaky adapter failed once, retry completed; adapter calls `2` |
| State survives restart | PASS | New `LiveStore` instance loaded `1` persisted scope |
| Guard upstream outage is explicit | PASS | Synthetic timeout returned HTTP `502` with the error envelope |
| Partial Recon failure is not empty success | PASS | TLS timeout produced state `partial` and warning `tls:timeout` |
| Proposal tampering is rejected | PASS | Changed fix content with the old digest produced `proposal digest does not match its content` |
| Unavailable optional input is degraded, not zero | PASS | Missing Intel input produced score `null`, coverage `66.666667`, unknown component `VUI` |
| Event retry/dead-letter and duplicate-consumer behavior | PASS | `tests/test_events.py` |
| Persisted scan/restart behavior | PASS | `tests/test_live_engine_persistence.py` |
| Focused Phase 14 test | PASS | `frontend/.venv/Scripts/python.exe -m pytest -q tests/test_phase14_e2e.py tests/test_remediation.py` — 21 passed |
| Full Python suite | PASS | `frontend/.venv/Scripts/python.exe -m pytest -q` — 204 passed |
| BFF suite | PASS | `frontend/.venv/Scripts/python.exe -m pytest -q frontend/backend/tests` — 13 passed |
| Frontend checks | PASS | `pnpm exec tsc --noEmit`, `pnpm test` (6 passed), `pnpm build` |
| Compose profiles | PASS | default, `core`, `full`, and `dev` configs all exit 0 |

## Verification commands

```powershell
frontend\.venv\Scripts\python.exe -m scripts.phase14_e2e
frontend\.venv\Scripts\python.exe -m pytest -q tests\test_phase14_e2e.py tests\test_remediation.py
```

## Safety boundaries

- No real scanner, public target, external feed, or model call.
- No remediation execution; proposals are generated, validated, queued, and
  approved by an explicit admin action only.
- The proposal validator now recomputes the SHA-256 digest over canonical
  content, so in-place content changes are rejected.
- No secrets are stored in proposal environment facts.

## Human signoff

**Human signoff:** Pending operator review of this Phase 14 evidence record.
Implementation was authorized on 2026-10-21.
