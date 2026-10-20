# ADR-001: End-to-end persisted correlation orchestration for Phase 8

## Status
Accepted

## Date
2026-10-17

## Context

Phase 8 (Correlation Completeness) turned normalized Recon services and Intel
vulnerability facts into reviewable findings. The matching engine
(`correlate_service`, `match_service`) and the PostgreSQL persistence layer
(`save_findings`, `save_uncertain_matches`) were already implemented, along
with the `intel_uncertain_matches` table (migration `0006_correlation.sql`)
and the `/api/v1/uncertain-matches` route.

What was missing was the end-to-end orchestration that ties persisted Recon
state through deterministic correlation into confirmed findings and uncertain
matches, stored atomically in PostgreSQL. Two tests exercised the missing
surface:

- `test_intel.py` imported `CorrelationBatch` and called `correlate_scope()`
- `test_intel_persistence.py` called `save_correlation()` on the
  `PostgresIntelRepository`

Both failed because those symbols did not exist.

## Decision

Add three pieces to complete Phase 8 end-to-end correlation orchestration:

1. `CorrelationBatch` — a frozen dataclass holding `findings` and
   `uncertain_matches` as sorted tuples.
2. `correlate_scope(services, facts, *, now, freshness_window)` in
   `app/intel.py` — correlates every service against every fact deterministically,
   returning a `CorrelationBatch` with confirmed findings and uncertain matches
   separated and sorted by `(service_id, cve_id)`.
3. `save_correlation(scope_id, findings, uncertain_matches,
   source_revision="")` in `app/intel_pg.py` — persists confirmed findings to
   `intel_findings` and uncertain matches to `intel_uncertain_matches` in a
   single PostgreSQL transaction (one `commit`), with `ON CONFLICT` upsert
   semantics matching the existing `save_findings`/`save_uncertain_matches`
   contracts.

## Alternatives Considered

### Reuse `save_findings` and `save_uncertain_matches` separately
Calling the two existing methods from an orchestration layer would require two
transactions, breaking the atomicity guarantee that findings and uncertainty
are committed together. Rejected.

### Add a new orchestration service module
A separate `app/correlation.py` module would duplicate the existing
`app/intel.py` boundary and require new imports across the API and runtime
layers. Rejected in favor of keeping correlation logic co-located with the
Intel model where `correlate_service` already lives.

## Consequences

- Confirmed findings and uncertain matches are persisted atomically; a partial
  failure leaves neither behind.
- Correlation output is deterministic for the same facts and services.
- Uncertain matches remain distinct from confirmed findings and are reviewable
  separately through `/api/v1/uncertain-matches`.
- Missing CVSS, EPSS, and KEV values remain explicit; no uncertain match
  silently becomes a confirmed finding.
- Two previously failing tests now pass; full suite is 109 tests, all green.
- No new dependencies, migrations, or external access introduced.