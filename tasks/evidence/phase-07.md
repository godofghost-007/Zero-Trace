# Phase 7 Evidence — Intel MVP

- **Decision:** READY FOR HUMAN SIGNOFF for implementation and disposable
  service operational contract; live scanner execution remains outside this
  phase
- **Environment:** Windows, Python 3.13
- **Reviewer:** Human review required
- **Date:** 2026-10-17

## Scope

Phase 7 normalizes vulnerability intelligence from fixed NVD, FIRST EPSS, and
CISA KEV source contracts, preserves provenance, correlates facts with Recon
services, and exposes role-checked ingestion/status/finding routes. Feed
responses are treated as untrusted input. Automated tests use synthetic
fixtures and an injected transport; no production feed or target was contacted.

## Required criteria and evidence

| Criterion | Status | Evidence |
|---|---|---|
| Versioned vulnerability facts and provenance | PASS | `tests.test_intel` normalization and provenance tests |
| Bounded NVD/EPSS/KEV adapters | PASS | `tests.test_intel_feeds` parser, endpoint allowlist, and body-cap tests |
| Deterministic matching and ambiguity rejection | PASS | Exact CPE and ambiguous fallback tests in `tests.test_intel` |
| Explainable priority formula | PASS | Bounded, monotonic, missing-input, and formula-version assertions |
| PostgreSQL schema and parameterized persistence | PASS | `migrations/0004_intel.sql` and `tests.test_intel_persistence` |
| Role-checked ingestion and findings API | PASS | `tests.test_intel_api` synthetic API tests |
| Full repository tests | PASS | `py -m unittest discover -s tests -v` — 90 tests passed |
| Fixed production feed retrieval | PASS | Bounded retrieval reached fixed NVD, FIRST EPSS, and CISA KEV endpoints: NVD page parsed 2,000 facts with 0 quarantined, EPSS parsed 100 records, KEV parsed 1,748 records |
| Python sources compile | PASS | `py -m compileall -q app scripts` |
| Recon-to-Intel-to-readiness integration contract | PASS | `tests.test_integration` validates deterministic cross-module recomputation |
| Runtime PostgreSQL/Valkey verification | PASS | Disposable PostgreSQL migrations applied twice; Valkey healthcheck and synthetic stream append passed |
| PostgreSQL-backed runtime API composition | PASS | `create_runtime_app` composes Recon and Intel routes; asset and finding reads are owner-filtered, paginated, and sourced from PostgreSQL repositories |
| Diff has no whitespace errors | PASS | `git diff --check` |

## Implementation notes

- [app/intel.py](../../app/intel.py) contains normalized facts, freshness,
  matching, and `intel-priority-v1`.
- [app/intel_feeds.py](../../app/intel_feeds.py) contains fixed allowlisted
  endpoints, bounded transport, redirect rejection, and strict parsers.
- [app/intel_pg.py](../../app/intel_pg.py) and
  [migrations/0004_intel.sql](../../migrations/0004_intel.sql) define
  parameterized fact/finding persistence and ingestion-state structures.
- [app/integration.py](../../app/integration.py) provides the deterministic
  Recon-to-Intel-to-readiness bridge used by the integration contract test.
- [app/intel_api.py](../../app/intel_api.py) exposes operator ingestion and
  viewer status/findings routes with idempotency.

## Exceptions and unresolved risks

- Production NVD, EPSS, and KEV retrieval was intentionally not performed.
- PostgreSQL migration execution and the Valkey service boundary have been
  verified against disposable local containers; application-level worker
  restart/recovery still requires a dedicated runtime exercise.
- The Valkey pending-message crash window has now been exercised with
  `XREADGROUP`, pending replay, `XAUTOCLAIM` support in the worker adapter, and
  `XACK`; the pending count returned to zero.
- Live feed compatibility was verified without logging raw records. The KEV
  parser accepts current `Known`/`Unknown` values and the NVD parser accepts
  documented UTC timestamps without an explicit offset.
- EPSS and KEV records are parsed independently; a production ingestion worker
  must merge source revisions before presenting a complete fact.
- Production identity/session provisioning remains a deployment-boundary
  decision; the runtime API requires an injected principal provider and does
  not invent credentials.

## Decision

- [x] Phase 7 implementation criteria have reproducible synthetic evidence.
- [x] Runtime PostgreSQL and Redis/Valkey criteria are verified against
  disposable services.
- [x] Human has reviewed and approved the Phase 7 gate with deployment identity
      and live-scanner exceptions retained.
- [x] Phase 8 is authorized.

## Entry preparation

- [x] Phase 8 correlation contract drafted in
  [docs/SPEC-phase-08-correlation.md](../../docs/SPEC-phase-08-correlation.md).
- [x] Runtime repository composition and API persistence hooks are covered by
  `tests.test_runtime_persistence_hooks`.
- [x] Human Phase 7 signoff and Phase 8 authorization are recorded.

**Human signoff:** Approved with exceptions on 2026-10-17. Production
identity/session provisioning remains deployment-specific, and no live scanner
execution was authorized by this approval.
