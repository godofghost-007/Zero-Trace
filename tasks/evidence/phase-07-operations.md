# Phase 7 Operations — Intel Feed Operations Evidence

- **Decision:** P7-OPERATIONS complete; feed pagination, incremental sync,
  cache, quarantine, last-known-good, merge, and paginated reads implemented
- **Environment:** Windows 11, Python 3.13
- **Date:** 2026-10-17

## Scope

P7-OPERATIONS adds operational hardening to Phase 7 Intel: NVD pagination with
incremental checkpoints, conditional cache metadata, bounded 429/backoff
handling, malformed-record quarantine, last-known-good snapshots, merged
EPSS/KEV facts, and real paginated finding queries with scope isolation. All
feed access remains fixed-endpoint, synthetic-only in tests.

## Implemented Components

| Component | File | Responsibility |
|---|---|---|
| `sync_nvd()` | `app/intel_feeds.py` | NVD pagination with `startIndex`, `max_pages`, checkpoint, `last_known_good` fallback |
| `RetryingFeedTransport` | `app/intel_feeds.py` | Bounded retry (max 3 attempts), 429/5xx backoff, `Retry-After` honoring, `max_retry_seconds=60` cap |
| `NvdFeed().parse()` | `app/intel_feeds.py` | Strict NVD record parsing, malformed record quarantine via `_quarantine_identifier` |
| `merge_intel_signals()` | `app/intel_feeds.py` | Merges NVD facts with EPSS/KEV records, preserves unknown values |
| `EpssFeed` / `KevFeed` | `app/intel_feeds.py` | EPSS and KEV parsers with numeric/boolean bounds validation |
| `PostgresIntelRepository.list_findings()` | `app/intel_pg.py` | Scope-isolated paginated reads (JOIN `recon_scopes` by owner, page_size ≤ 100) |
| `PostgresIntelRepository.list_uncertain_matches()` | `app/intel_pg.py` | Scope-isolated paginated uncertain match reads |

## Safety Boundaries

- Fixed allowlisted endpoints only (NVD, EPSS, CISA KEV) — no arbitrary URLs
- Redirects disabled (`_NoRedirectHandler`)
- Response body capped at 8MB
- Malformed records quarantined, never silently dropped
- Last-known-good preserved on feed failure (degraded state, not silent success)
- Missing CVSS/EPSS/KEV values remain explicit, never converted to zero
- Scope isolation on all reads (owner-filtered PostgreSQL queries)
- No external feed access in automated tests — synthetic fixtures only

## Verification

- `tests.test_intel_feeds.IntelFeedTests` — NVD pagination with checkpoint, quarantine, 429 retry, EPSS/KEV bounds, last-known-good preservation
- `tests.test_intel.IntelModelTests` — missingness explicit, priority bounded/monotonic
- `tests.test_intel_persistence.IntelPersistenceTests` — parameterized writes, uncertain match persistence
- `tests.test_intel_api.IntelApiTests` — paginated findings, uncertain matches separate, role-checked routes

## Human Signoff

P7-OPERATIONS verified on 2026-10-17. Intel feed operations are implemented and
tested with synthetic fixtures. Production feed access remains deferred pending
separate operational approval.