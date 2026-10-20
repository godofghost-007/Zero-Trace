# Phase 8 Evidence — Correlation Completeness

- **Decision:** Phase 8 implementation complete; end-to-end correlation
  orchestration implemented and verified
- **Environment:** Windows, Python 3.13
- **Date:** 2026-10-17
- **Authorization:** Phase 8 implementation authorized by human approval

## Scope

Phase 8 adds deterministic Recon-to-Intel correlation evidence. Confirmed
findings and uncertain matches are separate result types. This phase performs
no scanning, remediation, model inference, or arbitrary external access.

## Required criteria and evidence

| Criterion | Status | Evidence |
|---|---|---|
| Exact CPE matching | PASS | `tests.test_intel.IntelModelTests.test_matching_requires_exact_evidence_and_rejects_ambiguity` |
| Unique vendor/product/version fallback | PASS | `test_unique_fallback_match_is_confirmed` |
| Ambiguous matches remain reviewable | PASS | `test_ambiguous_match_is_reviewable_uncertain_evidence` |
| Missing service version is not confirmed | PASS | `test_missing_service_version_is_uncertain_not_confirmed` |
| Stale facts are not confirmed | PASS | `test_stale_exact_match_is_uncertain_not_confirmed` |
| Deterministic evidence and source revision | PASS | `CorrelationOutcome` and `UncertainMatch` preserve sorted evidence and source revision |
| PostgreSQL uncertainty persistence | PASS | `tests.test_intel_persistence.test_uncertain_matches_preserve_reason_evidence_and_revision` |
| Scope-isolated paginated reads | PASS | PostgreSQL repository joins `recon_scopes` by owner and bounds page size to 100 |
| Separate uncertainty API | PASS | `tests.test_intel_api.test_uncertain_matches_are_paginated_and_separate_from_findings` |
| Migration idempotency contract | PASS | Ordered migration discovery and idempotent DDL include `0006_correlation` |
| End-to-end correlation orchestration | PASS | `CorrelationBatch` and `correlate_scope()` in `app/intel.py`; `save_correlation()` in `app/intel_pg.py`; `tests.test_intel.test_scope_correlation_is_deterministic_and_separates_results` and `tests.test_intel_persistence.test_correlation_persistence_commits_findings_and_uncertainty_together` |
| Full repository verification | PASS | `py -m unittest discover -s tests -v` — 109 tests passed; compileall, all Compose profiles, and `git diff --check` passed |

## Safety boundaries

- Uncertain matches never enter confirmed `intel_findings`.
- Missing CVSS, EPSS, and KEV values remain explicit in confirmed priority
  inputs.
- API reads require the existing viewer role and owner-filtered PostgreSQL
  queries.
- No public target, arbitrary URL, credential, or scanner execution is used.

## Verification

```powershell
py -m unittest discover -s tests -v
py -m compileall -q app scripts
docker compose --profile core config --quiet
docker compose --profile full config --quiet
docker compose --profile dev config --quiet
git diff --check
```

## Human signoff

**Human signoff:** Approved on 2026-10-17. End-to-end correlation
orchestration from persisted Recon/Intel state through confirmed and uncertain
results is complete. This approval does not authorize live scanning or
automatic remediation.
