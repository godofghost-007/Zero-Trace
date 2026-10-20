# Phase 3 Evidence — Readiness Score

- **Decision:** PASS
- **Commit / diff:** Working tree diff; no commit was requested
- **Environment:** Windows 11, Python 3.13.5, Docker Engine 29.4.3,
  Compose v5.1.3
- **Reviewer:** User approval in this session
- **Date:** 2026-10-17

## Scope

Phase 3 freezes and tests the deterministic readiness-score contract. The
implementation is pure Python and uses only synthetic fixtures. No scanners,
external targets, customer data, production data, or migration changes were
used.

## Required criteria and evidence

| Criterion | Status | Evidence | Notes |
|---|---|---|---|
| Formula and component definitions/version frozen | PASS | `app/readiness.py` defines `readiness-v1`; `docs/SPEC-phase-01-architecture.md` records AEI, VUI, AIET, normalization, bounds, and score bands | VUI uses at most one reviewed contribution per asset |
| Independently calculated synthetic fixtures | PASS | `py -m unittest tests.test_readiness -v` passed 7 tests | Fixtures use only numeric synthetic values |
| Bounds and monotonicity | PASS | `test_vui_normalizes_cvss_and_stays_bounded`, `test_more_adverse_exposure_lowers_score` | Aggregate is clamped to 0–100 |
| Unknown and zero-denominator behavior | PASS | `test_zero_denominator_returns_unknown_without_precise_score` | Unknown components expose coverage and suppress precise score |
| Recovery behavior | PASS | `test_recovery_improves_score` | Lower adverse inputs improve readiness |
| Reproducibility | PASS | `test_calculation_is_reproducible` | Same inputs produce equal immutable results |
| Combined-case discrepancy resolved | PASS | `test_combined_scenario_uses_governing_equation` passed with score 73 | Governing equation takes precedence over source's printed 71 |
| Full repository tests | PASS | `py -m unittest discover -s tests -v` passed all 16 tests | Includes Phase 0–2 regression coverage |
| Python sources compile | PASS | `py -m compileall -q app scripts` completed successfully |  |
| Compose profiles validate | PASS | Core, full, and dev config commands returned `core=0 full=0 dev=0` |  |
| Worktree has no whitespace errors | PASS | `git diff --check` completed successfully |  |

## Implementation notes

- AEI and AIET are bounded ratios expressed as percentages.
- VUI normalizes CVSS 0–10 to 0–1 and averages one reviewed asset
  contribution per total asset count.
- A complete score uses `clamp(100 - (0.40 × AEI + 0.40 × VUI + 0.20 × AIET), 0, 100)`.
- A result with any unknown component has no score or band and reports
  percentage coverage.
- `migrations/0001_foundation.sql` and all existing migrations are unchanged.

## Exceptions and unresolved risks

- The score is deterministic and explainable but is not an empirically
  calibrated probability.
- The Phase 3 gate still requires human review and signoff before Phase 4.

## Decision

- [x] Implementation criteria pass with reproducible evidence.
- [x] Human has reviewed and signed the Phase 3 gate.
- [x] Phase 4 is authorized.

**Human signoff:** User approved Phase 3 signoff and Phase 4 transition in this
session on 2026-10-17.
