# ADR-006: Three-Trace Integrated Architecture — Recon → Intel → Guard → Readiness

## Status
Accepted

## Date
2026-10-17

## Context

ZeroTrace is a three-module cyber-defense platform: Recon (attack surface
discovery), Intel (vulnerability intelligence and prioritization), and Guard
(LLM security middleware). The wiki Phase 12 specification requires proving
that these three traces work together through a unified Operational Readiness
Score.

The existing `IntegratedReadinessState` in `app/integration.py` already
provided the data model for combining Recon, Intel, and Guard state into a
single readiness calculation. However, there was no end-to-end test proving
the full pipeline works without breaking.

## Decision

Create a comprehensive end-to-end integration test
(`tests/test_three_engine_integration.py`) that exercises the complete
Recon → Intel → Guard → Readiness pipeline using only synthetic fixtures
(no real scanners, no external network, no public targets). The test covers:

1. **Recon** — Discovers assets and services using a synthetic adapter
   (simulating nmap/subfinder without executing real scanner binaries)
2. **Intel** — Matches discovered services to CVEs using `correlate_service()`
   and `correlate_scope()`, prioritizes findings using `PrioritizationV2`
   (`intel-priority-v2` with business criticality), and correctly separates
   confirmed findings from uncertain matches
3. **Guard** — Accepts valid LLM requests, blocks jailbreak/prompt injection
   attempts, emits `attack_blocked` events, and enforces API key auth +
   rate limiting + upstream allowlisting
4. **Readiness** — Combines Recon (AEI), Intel (VUI), and Guard (AIET)
   data into a single `readiness-v1` score through `IntegratedReadinessState`

Additionally, `app/events.py` was updated to add `"guard_request"` to the
`EVENT_TYPES` allowlist, and `app/integration.py` was updated to handle
`PrioritizationInput` tuples (from `intel-priority-v2`) instead of
`Mapping[str, float]` (from `intel-priority-v1`).

## Alternatives Considered

### Integration test with real scanners
Rejected — would require authorized isolated-lab targets (P6-LAB is blocked
pending separate authorization). Synthetic adapters prove the same logic
without external dependencies.

### Integration test with real network feeds
Rejected — would require external network access to NVD/EPSS/KEV. Synthetic
feed data proves the same matching and prioritization logic.

### Modifying integration.py to support both intel-priority-v1 and v2
Chose to update integration.py to only support v2's `PrioritizationInput`
tuple format, since v1 is deprecated in favor of v2. This keeps the code
simple and avoids maintaining two code paths.

## Consequences

- The full three-trace pipeline (Recon → Intel → Guard → Readiness) is
  proven end-to-end with synthetic fixtures
- Uncertain matches from Intel correctly do not become confirmed findings
- Stale Intel facts correctly do not confirm findings
- Correlation output is deterministic (same input, same output)
- Readiness score decreases with asset exposure, vulnerability matches, and
  AI attacks; increases after remediation
- Remediation proposals are generated, validated, queued, and approved
  through the full Phase 10 lifecycle
- 5 new tests pass; full suite is 177 tests, all green
- No new dependencies; no network access; no external targets