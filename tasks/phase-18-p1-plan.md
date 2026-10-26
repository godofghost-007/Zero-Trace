# Implementation Plan: Phase 18 P0 closure and P1 hardening

## Overview

This plan closes the remaining Phase 18 P0 release-gate work and the P1
production-hardening backlog without weakening any safety boundary. Work is
split into small, independently verifiable slices. External deployment evidence
is separated from code work so that missing credentials never get mistaken for
a passing gate.

**Branch:** `feature/phase-17-production-hardening`
**Baseline:** `830e9c0`
**Tracker:** `tasks/phase-18-p1-todo.md`

## Critical path

1. Fix the red CI frontend job.
2. Get all required checks green on one commit.
3. Open the feature-branch PR so CodeQL runs on the default branch path.
4. Merge to `main`, apply the ruleset, and produce a signed release.
5. Deploy to the chosen target, run the Phase 18 acceptance script, and collect
   evidence bound to the released commit and image digests.
6. Record the named human signoff.

Code work that does not require external credentials can proceed in parallel
with steps 3–5.

## External inputs required

| Input | Needed for | Status |
|---|---|---|
| Domain + DNS access | TLS, OIDC callback, production acceptance | **Blocked** |
| Host choice (VPS / Oracle Always Free / free demo) | Real deployment | **Blocked** |
| IdP tenant, client ID/secret, callback URL, MFA test user | Live OIDC/MFA evidence | **Blocked** |
| GitHub repository admin access | Ruleset, Actions permissions, release | **Blocked** |
| Model provider key/base URL/model | Guard live-provider evaluation | **Blocked** |
| Off-host backup target (S3/R2/B2) + credentials | Backup/restore drill | **Blocked** |
| Alertmanager receiver + on-call owner | Production observability | **Blocked** |
| Named reviewer and date | Phase 18 signoff | **Blocked** |

## Architecture decisions

- Keep the app same-origin for v1: Caddy → BFF + static UI; engine and Guard
  remain private/loopback.
- Keep Guard as the only process that holds the provider key.
- Keep production startup fail-closed. No silent SQLite or demo-default
  fallback when `ZEROTRACE_ENV=production`.
- Use versioned SQL migrations for all BFF operational tables; no
  `create_all()` in production.
- Use Playwright against the built UI served by Flask, not the Vite dev proxy.
- Treat browser E2E, egress proof, backup/restore, and signoff as evidence
  artifacts bound to one commit and one deployment target.

## Task list

### Phase A — Release path and CI

- [ ] A1: Fix the frontend CI pnpm setup and confirm all seven CI jobs green.
- [ ] A2: Add CodeQL/release workflow validation and fix GHCR lowercase paths.
- [ ] A3: Add CI validation for observability configs and image SBOM artifacts.
- [ ] A4: Open/merge the feature PR, apply the ruleset, and tag a signed release.
- [ ] A5: Add a Phase 18 evidence template bound to commit and image digests.

### Phase B — Production startup and secrets

- [ ] B1: Make engine startup fail-closed in production for API key, auth
      secret, and PostgreSQL URL.
- [ ] B2: Fix the `ZEROTRACE_ENGINE_URL` / `ZEROTRACE_ENGINE_BASE_URL` mismatch.
- [ ] B3: Add engine production startup tests and BFF config tests.
- [ ] B4: Add secret-file (`*_FILE`) support and document Docker/KMS/Vault
      secret injection.
- [ ] B5: Add a CI secret scan and a pre-commit/staged-diff secret check.

### Phase C — Identity

- [ ] C1: Add MFA code prompt and OIDC login button to the browser.
- [ ] C2: Handle `mfa_required` / `mfa_verified` in the frontend auth state.
- [ ] C3: Add OIDC callback tests with a mocked provider.
- [ ] C4: Reject unverified OIDC email linking; require HTTPS issuer.
- [ ] C5: Add idle timeout and tenant-wide MFA policy.
- [ ] C6: Add live OIDC/MFA evidence once the IdP is available.

### Phase D — Guard egress lockdown

- [ ] D1: Add a negative egress test that proves the BFF cannot reach a
      non-allowlisted canary.
- [ ] D2: Separate BFF and Guard network namespaces or add a process/UID-level
      egress control.
- [ ] D3: Add an egress-proxy or host-firewall deployment reference.
- [ ] D4: Re-run the negative test and record evidence.

### Phase E — Browser E2E and accessibility

- [ ] E1: Add Playwright and a deterministic BFF+engine fixture.
- [ ] E2: Add login, scope creation, synthetic scan (multi-profile documented as out of scope), Guard, and
      failure-state specs.
- [ ] E3: Add axe-core checks and remove zoom-blocking markup.
- [ ] E4: Add Chromium/Firefox/WebKit projects and a CI job.
- [ ] E5: Add cross-browser evidence.

### Phase F — Backup, observability, acceptance

- [ ] F1: Add a fake-rclone test for off-host copy and checksum verification.
- [ ] F2: Add a scheduled backup service and production restore drill.
- [ ] F3: Add Alertmanager receiver routing and an on-call document.
- [ ] F4: Add queue-lag, backup-age, and scrape-health alerts/dashboard panels.
- [ ] F5: Add observability config checks to CI.
- [ ] F6: Run Phase 18 acceptance steps 1–10 on the real deployment.

### Phase G — P1 migrations and intel

- [ ] G1: Add `0010_bff_operational.sql` and a down migration for all BFF
      operational tables.
- [ ] G2: Add a migrations-only BFF boot test.
- [ ] G3: Dedupe NVD records, mark truncation degraded, and add per-record
      provenance digests.
- [ ] G4: Persist NVD checkpoints and add rate-limit/retry handling.
- [ ] G5: Add CPE version-range matching and a labeled matching-quality corpus.
- [ ] G6: Add EPSS/KEV freshness to the engine status type and UI.

### Phase H — P1 Guard, privacy, sandbox

- [ ] H1: Add `--mode live` to the Guard evaluation harness.
- [ ] H2: Add external detector configuration and a provider-neutral adapter
      boundary without claiming it is active.
- [ ] H3: Add admin-only user export and erasure endpoints.
- [ ] H4: Add privacy notice/DPA template and retention coverage for BFF tables.
- [ ] H5: Add an explicit scanner env allowlist and a sandbox wrapper interface.
- [ ] H6: Add a host-level per-scan sandbox reference and evidence.

## Checkpoints

### Checkpoint A — CI green

- [ ] All seven CI jobs pass on one commit.
- [ ] CodeQL runs on the PR.
- [ ] No secrets in the diff.

### Checkpoint B — Local release candidate

- [ ] Engine and BFF tests pass.
- [ ] Frontend typecheck, tests, and build pass.
- [ ] Browser E2E passes locally.
- [ ] Guard egress negative test passes.
- [ ] Migrations-only BFF boot passes.

### Checkpoint C — Production candidate

- [ ] Signed images and release exist.
- [ ] Ruleset is active.
- [ ] Deployment acceptance steps 1–10 pass.
- [ ] Backup/restore and rollback evidence exists.
- [ ] Phase 18 evidence and human signoff are recorded.

## Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| CI remains red | Blocks CodeQL, merge, release | Fix pnpm first; verify on one SHA |
| External credentials arrive late | Blocks live evidence | Complete local code and evidence templates first |
| Egress proof requires host privileges | Blocks Guard lockdown proof | Provide both Docker/CNI and host-firewall references; test what the target supports |
| OIDC/MFA UI missing | Blocks browser evidence | Implement frontend flow before live IdP test |
| BFF `create_all()` remains | Production schema drift | Migration-only boot test in CI |
| NVD truncation silently passes | Bad intel data | Degraded state + truncation tests |
| Sandbox breaks scanning | False confidence | Keep safe default off; require explicit host decision |
| Solo-maintainer branch protection | Cannot merge | Document admin bypass or use a second reviewer |

## Open questions

- Which host: Oracle Always Free VM, small VPS, or free demo only?
- Which IdP: GitHub, Google, Microsoft Entra, Keycloak, or other?
- Is a custom domain available for TLS and OIDC callback?
- Who is the named human reviewer for Phase 18?
- Which off-host backup target and alert receiver should be used?
- Is per-scan network isolation a hard requirement for v1, or a documented
  host-level control?
