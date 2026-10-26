# Phase 18 P0 closure and P1 hardening tracker

Plan: `tasks/phase-18-p1-plan.md`
Baseline: `830e9c0`

## Phase A - Release path and CI

- [ ] A1 Fix frontend CI pnpm setup; all seven CI jobs green
- [ ] A2 Validate CodeQL/release workflows; lowercase GHCR paths
- [x] A3 CI checks for observability configs and image SBOM artifacts
- [ ] A4 Merge feature PR; apply ruleset; signed release
- [ ] A5 Phase 18 evidence template bound to commit/image digests

## Phase B - Production startup and secrets

- [x] B1 Engine production fail-closed startup
- [x] B2 Engine URL environment-variable consistency
- [x] B3 Engine/BFF startup tests
- [x] B4 `*_FILE` secret support and deployment docs
- [ ] B5 CI/staged-diff secret scan

## Phase C - Identity

- [x] C1 Browser MFA code prompt
- [x] C2 Frontend `mfa_required` / `mfa_verified` handling
- [x] C3 Mocked OIDC callback tests
- [x] C4 Verified-email linking and HTTPS issuer checks
- [ ] C5 Idle timeout and tenant-wide MFA policy
- [ ] C6 Live OIDC/MFA evidence

## Phase D - Guard egress lockdown

- [ ] D1 Negative egress canary test
- [ ] D2 Separate BFF/Guard namespaces or process-level egress control
- [ ] D3 Egress-proxy/host-firewall deployment reference
- [ ] D4 Negative test evidence

## Phase E - Browser E2E and accessibility

- [x] E1 Playwright and deterministic fixture
- [x] E2 Login/scope/synthetic scan/Guard/failure specs (multi-profile documented as out of scope)
- [ ] E3 axe checks pass; zoom/reflow evidence still pending
- [x] E4 Chromium/Firefox/WebKit CI job added
- [ ] E5 Cross-browser evidence passes locally; CI run pending

## Phase F - Backup, observability, acceptance

- [ ] F1 Fake-rclone off-host copy test
- [ ] F2 Scheduled backup and production restore drill
- [ ] F3 Alertmanager receiver and on-call document
- [ ] F4 Queue/backup/scrape alerts and dashboard panels
- [ ] F5 Observability config checks in CI
- [ ] F6 Phase 18 acceptance steps 1-10

## Phase G - P1 migrations and intel

- [ ] G1 BFF operational migration and down migration
- [ ] G2 Migrations-only BFF boot test
- [ ] G3 NVD dedupe, truncation state, per-record digest
- [ ] G4 NVD checkpoints and rate-limit/retry handling
- [ ] G5 CPE version ranges and matching corpus
- [ ] G6 EPSS/KEV freshness in status and UI

## Phase H - P1 Guard, privacy, sandbox

- [ ] H1 Guard evaluation `--mode live`
- [ ] H2 External detector configuration/adapter boundary
- [ ] H3 Admin user export and erasure
- [ ] H4 Privacy notice/DPA and BFF retention coverage
- [ ] H5 Scanner env allowlist and sandbox wrapper
- [ ] H6 Host-level per-scan sandbox reference/evidence

## External evidence

- [ ] Domain/DNS access
- [ ] Host choice and access
- [ ] IdP tenant/client/MFA user
- [ ] GitHub admin access
- [ ] Model provider key/base URL/model
- [ ] Off-host backup target
- [ ] Alert receiver and on-call owner
- [ ] Named human reviewer/date
