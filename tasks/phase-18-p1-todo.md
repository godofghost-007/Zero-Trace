# Phase 18 P0 closure and P1 hardening tracker

Plan: `tasks/phase-18-p1-plan.md`
Baseline: `4e5f982` (last pushed); current work is uncommitted on `feature/phase-17-production-hardening`.

## Phase A - Release path and CI

- [ ] A1 Fix frontend CI pnpm setup; seven jobs green on `4e5f982`; new `Secret scan` job pending
- [ ] A2 Validate CodeQL/release workflows; lowercase GHCR paths
- [x] A3 CI checks for observability configs and image SBOM artifacts
- [ ] A4 Merge feature PR; apply ruleset; signed release
- [ ] A5 Phase 18 evidence template bound to commit/image digests

## Phase B - Production startup and secrets

- [x] B1 Engine production fail-closed startup
- [x] B2 Engine URL environment-variable consistency
- [x] B3 Engine/BFF startup tests
- [x] B4 `*_FILE` secret support and deployment docs
- [x] B5 CI/staged-diff secret scan (`Secret scan` CI job)

## Phase C - Identity

- [x] C1 Browser MFA code prompt
- [x] C2 Frontend `mfa_required` / `mfa_verified` handling
- [x] C3 Mocked OIDC callback tests
- [x] C4 Verified-email linking and HTTPS issuer checks
- [x] C5 Idle timeout and tenant-wide MFA policy
- [ ] C6 Live OIDC/MFA evidence

## Phase D - Guard egress lockdown

- [x] D1 Negative egress canary test
- [ ] D2 Separate BFF/Guard namespaces or process-level egress control
- [ ] D3 Egress-proxy/host-firewall deployment reference
- [ ] D4 Negative test evidence (tests exist; host/container canary pending)

## Phase E - Browser E2E and accessibility

- [x] E1 Playwright and deterministic fixture
- [x] E2 Login/scope/synthetic scan/Guard/failure specs (multi-profile documented as out of scope)
- [ ] E3 axe checks pass; zoom/reflow evidence still pending
- [x] E4 Chromium/Firefox/WebKit CI job added
- [x] E5 Cross-browser evidence passes locally and in CI `40395925263` (24/24)

## Phase F - Backup, observability, acceptance

- [x] F1 Fake-rclone off-host copy test
- [ ] F2 Scheduled backup and production restore drill
- [ ] F3 Alertmanager receiver and on-call document
- [ ] F4 Queue/backup/scrape alerts and dashboard panels
- [x] F5 Observability config checks in CI
- [ ] F6 Phase 18 acceptance steps 1-10

## Phase G - P1 migrations and intel

- [x] G1 BFF operational migration and down migration (`0010_bff_operational`)
- [x] G2 Migrations-only BFF boot test
- [x] G3 NVD dedupe, truncation state, per-record digest
- [x] G4 NVD checkpoints and rate-limit/retry handling
- [x] G5 CPE version ranges and matching corpus (`0011_intel_cpe_ranges`)
- [x] G6 EPSS/KEV/NVD freshness in status and UI

## Phase H - P1 Guard, privacy, sandbox

- [x] H1 Guard evaluation `--mode live` implemented (deterministic evidence regenerated; live provider evidence pending)
- [x] H2 External detector configuration/adapter boundary
- [x] H3 Admin user export and erasure
- [x] H4 Privacy notice/DPA and BFF retention coverage
- [x] H5 Scanner environment allowlist and sandbox reference
- [ ] H6 Host-level per-scan sandbox/network isolation evidence (reference documented; host evidence pending)

## Local verification (2026-10-27)

- Root: `290 passed, 4 skipped`
- BFF: `74 passed` with `ZEROTRACE_TEST_DATABASE_URL`
- Guard/detector/live-eval/backup/secret-scan: `47 passed`
- Migrations and rollback: `8 passed`; rollback drill recorded in `tasks/evidence/migration-rollback.json`
- Frontend `pnpm check` and `pnpm build`: pass
- Deterministic Guard evidence: `f1=0.9756`, precision `0.9524`, recall `1.0`, FPR `0.05`

## External evidence

- [ ] Domain/DNS access
- [ ] Host choice and access
- [ ] IdP tenant/client/MFA user
- [ ] GitHub admin access
- [ ] Model provider key/base URL/model
- [ ] Off-host backup target
- [ ] Alert receiver and on-call owner
- [ ] Named human reviewer/date
