# Phase 18 release gate

This gate is intentionally a stop sign, not a checklist that can be waved
through. A release is not ready because the code compiles; it is ready when the
evidence below is true for the exact commit and the exact deployment target.

## Current status

**NOT PASSED.** The repository has strong local evidence, but no real VPS or
Supabase deployment has been performed, no signed release exists, and no human
signoff is recorded.

## Required evidence

| Gate item | Required evidence | Current status |
|---|---|---|
| Root tests | `pytest -q` green, including disposable PostgreSQL | Pass (265 passed) |
| BFF tests | `pytest backend/tests -q` green | Pass (61 passed) |
| Frontend | typecheck, unit tests, production build | Pass (6 tests) |
| Migration rollback | apply and rollback against PostgreSQL | Pass locally (`tasks/evidence/migration-rollback.json`) |
| Encrypted restore | destructive restore into a clean database | Pass locally (`tasks/evidence/postgres-backup-restore.json`) |
| Dependency audit | `pip-audit` for engine and BFF | Pass locally |
| SBOM | Python and image SBOMs | Python pass; image SBOMs configured in CI, not run |
| Guard evaluation | labeled corpus with recorded mistakes; BFF route tests; loopback sidecar health | Pass locally (`tasks/evidence/guard-evaluation.json`, `guard-proxy-container.json`) |
| Runtime security smoke | headers, auth, Guard route auth, metrics token, loopback URL | Pass locally (`tasks/evidence/security-smoke.json`) |
| Edge rate limit | Caddy custom image and 2-request limit test | Pass locally (`tasks/evidence/observability-config.json`) |
| Load smoke | bounded error rate and p95 | Pass locally (`tasks/evidence/load-test.json`) |
| Container builds | BFF, engine, and Caddy images | Pass locally; CI configured, not run. Guard reuses the engine image. |
| CI and CodeQL | required checks green in GitHub | Pending: no git remote |
| Branch protection | ruleset applied to `main` | Pending |
| Signed release | cosign signature and provenance | Pending |
| Real deployment | VPS + Supabase + TLS + Caddy | Pending |
| OIDC | live identity-provider login and MFA | Pending |
| Egress lockdown | BFF cannot reach the model provider directly | Pending |
| Browser E2E | login, scope, multi-profile scan, Guard, failure states | Pending |
| Human signoff | named reviewer and date | Pending |

## Deployment acceptance

Run these against the real deployment, not localhost:

1. `GET /api/v1/health` and `GET /api/v1/ready` return 200 over TLS.
2. The engine port is not reachable from the public interface.
3. Login works with MFA; a viewer cannot perform operator actions.
4. A Normal scan against an authorized isolated-lab target completes.
5. A High/Deep scan without DNS TXT is rejected; with a fresh challenge it is
   accepted only in `isolated_lab`.
6. A scheduled scan revalidates and runs; an expired scope disables it.
7. A Guard request is blocked or redacted according to policy, and the provider
   key is absent from the browser and BFF logs.
8. Metrics require the bearer token; Grafana and Prometheus are not public.
9. A fresh encrypted backup is created, verified, and restored into a clean
   database within the documented RTO.
10. The previous image digest can be redeployed and the migration rollback or
    backup restore completes.

## Stop conditions

Do not release if any of these are true:

- Any required check is skipped, failing, or only tested locally.
- The production startup validation is disabled.
- The engine is published publicly or uses a non-loopback URL.
- The provider key is present in the BFF, browser, `.env.production`,
  repository, or logs.
- A reserved detector or Intel model slot is described as active without an
  adapter and evaluation evidence.
- A High/Deep scan bypasses DNS TXT authorization.
- A scheduled scan runs after its scope expires.
- The only backup is on the same host as the database.
- The release image is a mutable tag without a digest.
- The release notes imply production readiness beyond this evidence.

## Signoff

Record the reviewer, commit, image digests, deployment target, date, and any
accepted exceptions. An exception must name the risk owner and the expiry date.
