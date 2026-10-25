# Changelog

All notable changes to ZeroTrace are documented here. The project follows
[Semantic Versioning](https://semver.org/). The first public release is planned
as a self-hosted `0.1.0`; hosted SaaS is out of scope for this release.

## Unreleased — self-hosted hardening

### Added

- PostgreSQL live-engine store with pooled connections and dedicated `live_*`
  tables; SQLite remains the zero-dependency demo fallback.
- Migrations `0007_live_runtime`, `0008_identity_hardening`, and
  `0009_scan_schedules`, with reversible down migrations and
  disposable-database tests.
- TOTP MFA, optional OIDC, one-time password reset, session inventory and
  revocation, database-backed lockout, and auth audit events.
- Production configuration validation that fails closed on unsafe defaults.
- Caddy TLS/security-header reverse proxy, per-client edge rate limits, production
  Compose stack, non-root BFF and engine images, healthchecks, resource limits,
  and a deployment runbook.
- Scan queue depth, per-target cooldown, server-side target policy, runtime
  scanner version gates, and bounded scheduled scans with fail-closed
  revalidation.
- Fernet-encrypted, checksum-verified backups with PostgreSQL/SQLite restore,
  off-host copy, retention pruning, and a destructive restore drill.
- Dependency-free metrics, JSON logs, request IDs, trace propagation,
  Prometheus rules, Alertmanager config, a Grafana dashboard, SLOs, and an
  operations runbook.
- Guard response block/redact policy, model allowlist, strict upstream origin
  checks, key rotation, a loopback-only proxy runner, a production sidecar, an
  authenticated BFF `POST /api/v1/guard/chat` route, and a deterministic
  evaluation corpus.
- Runtime retention pruning for operational rows.
- Apache-2.0 license, NOTICE, CI, CodeQL, dependency audit, SBOM generation,
  container image SBOMs, branch-protection ruleset template, and a signed-release
  workflow.

### Changed

- The live engine uses PostgreSQL when `DATABASE_URL` is set.
- The BFF production image uses Python 3.13 and Gunicorn.
- Guard remains inspect-only by default; the optional upstream gateway is
  explicit configuration, not an implicit model call.
- Dependency pins moved to `cryptography>=50,<51`, Flask 3.1.3, and pytest
  9.0.3 after a dependency audit.

### Security

- MFA secrets are encrypted at rest with Fernet.
- Password-reset tokens are hashed, one-time, and revoke sessions on use.
- Production startup rejects SQLite, demo mode, schema auto-creation, insecure
  cookies, missing MFA keys, and incomplete OIDC configuration.
- Guard rejects non-HTTPS, userinfo, query-string, fragment, non-root-path, and
  non-443 upstream URLs; the provider key stays server-side.
- The engine remains loopback-only and is not published by the production
  Compose stack.

### Known limitations

- SAML, tenant-wide MFA enforcement, egress allowlist enforcement, browser E2E,
  and the full release gate are still open.
- No real VPS or Supabase deployment has been performed.
- The backup and migration drills are local Docker exercises, not production
  recovery proofs.
- OIDC and the Guard upstream gateway have not been exercised against every
  provider.
- Guard's detector is regex-based, English-only, and evaluated against a small
  synthetic corpus. The external detector and Intel model slots are reserved,
  not wired in this release.
- NVIDIA's free API is best-effort capacity and has no production SLA.
