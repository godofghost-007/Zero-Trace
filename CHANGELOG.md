# Changelog

All notable changes to ZeroTrace are documented here. The project follows
[Semantic Versioning](https://semver.org/). The first public release is planned
as a self-hosted `0.1.0`; hosted SaaS is out of scope for this release.

## Unreleased — self-hosted hardening

### Added

- PostgreSQL live-engine store with pooled connections and dedicated `live_*`
  tables; SQLite remains the zero-dependency demo fallback.
- Migrations `0007_live_runtime` and `0008_identity_hardening`, with reversible
  down migrations and disposable-database tests.
- TOTP MFA, optional OIDC, one-time password reset, session inventory and
  revocation, database-backed lockout, and auth audit events.
- Production configuration validation that fails closed on unsafe defaults.
- Caddy TLS/security-header reverse proxy, production Compose stack, non-root
  BFF and engine images, healthchecks, resource limits, and a deployment runbook.
- Scan queue depth and per-target cooldown controls.
- Apache-2.0 license, NOTICE, CI, and CodeQL workflows.

### Changed

- The live engine uses PostgreSQL when `DATABASE_URL` is set.
- The BFF production image uses Python 3.13 and Gunicorn.
- Guard remains inspect-only by default; the optional upstream gateway is
  explicit configuration, not an implicit model call.

### Security

- MFA secrets are encrypted at rest with Fernet.
- Password-reset tokens are hashed, one-time, and revoke sessions on use.
- Production startup rejects SQLite, demo mode, schema auto-creation, insecure
  cookies, missing MFA keys, and incomplete OIDC configuration.

### Known limitations

- SAML, tenant-wide MFA enforcement, encrypted off-host backup, observability,
  scanner runtime version gating, and the full release gate are still open.
- OIDC and the Guard upstream gateway have not been exercised against every
  provider.
- NVIDIA's free API is best-effort capacity and has no production SLA.
