# ZeroTrace Constraints

This file records the initial quality and safety constraints for the project.
Numbers that have not been measured are not treated as evidence.

## Safety

- External scanning is restricted to explicitly authorized scopes.
- Development uses synthetic data or an isolated lab.
- Generated remediation is a reviewed proposal, never automatic production
  execution.
- Secrets and production/customer data are excluded from source, fixtures,
  logs, and hosted AI context unless explicitly approved.

## Reliability

- Failed scanners, feeds, models, and event dependencies must report a visible
  failed or degraded state.
- A failure must not appear as an empty successful result.
- Durable state remains authoritative over transient notifications.

## Quality

- Every phase requires reproducible evidence and human signoff.
- Behavior changes require focused tests before implementation where practical.
- Security-sensitive, schema, event, dependency, deployment, and data-retention
  decisions require explicit approval before implementation.

## Security boundaries

- Authentication is required by default in the BFF. Sessions use opaque random
  tokens stored only as SHA-256 digests; mutating requests require a
  per-session CSRF token.
- Roles are ordered `viewer < operator < admin` and enforced centrally.
- Scheduled feeds reuse the allowlisted endpoints and bounded parsers; the
  scheduler never accepts an arbitrary URL.
- Backups must carry a SHA-256 manifest and be verified before restore; restore
  keeps a visible pre-restore copy.
- The loopback-only engine URL and server-side engine key remain mandatory.

## Measured values

- Target laptop resource usage was measured on 2026-10-21; see
  `MEASURED.md` and `tasks/evidence/phase-15.md`.
- Core profile: process peak `60.69 MB`, Guard latency median `0.0119 s`,
  SQLite query median `0.0074 s`.
- Phase 16: KEV `6.26 s` / `1,754` records; EPSS `38.39 s` / `394,415`
  records; root suite `210 passed`; BFF suite `24 passed`.
- Full profile's `9216 MB` target remains unproven because the optional model
  stack was not started.

## Open measurements

- Application test, lint, type-check, and build thresholds are not yet defined.
- PostgreSQL query latency and storage growth remain unmeasured on the target
  laptop; the disposable path and backup/restore are verified.
- The full live NVD sync and the full 9 GB model profile remain unproven.
- These values must be recorded before the related phase is closed.
