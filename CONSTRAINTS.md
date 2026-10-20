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

## Measured values

- Target laptop resource usage was measured on 2026-10-21; see
  `MEASURED.md` and `tasks/evidence/phase-15.md`.
- Core profile: process peak `60.69 MB`, Guard latency median `0.0119 s`,
  SQLite query median `0.0074 s`.
- Full profile's `9216 MB` target remains unproven because the optional model
  stack was not started.

## Open measurements

- Application test, lint, type-check, and build thresholds are not yet defined.
- PostgreSQL latency/size remains unmeasured on the target laptop.
- These values must be recorded before the related phase is closed.
