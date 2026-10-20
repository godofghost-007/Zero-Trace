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

## Open measurements

- Target laptop resource usage is not yet measured.
- Application test, lint, type-check, and build thresholds are not yet defined.
- These values must be recorded before the related phase is closed.
