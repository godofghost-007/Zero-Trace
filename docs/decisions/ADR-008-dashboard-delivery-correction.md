# ADR-008: Dashboard delivery correction

## Status
Accepted

## Date
2026-10-21

## Context

ADR-007 proposed a standalone `app/dashboard/` server built on Python's
`http.server`, serving vanilla HTML/CSS/JavaScript on port 8766. The committed
repository does not contain `app/dashboard/`, and the entrypoints around it
(`scripts/dashboard_cli.py`, `start_dashboard.py`, `test_dashboard_client.py`,
and `fix_server.py`) imported the missing package. The Phase 13 evidence file
therefore described code and test results that could not be reproduced.

At the same time, the delivered dashboard is a React/Vite single-page
application under `frontend/`. It is served by the Flask BFF, which persists the
connection settings server-side and proxies the live engine. The UI already
covers the operational views required by the phase: Architecture, Database &
Events, Recon, Intel, Guard, Targets & Scope, and Engine Settings.

## Decision

Keep the React dashboard and the Flask BFF as the Phase 13 delivery.
Remove the broken standalone-dashboard entrypoints and the CLI that imported the
missing package. Reconcile the Phase 13 evidence with reproducible checks
against the code that actually exists.

The live console is deliberately narrow:

- The browser talks only to same-origin Flask routes under `/api/v1/*`.
- Flask keeps the engine API key server-side and forwards to a loopback-only
  FastAPI engine.
- Scope and scan creation require an explicit `authorized: true` acknowledgement
  in both Flask and the engine.
- Recon profiles are allowlisted; the default live profile is TLS metadata.
- The UI exposes CISA KEV ingestion only. NVD and EPSS ingestion remain
  API-only.
- The engine persists scopes, scan results, Intel feed snapshots, Guard
  inspection counts, and readiness snapshots in a local SQLite file. Production
  deployments continue to use the PostgreSQL repositories and migrations.

## Alternatives Considered

### Recreate the standalone `http.server` dashboard
Rejected. It would duplicate the React UI, add a second authentication and
static-asset stack, and contradict the delivered design.

### Keep the broken CLI and document it as an exception
Rejected. An entrypoint that cannot import its module is not a usable delivery;
the honest correction is to remove it and record the supersession.

## Consequences

- `app/dashboard/` is not a supported path.
- `scripts/dashboard_cli.py`, `start_dashboard.py`,
  `test_dashboard_client.py`, and `fix_server.py` are removed.
- Phase 13 evidence points to `frontend/` and the BFF/live-engine tests.
- The Phase 13 CLI task is recorded as removed rather than verified.
- The UI remains local-demo software; it is not a production console.
