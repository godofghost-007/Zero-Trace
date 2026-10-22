# ADR-009: Local authentication, scheduled feeds, and verified recovery

## Status

Accepted

## Date

2026-10-22

## Context

The evaluation build had no login, no session model, and no role enforcement.
NVD and EPSS ingestion existed only behind an API endpoint, and there was no
tested backup/restore path. The Phase 15 report also left the PostgreSQL BFF
path, real scanner execution, and a fully exercised scheduled feed as open
gaps.

The demo must stay local, bounded, and evidence-driven. It is not a production
multi-tenant service, and the operator did not authorize public-target scanning,
exploitation, or automatic remediation.

## Decision

### Authentication and roles

Use local, database-backed accounts for the demo:

- The browser receives an opaque random session token in an `HttpOnly`,
  `SameSite=Lax` cookie. Only a SHA-256 digest is stored server-side.
- Every mutating request requires a per-session CSRF token in addition to the
  session cookie.
- Roles are ordered `viewer < operator < admin` and enforced by one central
  before-request guard. Login is rate-limited.
- Authentication is required by default. Tests may explicitly disable it for
  legacy fixtures that do not exercise auth.
- `create-user`, `list-users`, `revoke-user`, and a local-only
  `demo-credentials` bootstrap command are the operator interface.

This is deliberately **not** an enterprise identity provider, SSO, SCIM, or
MFA implementation. Tenant IDs are carried in sessions but do not provide
row-level tenant data isolation.

### Scheduled feeds

Reuse the same `ingest_source()` function for the HTTP endpoint and the
background scheduler. The scheduler:

- accepts only the allowlisted `nvd`, `epss`, and `kev` source names;
- runs one feed at a time in a daemon thread;
- persists last-start, last-completion, result, error, run count, and next-run
  state;
- retries after the configured interval, not in a tight loop; and
- keeps a failed run visible instead of turning it into an empty success.

Default intervals are NVD 6 h, EPSS 12 h, and KEV 24 h. The UI continues to
expose only KEV ingestion; NVD and EPSS remain API/schedule-only.

The EPSS adapter follows the API's `total` across 10,000-record pages. It
rejects an incomplete paged result rather than storing a partial snapshot.

### Recovery

- SQLite backups use the online backup API and write a SHA-256 manifest.
- PostgreSQL backups use `pg_dump` and `pg_restore` inside the Compose
  container.
- Restore verifies the manifest first and keeps a timestamped pre-restore copy.
- The BFF event table is named `demo_event_outbox` so it cannot collide with
  the root application's `event_outbox` table. A one-time, column-checked
  migration copies legacy SQLite rows.

## Alternatives Considered

### Build a full multi-tenant partition

Rejected for this phase. The operator allowed either login/RBAC or tenant
isolation, and login/RBAC closes the immediate gap with less schema risk.
Row-level tenant isolation remains a production task.

### Use an external identity provider

Rejected for the local demo. It would add network dependencies and credentials
that are not available in this environment. The local account boundary is
explicitly documented as a demo substitute.

### Download a single default EPSS page

Rejected. The public API returns 100 records by default; accepting that as a
"successful" sync would silently under-report 394,315 scores.

### Rely on file copies for backup

Rejected. A plain copy of a live SQLite database can be inconsistent.

## Consequences

- The dashboard now starts on a login screen and preserves the existing visual
  design after sign-in.
- The local credential file is gitignored and must be deleted after first use.
- A full live NVD sync and the 9 GB model profile remain unproven.
- PostgreSQL host-port access through Docker Desktop was intermittent on this
  laptop; the recorded smoke test runs on the Compose network.
- Backup artifacts are local and unencrypted; offsite retention and encryption
  remain production work.
