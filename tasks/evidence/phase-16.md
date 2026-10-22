# Phase 16 — Gap-Closure Evidence

Date: 2026-10-22
Status: **implemented, locally exercised; operator signoff pending**

This phase closes the five gaps recorded after Phase 15:

1. production-shaped login/RBAC (or multi-tenant isolation);
2. a locally exercised PostgreSQL path;
3. a real `nmap`/`subfinder` isolated-lab run;
4. scheduled NVD/EPSS/KEV ingestion; and
5. tested backup/restore or rollback.

The demo remains loopback-only, bounded, and proposal-only. No exploitation,
brute force, external public-target scanning, or automatic remediation was
added.

## 1. Login, sessions, and RBAC

Implemented:

- Opaque random session cookie `zt_session`; only a SHA-256 digest is stored.
- Per-session CSRF token required on every mutating API request.
- `HttpOnly`, `SameSite=Lax`, configurable `Secure` cookie flag.
- Ordered roles `viewer < operator < admin`, checked in one central guard.
- Origin checks on login and mutating requests.
- Login rate limiting (5 failed attempts per address/email key per 300 s).
- Session expiry (8 h default), last-seen tracking, logout revocation, and
  admin-triggered revocation.
- Bootstrap/CLI account management:
  `create-user`, `list-users`, `revoke-user`, `enable-user`,
  `set-password`, and local-only `demo-credentials`.
- React login page and auth gate; the existing dashboard design is preserved.
- `AUTH_REQUIRED` defaults to `true`. Tests explicitly disable it only for
  legacy fixtures that do not exercise authentication.

Manual check (`frontend/temp_login_check.py`, removed afterward):

```text
session_before 401
login 200 admin
state 200
mutation_without_csrf 403 csrf_failed
mutation_with_csrf 200 2
logout 200
session_after 401
```

Browser check: the login page rendered, the login request returned 200, and
the dashboard rendered after sign-in with `AUTHENTICATED LOCAL SESSION` and a
visible `Sign out` control.

BFF suite: `24 passed`. Evidence:
[tasks/evidence/phase-16-auth.json](phase-16-auth.json).

Remaining limits: this is local account authentication, not SSO/SCIM/MFA.
Tenant identifiers are carried in sessions, but data tables are not row-level
partitioned per tenant. The generated local credential file is demo-only.

## 2. Locally exercised PostgreSQL path

The disposable-database smoke test creates a unique database, runs login and
all three demo steps, verifies PostgreSQL readiness, audit-chain validity,
assets, matches, and summary, then drops the database.

The host `127.0.0.1:5432` path was intermittent while Docker Desktop performed
long checkpoints on this laptop. The successful proof therefore ran the same
script in a `python:3.13-slim` container attached to the Compose network:

```powershell
docker run --rm --network zerotrace_default `
  -v "E:\zerotrace-demo:/workspace" -w /workspace python:3.13-slim `
  sh -c "pip install --disable-pip-version-check -q --no-cache-dir -e . -r frontend/requirements.txt && python -u -m scripts.postgres_smoke --url postgresql://zerotrace:zerotrace-dev-only@postgres:5432/zerotrace"
```

Result: `ok: true`, `database: postgresql`, stage `3`, readiness `78.0`,
audit valid, 6 events, ready 200, 1 asset, 1 match, summary 200. Evidence:
[tasks/evidence/phase-16-postgres-smoke.json](phase-16-postgres-smoke.json).

A schema collision was found during this work: the root application owns a
PostgreSQL table named `event_outbox`, while the BFF used the same name with a
different schema. The BFF table is now `demo_event_outbox`; a one-time,
column-checked copy migrates old SQLite demo databases without touching the
root application's table.

## 3. Real isolated-lab scanner run

The lab Compose stack publishes only to loopback:

- `lab-web` on `127.0.0.1:8080`;
- `lab-web-alt` on `127.0.0.1:8081`;
- `lab-tls` on `127.0.0.1:8443`.

`lab-tls` previously served plain HTTP on the TLS port. It now generates a
short-lived self-signed certificate at container start and serves HTTPS. This
is a lab-only certificate; the engine keeps certificate verification enabled by
default and only the lab run sets `ZEROTRACE_TLS_VERIFY=false`. Unverified
metadata is reported as `status: "unverified"` rather than `valid`.

Hostnames use the public `nip.io` wildcard, so no hosts-file edit or elevated
privileges were needed. The scope was explicit, time-bounded, and limited to
the two lab hostnames. The scope uses the `synthetic` engine label because
`isolated_lab` requires a public DNS TXT challenge; the adapters still executed
the real binaries against the Docker-lab addresses.

Commands used:

```powershell
docker compose -f compose.lab.yaml up -d

$env:PATH = "$env:LOCALAPPDATA\ZeroTrace\bin;C:\Program Files (x86)\Nmap;$env:PATH"
$env:ZEROTRACE_TLS_PORT = "8443"
$env:ZEROTRACE_TLS_VERIFY = "false"
$env:ZEROTRACE_NMAP_PORTS = "8080,8081,8443"
python -m scripts.live_engine

python -m scripts.lab_scan --output tasks\evidence\phase-16-lab-scan.json
```

Result (`tasks/evidence/phase-16-lab-scan.json`):

| Profile | Target | State | Observed |
|---|---|---|---|
| `service_inventory_v1` | `lab-tls.127.0.0.1.nip.io` | completed | open TCP 8080, 8081, 8443 |
| `tls_metadata_v1` | `lab-tls.127.0.0.1.nip.io` | completed | CN `lab-tls.zerotrace.local`, self-signed, `unverified`, expires 2026-10-24 |
| `passive_subdomain_v1` | `lab.zerotrace.local` | completed | no passive records returned; no assets invented |

The Nmap service labels were the scanner's own table output (`http-proxy`,
`blackice-icecap`, `https-alt`). Tools installed locally: Nmap `7.80`,
Subfinder `v2.17.0`.

## 4. Scheduled NVD/EPSS/KEV ingestion

The same `ingest_source()` path is used by the HTTP endpoint and the scheduler.
Intervals default to NVD 6 h, EPSS 12 h, KEV 24 h; the initial delay and
intervals are configurable within bounds. Schedule status is persisted in
SQLite and exposed at `GET /api/v1/intel/schedule`; manual runs use
`POST /api/v1/intel/schedule/run?source=...` and execute off the event loop.

The EPSS path was also corrected to follow the API's `total` across 10,000-row
pages. Without this, the default API response would have silently imported only
100 of 394,415 records.

Real runs against the live engine:

| Source | Duration | Result |
|---|---:|---|
| KEV | 6.26 s | completed, 1,754 records |
| EPSS | 38.39 s | completed, 394,415 records across the full paged feed |
| NVD | bounded first page | 5 facts, 0 quarantined, `fresh` |

NVD's full live sync was not executed end to end; its scheduled wiring and
pagination are covered by tests, and one real first-page request proved the
endpoint and parser. This is recorded as a remaining exception rather than
claimed as a full NVD run.

Evidence:
[phase-16-intel-kev.json](phase-16-intel-kev.json),
[phase-16-intel-epss.json](phase-16-intel-epss.json), and
[phase-16-intel-nvd.json](phase-16-intel-nvd.json).

## 5. Backup and restore

SQLite and PostgreSQL paths were exercised with SHA-256 manifests.

SQLite:

- online backup of `frontend/instance/zerotrace.db` and the Guard audit DB;
- SHA-256 `d6f6a9d60b18fb5046aa2f6f367b481d5aa2c2bd5639f21595f32d36a40d0558`
  for the main DB;
- restore replaced the live DB and created a pre-restore copy;
- a probe table created after backup was absent after restore.

PostgreSQL:

- `pg_dump` from the Compose container for `zerotrace_bff`;
- SHA-256 `32bf483aa0ae9d12db7a958819ffb5bc31b37155496ae43f1ead0945a43099d3`;
- stage changed from `3` to `1`, then `pg_restore` restored stage `3`;
- pre-restore copy retained.

Evidence: [phase-16-backup.json](phase-16-backup.json).

## 6. Verification

| Check | Result |
|---|---|
| Root Python suite | `210 passed`, 2 warnings |
| BFF suite | `24 passed` |
| Frontend type check | passed |
| Frontend tests | 6 passed |
| Frontend production build | passed (`453.22 kB` JS, `135.63 kB` CSS) |
| Compose base/core/full/dev/lab config | all valid |
| PostgreSQL smoke | passed in Compose-network container |
| Real lab Nmap/TLS/Subfinder run | completed |
| Real KEV/EPSS ingestion | completed |
| SQLite and PostgreSQL restore | passed |

## 7. Remaining gaps and exceptions

- Full live NVD sync (all pages) was not run end to end; only a bounded
  first-page request and synthetic pagination tests exist.
- There is no enterprise identity provider, SSO, SCIM, or MFA.
- Tenant identifiers do not enforce row-level tenant data isolation.
- Docker Desktop's host-port PostgreSQL path was intermittent during checkpoints;
  the container-network smoke is the recorded proof.
- Backup files are local and unencrypted; no offsite copy or retention policy is
  implemented.
- The full 9 GB model profile and Ollama integration remain unproven.
- The local demo credential file must be deleted after first sign-in.

## 8. Human signoff

Phase 16 evidence is ready for operator review. No production deployment,
public-target scanning, or automatic remediation is claimed.
