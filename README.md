# ZeroTrace

ZeroTrace is a local-first cyber-defense demo with three cooperating modules:

- **Trace Recon** — bounded attack-surface inventory and TLS metadata reads.
- **Trace Intel** — normalized vulnerability facts, CISA KEV/EPSS signals,
  service correlation, and explainable prioritization.
- **Trace Guard** — prompt-injection and PII inspection for LLM traffic, with
  no upstream model call.

The operator-facing dashboard is a React single-page application served by a
Flask backend-for-frontend (BFF). The BFF talks to the real Python modules
directly for the fixture pages and, optionally, to a loopback-only FastAPI
live engine for the Targets & Scope console.

> **Status:** local demo and evaluation build. This is not a production
> scanner, vulnerability service, LLM proxy, or multi-tenant console. See
> [Safety boundaries](#safety-boundaries) and
> [docs/decisions](docs/decisions) for the limits recorded with the build.

## What works

| Area | Delivered |
|---|---|
| Dashboard | React/Vite pages for Architecture, Database & Events, Recon, Intel, Guard, Targets & Scope, and Engine Settings |
| Recon | Allowlisted synthetic, TLS-metadata, Nmap, Subfinder, and read-only S3 adapters; approved scopes; rate limits; retries; normalized inventory |
| Intel | NVD/EPSS/CISA KEV parsing, service correlation, confidence/freshness, priority formula, persisted facts |
| Guard | Prompt-injection and PII inspection, audit metadata, bounded request handling; inspect-only by design |
| Readiness | AEI/VUI/AIET components, explicit unknown inputs, persisted snapshots |
| Live console | Server-side engine key, loopback-only engine URL, explicit operator authorization, durable demo state |
| Auth | Local login, opaque DB-backed sessions, per-session CSRF, ordered viewer/operator/admin roles, CLI account management |
| Intel schedule | Background NVD/EPSS/KEV runs through the same bounded ingestion path, persisted last-run status, KEV exposed in the UI |
| Recovery | SHA-256-manifested SQLite and PostgreSQL backup, verification, and restore with pre-restore copies |
| Persistence | PostgreSQL migrations for the production path; SQLite for the self-contained live-engine demo |
| Tests | Python, BFF, and frontend suites plus type-check, build, Compose validation, and a disposable PostgreSQL smoke test |

The five fixture-backed pages are deterministic demo views. **Targets & Scope**
and **Engine Settings** are the live console. The UI intentionally exposes only
CISA KEV ingestion; NVD and EPSS remain API-only.

## Architecture

```text
Browser
  │  same-origin /api/v1/*
  ▼
Flask BFF (127.0.0.1:3000)
  │  server-side API key, allowlisted fields
  ▼
Loopback FastAPI live engine (127.0.0.1:8765)
  ├── app/recon.py       approved scopes, allowlisted profiles, TLS metadata
  ├── app/intel_*.py     feed parsing, correlation, prioritization
  ├── app/guard.py       prompt-injection and PII detectors
  ├── app/readiness.py   AEI / VUI / AIET calculation
  └── data/live-engine.sqlite3   durable demo state
```

Production deployment uses the PostgreSQL repositories and migrations in
`app/recon_pg.py`, `app/intel_pg.py`, and `migrations/`. The live demo uses
`app/live_store.py` so it can run on a laptop without a database service.

## Quick start

### Windows one-command demo

Prerequisites: Python 3.13, Node.js 22, pnpm, and PowerShell.

```powershell
.\run-live-demo.ps1
```

Open <http://127.0.0.1:3000/>. The script creates a Python environment if
needed, builds the dashboard if needed, creates a local admin account on first
run, starts the live engine on loopback, and serves the UI and API from the same
origin. The generated credentials are printed once and saved to the gitignored
`frontend/instance/local-credentials.txt`; delete that file after the first
sign-in.

### Manual host setup

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m pip install -r frontend\requirements.txt

Set-Location frontend
pnpm install
pnpm build
..\.venv\Scripts\python.exe -m flask --app backend:create_app demo-credentials
Set-Location ..

# Terminal 1 — live engine
.\.venv\Scripts\python.exe -m scripts.live_engine

# Terminal 2 — Flask BFF + built UI
Set-Location frontend
..\.venv\Scripts\python.exe -m flask --app backend:create_app run `
  --host=127.0.0.1 --port=3000 --no-reload
```

If this checkout already uses `frontend\.venv`, substitute
`frontend\.venv\Scripts\python.exe` from the repository root and
`.\.venv\Scripts\python.exe` from `frontend\`; `run-live-demo.ps1` supports both.

Account recovery commands (run from `frontend/`):
`create-user`, `list-users`, `set-password`, `revoke-user`, and
`enable-user`. Run them with
`..\.venv\Scripts\python.exe -m flask --app backend:create_app <command>`.

Open <http://127.0.0.1:3000/>. The engine's database defaults to
`data/live-engine.sqlite3`; override it with `ZEROTRACE_LIVE_DB`.

### Docker Compose (PostgreSQL path)

`compose.yaml` starts PostgreSQL and Valkey only; the Flask BFF and React UI
still run on the host. Start the database profile, then point the BFF at it:

```powershell
docker compose --profile core up -d
docker compose exec postgres createdb -U zerotrace zerotrace_bff

$env:DATABASE_URL = "postgresql+psycopg://zerotrace:zerotrace-dev-only@127.0.0.1:5432/zerotrace_bff"
Set-Location frontend
..\.venv\Scripts\python.exe -m flask --app backend:create_app run `
  --host=127.0.0.1 --port=3000 --no-reload
```

The dedicated `zerotrace_bff` database keeps BFF demo tables separate from the
root application's PostgreSQL schema. Skip `createdb` if it already exists.

The disposable PostgreSQL proof and the backup/restore commands are listed in
[tasks/evidence/phase-16.md](tasks/evidence/phase-16.md). The Compose stack does
not start Recon adapters, the live engine, or a model.

## Five-minute demo flow

1. Sign in with the local account created by `demo-credentials` (or
   `create-user`). Sessions are DB-backed and mutations need the per-session
   CSRF token.
2. Open **Engine Settings**, keep the default loopback URL, and select **Test
   connection**. The engine key stays on the Flask side.
3. Open **Targets & Scope**, create a scope with an explicit authorization
   acknowledgement, then run the TLS-metadata profile (the default) or the
   synthetic inventory profile.
4. In **Targets & Scope**, use the live **Intel engine** panel to run the CISA
   KEV sync. The UI exposes KEV only; NVD and EPSS run on the schedule.
5. In the same page, use the live **Guard inspection** panel to run the
   built-in jailbreak prompt and verify that it is blocked without an upstream
   model call.
6. Inspect the **Operational Readiness** panel. Unknown inputs are shown as
   unknown, not as zero.

Persisted scopes, scan results, KEV counters, Guard inspection counts, and
readiness snapshots survive an engine restart.

## Safety boundaries

- Scope and scan creation require `authorized: true` in the BFF and the engine.
- Scan targets must be inside an approved, unexpired scope.
- Profiles are allowlisted; unavailable adapters are not advertised.
- The default live scan is a single bounded TLS metadata read.
- Recon rate limits, timeouts, output-size limits, and retry ceilings apply.
- The engine binds to loopback only; the BFF rejects non-loopback URLs.
- The browser never receives the engine API key.
- Authentication is required by default; sessions are opaque, CSRF-protected,
  and checked against ordered viewer/operator/admin roles.
- Feed runs use the same allowlisted source endpoints and bounded parsers as the
  manual endpoint; the scheduler never accepts an arbitrary URL.
- Guard inspection does not call an upstream model.
- No exploitation, brute force, credential attack, or automatic remediation is
  implemented.

## Verification

```powershell
# Python (root)
.\.venv\Scripts\python.exe -m pytest -q

# BFF
.\.venv\Scripts\python.exe -m pytest -q frontend\backend\tests

# Frontend
Set-Location frontend
pnpm exec tsc --noEmit
pnpm test
pnpm build

# Phase 14 synthetic end-to-end harness
Set-Location ..
.\.venv\Scripts\python.exe -m scripts.phase14_e2e

# Phase 15 resource/reliability report
.\.venv\Scripts\python.exe -m scripts.performance_report

# Phase 16 lab evidence driver (requires compose.lab.yaml)
.\.venv\Scripts\python.exe -m scripts.lab_scan

# Phase 16 scheduled feed run (requires the live engine)
.\.venv\Scripts\python.exe -m scripts.feed_run --source kev

# Phase 16 backup and restore
Set-Location frontend
..\.venv\Scripts\python.exe -m flask --app backend:create_app backup-db --output ..\backups\bff-demo.sqlite3
..\.venv\Scripts\python.exe -m flask --app backend:create_app verify-db-backup ..\backups\bff-demo.sqlite3

# Compose syntax
Set-Location ..
docker compose config --quiet
docker compose --profile core config --quiet
docker compose --profile full config --quiet
docker compose --profile dev config --quiet
docker compose -f compose.lab.yaml config --quiet
```

The Phase 13 evidence record is
[tasks/evidence/phase-13.md](tasks/evidence/phase-13.md). The corrected
dashboard decision is
[docs/decisions/ADR-008-dashboard-delivery-correction.md](docs/decisions/ADR-008-dashboard-delivery-correction.md).

Phase 14 evidence is
[tasks/evidence/phase-14.md](tasks/evidence/phase-14.md); Phase 15 evidence is
[tasks/evidence/phase-15.md](tasks/evidence/phase-15.md). Both are synthetic
and bounded. Phase 14 and Phase 15 human signoff remain pending operator
review.

Phase 16 closes the login/RBAC, PostgreSQL, real-lab scanner, scheduled-feed,
and backup/restore gaps. Evidence is
[tasks/evidence/phase-16.md](tasks/evidence/phase-16.md); human signoff is
pending.

## Repository layout

```text
app/                     Python engines, persistence, API factories, security
frontend/backend/        Flask BFF, settings, auth, audit, live-engine client
frontend/client/         React/Vite dashboard
scripts/                 Live engine and operator utilities
migrations/              PostgreSQL schema
tests/                   Python tests
tasks/                   Plan, todo, phase evidence
docs/                    Architecture, operations, decisions, runbooks
compose.yaml             PostgreSQL/Valkey development stack
compose.lab.yaml         Loopback-only isolated lab containers
```

## Known limitations

- Local account authentication is implemented, but there is no enterprise
  identity provider, SSO, SCIM, or MFA. Tenant IDs are not row-level data
  isolation.
- Fixture-backed views are intentionally synthetic.
- NVD and EPSS are scheduled but API-only in the UI; the full live NVD sync was
  not run end to end.
- Real scanner profiles require the corresponding binaries and a separately
  authorized scope. The recorded lab run uses a short-lived self-signed
  certificate and is not a production scan.
- The SQLite live store is demo infrastructure; PostgreSQL is the production
  persistence path. The host-port PostgreSQL path was intermittent during
  Docker Desktop checkpoints; the recorded smoke test uses the Compose network.
- Backups are local and unencrypted; there is no offsite copy or retention
  policy.
- Performance and remediation are measured/proposed, not automatically
  executed in production. The full 9 GB model profile is unproven.
