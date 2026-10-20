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
| Persistence | PostgreSQL migrations for the production path; SQLite for the self-contained live-engine demo |
| Tests | Python, BFF, and frontend suites plus type-check, build, and Compose validation |

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
needed, builds the dashboard if needed, starts the live engine on loopback, and
serves the UI and API from the same origin.

### Manual host setup

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m pip install -r frontend\requirements.txt

Set-Location frontend
pnpm install
pnpm build
Set-Location ..

# Terminal 1 — live engine
.\.venv\Scripts\python.exe -m scripts.live_engine

# Terminal 2 — Flask BFF + built UI
Set-Location frontend
..\.venv\Scripts\python.exe -m flask --app backend:create_app run `
  --host=127.0.0.1 --port=3000 --no-reload
```

Open <http://127.0.0.1:3000/>. The engine's database defaults to
`data/live-engine.sqlite3`; override it with `ZEROTRACE_LIVE_DB`.

### Docker Compose (PostgreSQL path)

```powershell
Copy-Item frontend\.env.example frontend\.env
# Set a unique local POSTGRES_PASSWORD in frontend\.env.
Set-Location frontend
docker compose up --build
```

This path runs the Flask application, PostgreSQL, and Valkey. The live engine
remains a separate loopback process; the Compose stack does not start Recon
adapters or a model.

## Five-minute demo flow

1. Open **Engine Settings**, keep the default loopback URL, and select **Test
   connection**. The engine key stays on the Flask side.
2. Open **Targets & Scope**, create a scope with an explicit authorization
   acknowledgement, then run the TLS-metadata profile (the default) or the
   synthetic inventory profile.
3. In **Targets & Scope**, use the live **Intel engine** panel to run the CISA
   KEV sync. The UI exposes KEV only.
4. In the same page, use the live **Guard inspection** panel to run the
   built-in jailbreak prompt and verify that it is blocked without an upstream
   model call.
5. Inspect the **Operational Readiness** panel. Unknown inputs are shown as
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

# Compose syntax
Set-Location ..
docker compose config --quiet
docker compose --profile core config --quiet
docker compose --profile full config --quiet
docker compose --profile dev config --quiet
```

The Phase 13 evidence record is
[tasks/evidence/phase-13.md](tasks/evidence/phase-13.md). The corrected
dashboard decision is
[docs/decisions/ADR-008-dashboard-delivery-correction.md](docs/decisions/ADR-008-dashboard-delivery-correction.md).

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

- The dashboard has no login/RBAC/session model; it is a single-operator local
  demo.
- Fixture-backed views are intentionally synthetic.
- NVD and EPSS ingestion are API-only and are not scheduled by the UI.
- Real scanner profiles require the corresponding binaries and a separately
  authorized scope.
- The SQLite live store is demo infrastructure; PostgreSQL is the production
  persistence path.
- Performance and remediation are measured/proposed, not automatically
  executed in production.
