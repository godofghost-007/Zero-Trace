# Phase 13 Evidence — Dashboard UI/UX

## Decision
Phase 13 is **implemented and reproducible** as the React/Vite dashboard in
`frontend/`, served by the Flask BFF. The previously claimed standalone
`app/dashboard/` server never existed in the committed tree and has been
removed from the delivery record. See
[ADR-008](../../docs/decisions/ADR-008-dashboard-delivery-correction.md).

## Environment
- Windows 11, Python 3.13.5, Node.js 22.14.0, pnpm 10.22.0
- Flask BFF on `127.0.0.1:3000`
- Optional loopback live engine on `127.0.0.1:8765`
- SQLite demo state at `data/live-engine.sqlite3`
- Docker lab services on loopback only (nginx/httpd)

## Date
2026-10-21

## Scope
The dashboard is a React single-page application with a Flask backend-for-
frontend (BFF). The browser talks only to same-origin `/api/v1/*` routes. Flask
keeps the live-engine API key server-side and forwards only allowlisted fields
to the loopback engine. No standalone `http.server` dashboard, no port 8766
server, and no browser-held engine key are part of the delivery.

The live console covers:

- operator-approved scope creation and scan creation;
- allowlisted Recon profiles with the TLS metadata profile as the default live
  read;
- scan status/result polling and TLS metadata display;
- CISA KEV ingestion with persisted counters;
- Guard prompt-injection/PII inspection without an upstream model call;
- component-by-component Operational Readiness Score with explicit unknown
  inputs.

## Required criteria and evidence

| Criterion | Status | Evidence |
|---|---|---|
| React dashboard is present and routed | PASS | `frontend/client/src/App.tsx` routes `/`, `/database`, `/recon`, `/intel`, `/guard`, `/targets`, `/settings` |
| Shared design primitives are preserved | PASS | `frontend/client/src/components/DemoPrimitives.tsx`, `DemoShell.tsx`, `index.css` |
| Browser uses same-origin Flask API only | PASS | `frontend/client/src/lib/api.ts` calls `/api/v1${path}` |
| Engine key stays server-side | PASS | `frontend/backend/services/engine.py`; React settings type exposes only `apiKeyConfigured`/`apiKeyHint` |
| Engine URL is loopback-only | PASS | `validate_base_url()` in `frontend/backend/services/engine.py` |
| Scope and scan creation require explicit authorization | PASS | `frontend/backend/engine_api.py` plus `tests/test_engine_api.py` |
| Live engine composes Recon/Intel/Guard | PASS | `scripts/live_engine.py` |
| State survives an engine restart | PASS | `tests/test_live_engine_persistence.py::test_live_engine_state_survives_restart` |
| Intel snapshot survives an engine restart | PASS | Same test — KEV counter remains `1` after restart |
| Readiness recomputes from persisted traces | PASS | `GET /api/v1/engine/readiness`; `tests/test_live_engine_persistence.py` |
| CISA KEV is the only feed exposed by the UI | PASS | `frontend/backend/engine_api.py` rejects non-KEV sources; `Targets.tsx` shows the API-only note |
| Guard inspection does not contact an upstream model | PASS | `scripts/live_engine.py` uses `PromptInjectionDetector`/`PIIScanner`; `upstreamConfigured: false` |
| Standalone dashboard CLI is removed | PASS | `scripts/dashboard_cli.py`, `start_dashboard.py`, `test_dashboard_client.py`, `fix_server.py` removed |
| Frontend type-check and build | PASS | `pnpm exec tsc --noEmit`; `pnpm build` |
| Python tests | PASS | `frontend/.venv/Scripts/python.exe -m pytest -q` — 199 passed |
| BFF tests | PASS | `frontend/.venv/Scripts/python.exe -m pytest -q frontend/backend/tests` — 13 passed |
| Frontend tests | PASS | `pnpm test` — 6 passed |
| Persisted scan is visible after restart | PASS | Browser reload showed scope `zt-lab-20261021`, completed scan `3cc1d8fc…`, KEV count `1748`, the persisted Guard count, and zero console errors |
| Compose configuration | PASS | `docker compose ... config --quiet` |
| Browser smoke check | PASS | `/settings` and `/targets` loaded, engine connection succeeded, scope + synthetic scan completed, Guard blocked the demo prompt, persisted state reloaded, zero console errors |

## Verification commands

```powershell
frontend\.venv\Scripts\python.exe -m pytest -q
frontend\.venv\Scripts\python.exe -m pytest -q frontend/backend/tests
Set-Location frontend; pnpm exec tsc --noEmit; pnpm test; pnpm build
docker compose config --quiet
docker compose --profile core config --quiet
docker compose --profile full config --quiet
docker compose --profile dev config --quiet
```

## Persistence design

`app/live_store.py` is a small SQLite store used only by the local demo engine.
It persists:

- approved scopes;
- queued/completed scan rows, including normalized assets, services, warnings,
  and TLS findings;
- the last NVD/EPSS/KEV snapshot and ingestion/idempotency metadata;
- Guard inspection counts;
- readiness snapshots.

The production PostgreSQL repositories and migrations remain the canonical
deployment path. The SQLite store exists so the demo survives a process restart
without requiring a database service on the laptop.

## Removed artifacts

The following files imported or exercised the missing `app/dashboard` package
and were removed:

- `scripts/dashboard_cli.py`
- `start_dashboard.py`
- `test_dashboard_client.py`
- `fix_server.py`

`docs/decisions/ADR-007-dashboard.md` is marked superseded. The Phase 13 CLI
task is recorded as removed rather than verified.

## Authorized local evaluation record — 2026-10-21

The operator-authorized evaluation used the loopback engine and the
deterministic synthetic inventory adapter:

- Scope: `zt-lab-20261021`
- Target: `lab.example.test`
- Environment: `synthetic`
- Profiles approved: `synthetic_inventory_v1`, `tls_metadata_v1`
- Authorization acknowledgement: present at scope and scan creation
- Scan: `3cc1d8fc-3fa2-448d-be5d-bffc9c44adec` — `completed`
- Result: one asset (`lab.example.test`), one service (`tcp/443`, `https`)
- Intel: live CISA KEV ingestion — `1748` records, persisted across restart
- Guard: jailbreak prompt — blocked as `prompt_injection`; PII not blocked
- Readiness: AEI `100.00%` known, VUI unknown (NVD not loaded), AIET `0.00%`
  known, coverage `66.7%`, score correctly withheld
- Restart: the Flask BFF and live engine were stopped and restarted; the UI
  reloaded the persisted scope, scan result, KEV counter, and Guard count

The Docker lab containers were not used for a real scanner run: the host lacks
`nmap`/`subfinder`, and the lab TLS host port (`8443`) does not match the live
engine's default TLS port (`443`). This is recorded rather than represented as
real scanner evidence. See [docs/LAB-RUNBOOK.md](../../docs/LAB-RUNBOOK.md).

## Exceptions and unresolved risks

- The demo dashboard is not a production console: there is no login/RBAC/CSRF
  session model, no external feed scheduler, and no executable remediation.
- The live engine is loopback-only and single-operator. It is not a multi-tenant
  service.
- NVD and EPSS ingestion remain API-only. KEV ingestion requires outbound access
  to the fixed CISA endpoint; the automated tests use a synthetic transport.
- Real scanner profiles require the corresponding binaries and a separately
  authorized isolated-lab target.

## Human signoff

**Human signoff:** Pending operator review of this corrected evidence record.
