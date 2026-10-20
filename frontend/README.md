# ZeroTrace Dashboard

React + Vite dashboard for the local ZeroTrace demo, served with a Flask BFF.
The browser only calls same-origin `/api/v1/*` routes. Flask keeps the live
engine API key on the server and forwards to a loopback-only FastAPI process.

## Pages

| Route | Source | Purpose |
|---|---|---|
| `/` | Fixtures | Architecture and the three-module story |
| `/database` | Fixtures | Database, event outbox, and readiness pipeline |
| `/recon` | Fixtures | Recon inventory and TLS metadata walkthrough |
| `/intel` | Fixtures | Intel correlation and prioritization walkthrough |
| `/guard` | Fixtures | Guard prompt-injection/PII walkthrough |
| `/targets` | **Live engine** | Approved scope and scan console, readiness components |
| `/settings` | **Live engine** | Loopback connection settings and test |

The fixture pages are deterministic demo views. `Targets & Scope` and `Engine
Settings` are the live console. The UI exposes CISA KEV ingestion only; NVD and
EPSS remain API-only.

## Run

From the repository root:

```powershell
.\run-live-demo.ps1
```

Open <http://127.0.0.1:3000/>. The script starts the loopback engine and the
Flask BFF.

Or manually:

```powershell
# Terminal 1 (repository root)
.\.venv\Scripts\python.exe -m scripts.live_engine

# Terminal 2
Set-Location frontend
..\.venv\Scripts\python.exe -m flask --app backend:create_app run `
  --host=127.0.0.1 --port=3000 --no-reload
```

For Vite development with hot reload:

```powershell
# Terminal 1
..\.venv\Scripts\python.exe -m flask --app backend:create_app run `
  --host=127.0.0.1 --port=5000 --no-reload

# Terminal 2
pnpm dev
```

Open <http://127.0.0.1:3000/>. Vite proxies `/api/v1` to Flask on
`127.0.0.1:5000`; see `vite.config.ts`.

## Live engine settings

The BFF persists non-secret connection settings in
`frontend/instance/engine-settings.json` (gitignored). The API key is never
returned to the browser; only `apiKeyConfigured` and a hint are exposed.

Defaults:

- Engine URL: `http://127.0.0.1:8765`
- BFF URL: `http://127.0.0.1:3000`
- Engine state: `data/live-engine.sqlite3` (override with `ZEROTRACE_LIVE_DB`)

The engine URL must resolve to a loopback host. Scope and scan creation require
an explicit `authorized: true` acknowledgement in both layers.

## Security model

- Same-origin browser requests with the existing origin/CSRF checks.
- Server-side engine key custody.
- Loopback-only engine URL validation.
- Allowlisted request fields and response size limits.
- No upstream model call for Guard inspection.
- No exploitation, brute force, or automatic remediation.

This is a single-operator demo, not a production console. There is no
login/RBAC or multi-tenant isolation.

## Tests and checks

```powershell
pnpm exec tsc --noEmit
pnpm test
pnpm build
..\.venv\Scripts\python.exe -m pytest -q backend\tests
```

The BFF tests cover the engine settings, loopback validation, authorization,
forwarding, and safe error handling. The live-engine persistence tests are in
the repository root at `tests/test_live_engine_persistence.py`.

## Docker

`compose.yaml` runs Flask with PostgreSQL and Valkey:

```powershell
Copy-Item .env.example .env
# Set a unique local POSTGRES_PASSWORD.
docker compose up --build
```

The live engine is not started by this Compose stack; run it separately on the
host when you want the Targets console in live mode.
