# ZeroTrace — Flask-Connected Local Demo

A five-view React dashboard connected to a local Flask API. The backend persists the shared Recon → Intel → Guard fixture flow, readiness snapshots, event outbox, and Guard audit metadata. Security engines deliberately use fixed sample data; this is not yet a real scanner, vulnerability-feed service, classifier, or LLM proxy.

## Run on a laptop

### Docker Compose (PostgreSQL + Valkey + Flask + UI)

Prerequisites: Docker Desktop (or Docker Engine with Compose) and enough available RAM for the chosen services.

```bash
cp .env.example .env
# Set POSTGRES_PASSWORD in .env to a unique local value before starting.
docker compose up --build
```

Open `http://localhost:3000`. The app is bound to `127.0.0.1`; PostgreSQL and Valkey ports are internal to the Compose network. Named volumes preserve the database, event stream and SQLite audit file between restarts. The Compose stack targets PostgreSQL plus Valkey; it does not start scanners or an inference model.

### Host development (SQLite + Vite)

In terminal 1, create and activate a Python virtual environment, then install backend dependencies:

```bash
python -m venv .venv
# macOS/Linux: source .venv/bin/activate
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
flask --app backend:create_app run --host=127.0.0.1 --port=5000
```

In terminal 2:

```bash
pnpm install
pnpm dev
```

Vite serves the UI on port 3000 and proxies relative `/api/v1/*` requests to Flask on `127.0.0.1:5000`. Host development defaults to SQLite files under `instance/`; no Valkey is required, so outbox events remain visibly `pending`. To test Redis/Valkey publication use Compose.

On Windows, the `pnpm dev` script's `${PORT:-3000}` placeholder is not expanded by `cmd.exe`. Use the explicit command instead (with Flask still running on port 5000):

```powershell
pnpm exec vite --host 127.0.0.1 --port 3000 --strictPort
```

Alternatively, serve the built UI and the API from one Flask origin:

```powershell
.\run-local.ps1
```

Open `http://127.0.0.1:3000/`. The script creates `.venv` when needed, installs the pinned host dependencies, builds `dist/public` when missing, and runs Flask on port 3000.

## Checks

```bash
# Python integration tests (activate .venv first)
python -m pytest -q backend/tests

# Existing frontend type-check, tests, and static asset build
pnpm check && pnpm test && pnpm build
```

`pnpm build` emits the UI to `dist/public/`. The container image builds the frontend and serves it with Flask/Gunicorn on port 3000; production-like serving is provided by Docker Compose, not `pnpm start` alone.

## What is connected, and what is not

- **Connected:** every page reads Flask-backed state; engine actions persist synthetic records in SQLite for host development or PostgreSQL in Compose; a PostgreSQL transactional outbox relays events to Valkey Streams when configured; Guard writes/verifies a separate SQLite SHA-256 chain.
- **Fixture-only:** Recon does not run Subfinder/Nmap or make DNS/TLS/S3 requests. Intel does not fetch NVD/EPSS/KEV or run XGBoost/Ollama. Guard does not accept real API keys, load ONNX, proxy an upstream model, or scan a model response. No prompt text is sent to Flask.
- **Not production-ready:** there is no login/RBAC/CSRF protection, schema migration system, real workers/consumers, external feed integration, executable remediation, or hardened audit backup. Keep this demo local and use only the bundled synthetic records.

The demo reset button clears this application's scenario tables and Guard audit rows in the configured local data store. Do not point it at non-demo data. `docker compose down -v` deletes all Compose volumes and is destructive to persisted demo data.

The approximately 9 GB memory figure remains a project target, not a measurement. Readiness indexes with zero denominators remain unknown; the documented combined-case arithmetic discrepancy is retained in the UI and docs.

## Documentation

- [Page and engine connectivity map](docs/01-page-and-engine-connectivity.md)
- [Backend connectivity and API contract](docs/02-backend-connectivity.md)
- [Project implementation plan](plan.md)
