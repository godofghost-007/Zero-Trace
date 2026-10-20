# ZeroTrace Flask connectivity — implementation plan

## Goal and scope

Evolve the five-screen ZeroTrace prototype into a locally connected demo: the existing React pages call a Python Flask API, scenario state and events persist in a database, Guard audit rows append to a separate SQLite hash-chain file, and the event outbox can publish to Valkey/Redis when configured. The same sample asset, finding, attack, score snapshots and correlation ID must travel through the Recon → Intel → Guard sequence.

This is a safe local integration slice, not production ZeroTrace. Recon and Intel actions materialize deterministic synthetic fixtures only; they do not invoke Subfinder, Nmap, DNS, NVD, EPSS, CISA KEV, XGBoost, ONNX, Ollama, or a real LLM. Guard records a simulated decision; it does not expose an OpenAI-compatible proxy yet. No generated remediation is executed. Authentication/RBAC, live worker scheduling, and production backup/retention are not part of this implementation. Local Compose will bind the app to loopback and keep PostgreSQL/Valkey ports internal.

## Architecture and request flow

- The React/Vite UI remains the presentation layer and sends same-origin `/api/v1/...` JSON calls. During development Vite proxies those paths to Flask on `127.0.0.1:5000`; in the Compose image, Flask serves the compiled React app and the API from the same origin on port 3000.
- Flask uses an app factory and blueprints, SQLAlchemy models and service functions. `DATABASE_URL` selects PostgreSQL in Compose; the development default is a local SQLite database so the API can run and be tested without Docker.
- PostgreSQL is canonical for demo state, asset/finding fixtures, Guard event metadata, score snapshots and an `event_outbox` table. A domain write and outbox row share one SQL transaction.
- An outbox relay attempts to add event metadata to a Valkey/Redis stream. If the bus is unavailable, the canonical outbox row remains pending and can be retried; an event is not mislabeled as consumed. The API reports bus/outbox status.
- Guard's audit chain is a separate SQLite file, with append-only sequence, canonical metadata, previous hash and SHA-256 digest. It stores no prompt or response body. This demo chain is tamper-evident, not tamper-proof.
- `/api/v1/demo/state`, `/reset`, and the Recon/Intel/Guard step endpoints supply the same IDs and score semantics to every page. Health, summary, readiness, event, inventory, Intel and Guard read APIs expose the corresponding real backend state.

## Project structure

```text
backend/
  __init__.py                 Flask app factory and static SPA serving
  config.py                   DATABASE_URL, REDIS_URL, audit path, demo-only settings
  extensions.py               SQLAlchemy extension
  models.py                   scenario, asset, finding, score, Guard metadata, outbox
  api.py                      /api/v1 health, state, summary and engine/read APIs
  services/
    scenario.py               fixture-only staged transitions and readiness snapshots
    outbox.py                 pending-event relay and bounded retry behavior
    audit.py                  independent SQLite append and integrity verification
  tests/                      API, stage, outbox and hash-chain tests
client/src/lib/
  api.ts                      typed same-origin fetch/error handling
  zeroTraceDemo.tsx           API-backed shared query/action state
compose.yaml                  app + PostgreSQL + Valkey, host-bound app only
Dockerfile                    Node frontend build stage, slim Python Flask runtime
requirements.txt              pinned Flask/SQLAlchemy/PostgreSQL/Redis/Gunicorn/test deps
```

## User experience and safety

Keep the five page routes and approved Forensic Paper Trail design; replace “browser-only” claims with truthful “local backend / sample data” indicators. Show API connectivity, persisted sample state, partial/unknown values, and event outbox status without implying scanner/model execution. Reset is an explicit demo-data reset, not a production delete. Compose exposes only the web app on `127.0.0.1`; PostgreSQL and Valkey are internal network services. Do not add credentials to Vite variables or frontend bundles.

The browser must never receive a database DSN, Redis URL, provider API key or audit file path. A later internet-accessible deployment requires authentication/RBAC, CSRF protection where cookies are used, request limits, authorization scopes and the additional security controls in `docs/02-backend-connectivity.md`.

## Existing platform constraints

The project is currently configured for static-only WebDev (`server:false`, `database:false`) with Preview on port 3000. Do not change those one-way managed feature settings or publish the app: the requested target is Flask/Python local connectivity, not managed hosting. The existing Vite Preview stays on 3000 and proxies to a local Flask process on 5000. Containerized PostgreSQL/Valkey are described in Compose; because the current Sandbox has no Docker executable, exercise the application with SQLite and a Redis-unavailable/pending-outbox path here, and provide Compose for the user's laptop.
