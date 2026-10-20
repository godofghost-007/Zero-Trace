# ZeroTrace Flask backend connectivity

**Status:** local connected prototype. The React dashboard talks to a Flask API, SQL persistence, a transactional outbox, optional Valkey/Redis Streams, and a separate SQLite Guard audit file. The engine actions are safe synthetic fixtures; this is not the full ZeroTrace cyber-defense platform.

Related: [Page and engine connectivity map](01-page-and-engine-connectivity.md), [compiled architecture](../../zerotrace/wiki/architecture.md), [Recon](../../zerotrace/wiki/trace-recon.md), [Intel](../../zerotrace/wiki/trace-intel.md), [Guard](../../zerotrace/wiki/trace-guard.md), [readiness score](../../zerotrace/wiki/operational-readiness.md).

## 1. Service layout

```text
React / Wouter dashboard
  └── relative JSON /api/v1/*
      ├── Host dev: Vite :3000 → proxy → Flask 127.0.0.1:5000
      └── Compose: Flask/Gunicorn serves frontend + API :3000
           ├── SQLite (host-development fallback) OR PostgreSQL (Compose target)
           ├── SQL transactional event_outbox → optional Valkey Streams
           └── separate SQLite guard-audit.sqlite
```

Core implementation: `backend/api.py` routes, `backend/services/scenario.py` fixture transitions and readiness snapshots, `backend/services/outbox.py` event relay, `backend/services/audit.py` hash chain, and `backend/models.py` SQLAlchemy entities. React transport is `client/src/lib/api.ts`; shared state is in `client/src/lib/zeroTraceDemo.tsx`.

The Flask app auto-creates the prototype schema on startup. This is convenient for the local demo, **not** a production migration strategy. Compose binds only `127.0.0.1`; database and Valkey are internal services, not published host ports. No authentication is configured, so keep it local and use only the bundled fictional data.

## 2. Implemented API surface

All routes use `/api/v1`, relative same-origin paths, JSON and a response `X-Request-ID` header.

| Method and route | Implementation behavior |
|---|---|
| `GET /health`, `GET /ready` | Liveness; database and sanitized event-bus availability. |
| `GET /demo/state`, `POST /demo/reset` | Load all shared demo state; reset only demo records and audit rows. Reset requires `DEMO_MODE=true`. |
| `POST /demo/steps/recon` | Persist a partial sample scan, asset, `asset_created`, and score snapshot; makes no network scan. |
| `POST /demo/steps/intel` | Persist a synthetic finding/match, review-required 48-hour proposal, event, and snapshot. |
| `POST /demo/steps/guard` | Persist a blocked sample outcome, correlated SQLite audit row, outbox event, and snapshot. No prompt is sent. |
| `GET /dashboard/summary` | Current state and compact counts. |
| `GET /events?limit=50`, `POST /events/relay-pending` | Outbox records and bounded manual retry. Limit is clamped to 1–100. |
| `GET /assets`, `GET /assets/{asset_id}`, `GET /recon/scans` | Persisted demo inventory and partial scan status. |
| `GET /intel/status`, `GET /matches`, `GET /patch-proposals` | Synthetic feed/model availability, linked evidence, and non-executable review proposal. |
| `GET /guard/status`, `GET /guard/events`, `GET /guard/audit/verify` | Simulated proxy status (disabled), minimal event metadata, and chain integrity status. |
| `GET /readiness/current`, `GET /readiness/history` | Latest score/index snapshot and history. |

Engine-step writes enforce order and are idempotent for a completed stage. They return `409` if a prior stage is missing. Error responses have a stable `{error:{code,message}, request_id}` shape; unexpected failures are logged server-side without leaking details.

## 3. SQL persistence and canonical state

| Table | Owner / contents |
|---|---|
| `demo_scenario` | Current demo stage and correlation ID. |
| `scan_runs` | Synthetic Recon scan result, `partial` flag and warnings. |
| `assets` | Stable asset ID, hostname, scope, fixture provenance and service JSON. |
| `vulnerabilities` | Synthetic finding fields, including illustrative CVSS/EPSS-like values. |
| `service_vulnerabilities` | Finding-to-asset link, fixture method, confidence, evidence and review state. |
| `patch_proposals` | Proposal status, 48-hour window, human-review required, execution disabled. |
| `guard_events` | Minimal outcome and pointer to the separate SQLite audit chain. |
| `score_snapshots` | Nullable AEI/VUI/AIET values, coverage components and formula version. |
| `event_outbox` | Stable event envelope, payload, publication attempts, Valkey stream entry ID and status. |

`DATABASE_URL` selects the database. The default host path is `sqlite:///instance/zerotrace.db`; Compose supplies `postgresql+psycopg://…`. The audit file defaults to `instance/guard-audit.sqlite` in host development and `/data/guard-audit.sqlite` in the app container. A normalized `services` table, observation tables, account/scope authorization, migration tooling and retention policy are not yet implemented.

## 4. Outbox and event transport

Producers commit domain records, stage and outbox rows in one SQL transaction. After an action commits, `relay_pending()` attempts to append each outbox row to `REDIS_STREAM` (default `zerotrace:events`) using `XADD` when `REDIS_URL` is configured. The message carries IDs, schema version, source, timestamp, correlation and bounded JSON data—never credentials or the prompt. Without Valkey, or if it is unreachable, the row remains `pending`; the UI shows the pending count. The retry endpoint can be used after the bus recovers.

This demo contains no stream consumer groups, worker acknowledgements, dead-letter processor, or event-driven recomputation worker: the UI's ordered actions update the snapshot within the Flask request. Treat any future consumer as at-least-once and make handlers idempotent; an event's `published` status must not be treated as proof of consumption.

## 5. Guard audit chain

The independent SQLite table contains sequence, event ID, action/outcome, asset/finding/correlation IDs, UTC time, previous hash and row hash. Hash is SHA-256 over the previous hash and a canonical JSON record. Repeated event IDs are idempotent; `GET /guard/audit/verify` checks sequence continuity and recomputes every digest. Only minimal metadata is stored. The plaintext demo prompt stays in the UI and is not included in the POST body.

This is tamper-evident, not immutable: privileged deletion or replacement of the SQLite file is not prevented. A production service needs protected backups/checkpoints, access control, retention and an explicit failure policy. There is no live proxy, API-key store, regex engine, ONNX model, upstream, or PII scan in this prototype.

## 6. Readiness behavior

The governing formula is `clamp(100 - (0.40 × AEI + 0.40 × VUI + 0.20 × AIET), 0, 100)`. Components are nullable until their denominator exists; overall score stays unavailable until all components are observed. After the synthetic Guard event, AEI=20, VUI=35 and AIET=0 yield a demo score of 78. A blocked request is not counted as an unblocked attack. The source's separate `(20,35,25)` arithmetic conflict—equation gives 73, source table says 71—remains visibly documented and has not been silently reconciled.

## 7. Run locally

### Docker Compose

```bash
cp .env.example .env
# Change POSTGRES_PASSWORD in .env to a unique local-only value.
docker compose up --build
```

Open `http://localhost:3000`. The Compose app uses PostgreSQL and Valkey and stores its audit chain/data in named volumes. `docker compose down -v` removes all volumes and is destructive.

### Host development

Activate a Python 3.12 virtual environment, install `requirements.txt`, then run:

```bash
flask --app backend:create_app run --host=127.0.0.1 --port=5000
```

In a second terminal, run `pnpm install` and `pnpm dev`. Vite proxies `/api/v1` to Flask. Host development defaults to SQLite; outbox events remain pending unless `REDIS_URL` points to a local Valkey/Redis instance.

On Windows, run Vite explicitly because `cmd.exe` does not expand the `${PORT:-3000}` placeholder: `pnpm exec vite --host 127.0.0.1 --port 3000 --strictPort`. Alternatively `.\run-local.ps1` builds `dist/public` and serves the UI and API together from Flask on `http://127.0.0.1:3000/`.

Tests: `python -m pytest -q backend/tests`; frontend checks/build: `pnpm check && pnpm test && pnpm build`.

## 8. Production gap / safety contract

Before deployment or real targets, implement authentication, roles and CSRF controls; database migrations and backup/restore; formal scope authorization and scanner sandboxing; feed freshness and schemas; deterministic match review; model evaluation and calibrated thresholds; separate live Guard gateway with key lifecycle, upstream allowlist, timeouts, PII policy; event consumers/retries/dead letters; audit policy; and measured resource limits. The current local demo intentionally performs none of these privileged operations.
