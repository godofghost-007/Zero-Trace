# ZeroTrace

ZeroTrace is a planned three-module cyber-defense platform:

- **Recon** discovers authorized assets and exposed services.
- **Intel** correlates vulnerability intelligence and prioritizes remediation.
- **Guard** protects LLM traffic through an OpenAI-compatible gateway.

This repository is currently at **Phase 6 — Recon MVP**. The runnable
foundation, deterministic readiness-score contract, tested security primitives,
event delivery state model, and constrained Recon contracts/adapters are in
place.

## Development workflow

Development follows the repository-local
[Copilot Development Loop](./copilot-zerotrace-loop/copilot-zerotrace-loop/README.md).
Work must proceed phase by phase with recorded evidence, tests, human review,
and explicit approval for security-sensitive decisions.

## Repository layout

```text
app/                    Application package and health endpoint
migrations/             PostgreSQL foundation migrations
scripts/                Operational entrypoints such as migrations
tests/                  Test suite and controlled fixtures
tasks/                  Active plan, task tracker, and phase evidence
docs/                   Project decisions and operational documentation
ZeroTrace/              Source project documentation and design notes
copilot-zerotrace-loop/ Development workflow kit
```

## Current status

- Phase 0 and Phase 1 are complete with recorded evidence.
- Phase 2 provides validated settings, logging, health endpoints, and an
  idempotent PostgreSQL foundation migration plus event-reliability persistence
  primitives.
- Phase 3 provides versioned AEI, VUI, and AIET calculations with explicit
  unknown-component and coverage behavior. The governing combined fixture
  `(20, 35, 25)` evaluates to 73.
- Phase 4 provides fail-closed password/API-key primitives, role checks, CSRF
  tokens, secure session-cookie formatting, request-size limits, security
  headers, and private audit-file handling. Persistent user/session storage
  and full API route authentication remain later integration work.
- Phase 5 provides a validated versioned event envelope, commit-before-publish
  outbox semantics, idempotent consumer processing, bounded retry/backoff,
  dead-letter transitions, and stale-record reconciliation. The in-memory
  repository is a deterministic test double; PostgreSQL and Redis integration
  remain deployment work.
- Phase 6 provides approved-scope enforcement, fixed-profile Subfinder/Nmap/TLS
  and read-only S3 adapter boundaries, untrusted-output parsing, normalized
  observations, explicit timeout/cancellation/partial/failure states,
  idempotent run creation, and result-before-event ordering. Tests use fake
  runners/connectors only; no external or live lab target was scanned.
  Target authorization now supports exact-domain, single-use DNS TXT
  challenges with bounded system DNS or allowlisted DoH resolution. Isolated
  lab queueing rejects scopes without an active authorization.
- No scanners or external targets are used during development setup.
- No generated remediation is executed automatically.
- Secrets and production/customer data must not be placed in source, fixtures,
  logs, or hosted Copilot context without an approved data-handling decision.

## Local verification

Install the project dependency and start the disposable development database:

```powershell
py -m pip install -e .
docker compose --profile dev up -d postgres
```

Apply all database migrations. The runner applies ordered migrations and is safe
to run repeatedly:

```powershell
$env:DATABASE_URL = "postgresql://zerotrace:zerotrace-dev-only@127.0.0.1:5432/zerotrace"
py scripts/run_migrations.py
```

Run the application health endpoint:

```powershell
$env:ZEROTRACE_ENV = "dev"
$env:DATABASE_URL = "postgresql://zerotrace:zerotrace-dev-only@127.0.0.1:5432/zerotrace"
py -m app
```

In another terminal, request `http://127.0.0.1:8765/health`. The liveness
endpoint returns HTTP 200. `/ready` remains degraded until dependency checks
are wired into the runtime in a later foundation increment.

Run the automated checks:

```powershell
py -m unittest discover -s tests -v
py -m compileall -q app scripts
docker compose --profile core config --quiet
docker compose --profile full config --quiet
docker compose --profile dev config --quiet
git diff --check
```
