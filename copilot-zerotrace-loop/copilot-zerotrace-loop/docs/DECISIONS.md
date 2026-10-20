# ZeroTrace Decision Register

These items are open until the project owner records an answer, rationale, date, and affected contracts. Copilot must not invent a choice or implement dependent behavior while it remains unresolved.

| ID | Decision | Why it matters | Current status |
|---|---|---|---|
| D-001 | Durable events: PostgreSQL transactional outbox, Redis Streams, or documented combination | Delivery guarantee, replay, operational complexity, failure handling | Closed; PostgreSQL transactional outbox + Redis Streams |
| D-002 | Readiness score: precise AEI/VUI/AIET definitions, normalization, missing values, zero denominators, bands and formula version | Score correctness and explainability | Closed; unknown components and coverage are exposed, with no false precise aggregate |
| D-003 | Authentication scope and session/JWT/API-key boundaries; role matrix | Access control and API contracts | Closed; separate session, bearer, and Guard-key boundaries; standard lifetimes |
| D-004 | Audit design: what data is stored, redaction/retention, hash algorithm/keying, SQLite file protection, verification/recovery | Tamper evidence and privacy limitations | Closed; minimal metadata, no raw prompts/responses by default, 30-day operational retention |
| D-005 | Guard policy for Redis outage, audit-write failure, model absence, upstream failure | Fail-open/closed and availability/security tradeoffs | Closed; fail closed for limiter/audit, model absence DEGRADED, upstream 502 |
| D-006 | Explicit authorized scan-scope representation, approval process, Nmap profiles and limits | Prevent out-of-scope scanning and unsafe command execution | Closed; canonical Scope records with target/profile/expiry/approval evidence |
| D-007 | Docker Compose core/full/dev profiles, network exposure and optional model services | Laptop RAM and safe deployment | Closed; core/full/dev, private data services, Ollama optional |
| D-008 | Copilot-hosted data boundary: code/spec/telemetry allowed, prohibited secrets/customer/production data | External model privacy | Closed; sanitized project context only |
| D-009 | Actual repository root and document paths (notes refer to `E:\\zerotrace-demo`) | Avoid editing wrong workspace or duplicating docs | Closed; root confirmed |

## Decision record format

For each closed item, add: choice; alternatives; rationale; consequences; affected modules/contracts; tests or migration impact; owner; date; status. If it changes existing approved intent, update the relevant spec/ADR before code and identify downstream evidence needing rerun.

## Closed decisions

### D-008 — Copilot-hosted data boundary

- **Choice:** Sanitized project code and specifications may be used with hosted
  Copilot. Secrets, customer data, production data, and raw sensitive prompts
  are prohibited.
- **Rationale:** Allows normal development while keeping high-risk data outside
  the hosted context.
- **Affected areas:** Prompts, fixtures, logs, context bundles, and reviews.
- **Owner/date:** User, 2026-10-17.

### D-009 — Repository root

- **Choice:** `E:\zerotrace-demo` is the implementation repository root.
- **Rationale:** Git reports this path as the repository root and the loop kit
  is nested within it.
- **Affected areas:** All project paths and phase evidence.
- **Owner/date:** User, 2026-10-17.

### D-001 — Durable events

- **Choice:** Use a PostgreSQL transactional outbox as the authoritative event
  record and Redis Streams for delivery/replay.
- **Rationale:** State and event intent commit atomically; Streams provide
  consumer groups, replay, retry, and dead-letter workflows.
- **Consequences:** Requires outbox publisher, processed-event records, retry
  policy, and reconciliation. Redis is not the canonical state store.
- **Affected modules:** `canonical-state`, `event-reliability`, all consumers.
- **Tests/migrations:** Unique event IDs, commit-before-publish, duplicate,
  retry, dead-letter, and reconciliation tests; outbox tables in migrations.
- **Owner/date:** User, 2026-10-17.

### D-002 — Readiness unknowns

- **Choice:** Represent zero-denominator components as `unknown`, expose
  coverage and missingness, and do not present a precise aggregate score until
  the approved aggregation policy can be applied.
- **Rationale:** Avoids silently converting missing evidence into zero risk.
- **Consequences:** The API/dashboard must expose partial coverage and status;
  readiness consumers must handle an unavailable precise score.
- **Affected modules:** `readiness-scoring`, `operator-surface`, `canonical-state`.
- **Tests/migrations:** Zero-denominator, missing-component, coverage, and
  deterministic score tests; snapshot missingness fields.
- **Owner/date:** User, 2026-10-17.

### D-003 — Authentication lifetimes and boundaries

- **Choice:** Dashboard secure session lifetime 8 hours; control API bearer
  token lifetime 1 hour; Guard API keys require rotation and expiry. Keep
  dashboard sessions, API bearer tokens, and Guard keys separate.
- **Rationale:** Limits exposure while fitting an operator workflow.
- **Consequences:** Token refresh/revocation and Guard-key rotation contracts
  are required; exact refresh mechanism remains implementation detail within
  this boundary.
- **Affected modules:** `identity-access`, `operator-surface`, `guard-boundary`.
- **Tests/migrations:** Negative auth/RBAC tests, expiry/revocation tests, key
  hash/rotation tests, secure-cookie checks.
- **Owner/date:** User, 2026-10-17.

### D-004 — Audit and retention

- **Choice:** Store minimal Guard audit metadata, never raw prompts/responses by
  default, retain operational metadata for 30 days, and use the SQLite
  hash-chain design with protected file access and verification.
- **Rationale:** Minimizes sensitive-data exposure while retaining short-term
  operational evidence.
- **Consequences:** Retention/deletion jobs and protected checkpoint/export
  handling are required; compliance review may change the period later.
- **Affected modules:** `guard-boundary`, `canonical-state`, deployment.
- **Tests/migrations:** Redaction/minimization, retention, hash-chain tamper,
  startup verification, and audit-write failure tests.
- **Owner/date:** User, 2026-10-17.

### D-005 — Guard failure policy

- **Choice:** Fail closed when the shared rate limiter or mandatory audit write
  is unavailable; semantic-model absence is visible `DEGRADED` with the
  approved fallback policy; configured upstream failure returns 502.
- **Rationale:** Guard protects a security boundary; silent bypass is not an
  acceptable default.
- **Consequences:** Availability may be reduced during dependency failure;
  health/readiness endpoints and alerts must make the state visible.
- **Affected modules:** `guard-boundary`, `event-reliability`, deployment.
- **Tests/migrations:** Limiter outage, audit failure, model absence, upstream
  timeout, and compatible error-envelope tests.
- **Owner/date:** User, 2026-10-17.

### D-006 — Authorized scan scopes

- **Choice:** Canonical `Scope` records contain normalized targets, owner,
  approved scanner profile, approval evidence, expiry, and status. Scope is
  validated before queueing and execution.
- **Rationale:** Authorization must be enforced in code, not inferred from
  prompts or operator intent.
- **Consequences:** Recon cannot accept arbitrary targets or scanner flags;
  expired scopes fail visibly and all scan runs retain scope provenance.
- **Affected modules:** `recon-boundary`, `identity-access`, `canonical-state`.
- **Tests/migrations:** Out-of-scope, expired-scope, profile, cancellation,
  timeout, and provenance tests.
- **Owner/date:** User, 2026-10-17.

### D-007 — Compose profiles and exposure

- **Choice:** Provide `core`, `full`, and `dev` profiles. PostgreSQL and
  Valkey remain private to the Compose network. Ollama is optional and enabled
  only in the full profile.
- **Rationale:** Supports a usable low-resource profile while keeping optional
  model workloads explicit.
- **Consequences:** Health checks, resource limits, profile-specific
  configuration, and degraded behavior are required.
- **Affected modules:** `deployment-profiles`, all runtime services.
- **Tests/migrations:** Compose config checks for each profile, network exposure
  checks, startup/health checks, and resource measurement in Phase 15.
- **Owner/date:** User, 2026-10-17.
