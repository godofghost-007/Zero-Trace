# Implementation Plan: ZeroTrace Phase 1–2 Foundation

## Overview

Phase 1 converted the approved capability map and architecture specification
into an implementation-ready contract. Phase 2 now establishes the smallest
runnable application foundation: validated settings, consistent error and
logging primitives, health/readiness reporting, and a disposable PostgreSQL
migration path. Feature modules remain out of scope.

**Approved specification:** [SPEC-phase-01-architecture.md](../docs/SPEC-phase-01-architecture.md)  
**Capability map:** [CAPABILITY_MAP.md](../docs/CAPABILITY_MAP.md)  
**Task tracker:** [tasks/todo.md](./todo.md)

## Architecture decisions

The specification recommends, but does not silently select:

- PostgreSQL transactional outbox plus a Redis-compatible delivery mechanism.
- Explicit score coverage and `unknown` components for zero denominators.
- Separate dashboard session, control API bearer, and Guard API-key boundaries.
- Visible degraded behavior for missing models, audit failures, limiter outages,
  stale feeds, scanner failures, and upstream failures.
- Authorized, expiring scan scopes with fixed scanner profiles.
- Core/full/dev deployment profiles with private data services.

Each recommendation requires human approval before dependent implementation.

## Phase 1 task list

### Decision gate

1. **P1-DECISIONS:** Close the durable-event, score-missingness, auth/key
   lifecycle, Guard failure, retention, scan-scope, and Compose-profile
   decisions.
   - **Acceptance:** Each decision has a selected option, rationale,
     consequences, owner/date, affected contracts, and test/migration impact.
   - **Verify:** Review the updated decision register against all open items.
   - **Files:** `copilot-zerotrace-loop/.../docs/DECISIONS.md`,
     `docs/SPEC-phase-01-architecture.md`
   - **Dependencies:** None
   - **Scope:** Medium

### Contract lock

2. **P1-CONTRACTS:** Reconcile the approved decisions into the service,
   entity, API, event, auth, score, and security contracts.
   - **Acceptance:** No contract contradicts the decision register; all
     versioning, error, pagination, idempotency, event, and missingness rules
     are explicit.
   - **Verify:** `git diff --check`; manual contract review against the Phase 1
     gate.
   - **Files:** `docs/SPEC-phase-01-architecture.md`,
     `docs/CAPABILITY_MAP.md`, approved ADR/decision files
   - **Dependencies:** P1-DECISIONS
   - **Scope:** Medium

3. **P1-SECURITY-BOUNDARIES:** Record the threat-boundary and data-handling
   decisions as enforceable design constraints.
   - **Acceptance:** Every external boundary has validation, authorization,
     logging/privacy, rate/size/timeout, and failure behavior; no secret or
     raw-sensitive-data path is unspecified.
   - **Verify:** Security review checklist against the approved specification.
   - **Files:** `docs/SPEC-phase-01-architecture.md`,
     `CONSTRAINTS.md`, approved security ADR if needed
   - **Dependencies:** P1-DECISIONS
   - **Scope:** Medium

### Evidence and phase exit

4. **P1-EVIDENCE:** Run documentation and repository checks and prepare the
   Phase 1 exit record.
   - **Acceptance:** Phase gate criteria are marked PASS/FAIL/BLOCKED with exact
     evidence; unresolved decisions block dependent work rather than being
     assumed.
   - **Verify:** `py -m unittest discover -s tests -v`,
     `docker compose -f compose.yaml config --quiet`, and `git diff --check`.
   - **Files:** `tasks/evidence/phase-01.md`, `tasks/todo.md`
   - **Dependencies:** P1-CONTRACTS, P1-SECURITY-BOUNDARIES
   - **Scope:** Small

## Checkpoint: Phase 1 architecture lock

- [ ] All open Phase 1 decisions are closed or explicitly block dependent work.
- [ ] Capability map and architecture specification agree.
- [ ] Service, entity, API, event, auth, score, and security contracts are
      internally consistent.
- [ ] Evidence record contains exact commands, results, risks, and human signoff.
- [x] Human approved the Phase 1 exit before Phase 2 work began.

## Phase 2 task list

### Foundation slice

5. **P2-CONFIG-ERRORS:** Add typed application settings, structured
   configuration errors, logging setup, and health/readiness state.
   - **Acceptance:** Missing required settings fail with named errors; health
     reports liveness separately from dependency readiness; logs use a stable
     non-secret format.
   - **Verify:** Focused unittest module and `py -m app`.
   - **Files:** `app/settings.py`, `app/errors.py`, `app/logging_config.py`,
     `app/health.py`, `app/__main__.py`, `tests/test_core_foundation.py`
   - **Dependencies:** Phase 1 approval
   - **Scope:** Medium

### Persistence slice

6. **P2-MIGRATIONS:** Add the initial PostgreSQL migration and a bounded,
   non-interactive migration runner.
   - **Acceptance:** A disposable PostgreSQL instance can apply the migration
     once and report its schema version; a second run is idempotent; connection
     failures are explicit.
   - **Verify:** `scripts/run_migrations.py` against the disposable Compose
     database and migration unittest coverage.
   - **Files:** `migrations/0001_foundation.sql`, `scripts/run_migrations.py`,
     `compose.yaml`, `pyproject.toml`, `tests/test_migrations.py`
   - **Dependencies:** P2-CONFIG-ERRORS
   - **Scope:** Medium

### Phase exit

7. **P2-EVIDENCE:** Run the application, migration, test, Compose, and diff
   checks; record Phase 2 evidence.
   - **Acceptance:** Every Phase 2 gate criterion has exact evidence or is
     explicitly BLOCKED; no feature module is implied complete.
   - **Verify:** Full unittest discovery, app startup check, migration run,
     Compose config, and `git diff --check`.
   - **Files:** `tasks/evidence/phase-02.md`, `tasks/todo.md`, `README.md`
   - **Dependencies:** P2-CONFIG-ERRORS, P2-MIGRATIONS
   - **Scope:** Small

## Checkpoint: Phase 2 skeleton/core domain

- [x] App starts with a health response.
- [x] Invalid required configuration fails clearly.
- [x] Disposable PostgreSQL migration applies idempotently.
- [x] Domain/error/logging/health tests pass.
- [x] Reproducible setup commands are documented.
- [ ] Human approves the Phase 2 exit before Phase 3 work begins.

## Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Durable-event choice changes persistence and worker design | High | Close the decision before schema or worker implementation |
| Unknown score semantics produce misleading readiness | High | Store coverage/missingness and require explicit display/aggregation policy |
| Auth/key lifecycle is underspecified | High | Keep all protected surfaces separate and require negative tests |
| Scan authorization is treated as prompt guidance | Critical | Represent scope and approval as canonical state enforced in code |
| Retention expands sensitive-data exposure | High | Minimize raw data and approve retention/deletion before persistence |
| Compose profiles exceed laptop resources | Medium | Make optional services explicit and measure in Phase 15 |

## Phase 1 out of scope

- Application source code.
- Database migrations.
- Scanner, feed, model, or proxy implementation.
- Dependency additions.
- Network scans or external target access.
- Production deployment or remediation.

## Phase 2 out of scope

- Recon, Intel, Guard, authentication, event consumers, readiness scoring,
  dashboard behavior, external feeds, scanners, model inference, and
  production deployment.

## Phase 3 — Readiness score

Phase 2 has been approved for transition. Phase 3 implements only the
deterministic readiness-score contract already recorded in the architecture
specification and decision register. It does not add persistence, API routes,
scanners, external feeds, or production data access.

### Score contract

- Formula version: `readiness-v1`.
- `AEI` is exposed services divided by total services, expressed as a
  percentage.
- `VUI` is the sum of per-asset exploit-probability × normalized-CVSS impact
  values divided by total assets, expressed as a percentage. CVSS is
  normalized from the 0–10 scale to 0–1.
- `AIET` is unblocked attack attempts divided by total LLM requests, expressed
  as a percentage.
- A zero denominator produces an `unknown` component and is excluded from the
  aggregate; no precise aggregate score is returned unless all components are
  known.
- The aggregate is `clamp(100 - (0.40 × AEI + 0.40 × VUI + 0.20 × AIET), 0, 100)`.
- Score bands are Secure (90–100), Moderate (70–89), Elevated (50–69), and
  Critical (0–49).

### Phase 3 task list

1. **P3-SCORE-CONTRACT:** Implement typed, deterministic component and
   aggregate calculations with explicit unknown/coverage state.
   - **Acceptance:** Inputs are validated; known components stay within
     0–100; zero denominators are unknown; complete results include formula
     version and score band; incomplete results do not expose a precise score.
   - **Verify:** Focused readiness unit tests and full unittest discovery.
   - **Files:** `app/readiness.py`, `tests/test_readiness.py`
   - **Dependencies:** Phase 2 approval
   - **Scope:** Medium

2. **P3-SCENARIOS:** Add independently calculated synthetic fixtures covering
   bounds, monotonicity, unknown denominators, recovery, reproducibility, and
   the documented combined-case discrepancy.
   - **Acceptance:** The `(20, 35, 25)` fixture evaluates to 73; adverse
     exposure lowers readiness; recovery improves it; repeated calculation is
     identical; fixture data contains no real targets or customer data.
   - **Verify:** `py -m unittest tests.test_readiness -v`.
   - **Files:** `tests/test_readiness.py`, `docs/SPEC-phase-01-architecture.md`
   - **Dependencies:** P3-SCORE-CONTRACT
   - **Scope:** Medium

3. **P3-EVIDENCE:** Record exact Phase 3 checks and update the tracker.
   - **Acceptance:** All Phase 3 gate criteria have reproducible evidence and
     unresolved limitations are explicit; no migration changes are required.
   - **Verify:** Full unittest, compileall, Compose config, and diff checks.
   - **Files:** `tasks/evidence/phase-03.md`, `tasks/todo.md`, `README.md`
   - **Dependencies:** P3-SCORE-CONTRACT, P3-SCENARIOS
   - **Scope:** Small

### Phase 3 risks

| Risk | Impact | Mitigation |
|---|---|---|
| VUI units are ambiguous in source material | High | Freeze CVSS 0–10 to 0–1 normalization and test it |
| Missing evidence could look like zero risk | High | Return explicit unknown components and no precise aggregate |
| Source fixture prints 71 for `(20,35,25)` | Medium | Treat the governing equation as authoritative; record 73 |

## Phase 4 — Auth and platform security

Phase 3 was reviewed and approved for transition on 2026-10-17. Phase 4 adds
security primitives without introducing external services, real credentials,
or database schema changes. Existing health, readiness, migration, and score
behavior must remain compatible.

### Phase 4 task list

1. **P4-AUTH-PRIMITIVES:** Implement password hashing, API-key verification,
   secret loading, and explicit role authorization.
   - **Acceptance:** Passwords are scrypt-hashed with per-password salts and
     constant-time verification; API keys are never stored or logged in
     plaintext; missing/weak secrets fail closed; unauthenticated and
     role-negative authorization tests pass.
   - **Verify:** Focused security unit tests and full unittest discovery.
   - **Files:** `app/security.py`, `tests/test_security.py`, `app/settings.py`
   - **Dependencies:** Phase 3 approval
   - **Scope:** Medium

2. **P4-BOUNDARY-CONTROLS:** Add CSRF validation, request-size limits, and
   security response headers while preserving current health endpoints.
   - **Acceptance:** CSRF tokens are bound to the session secret; oversized
     requests fail before body processing; security headers are present on
     health responses; existing query-string health behavior remains intact.
   - **Verify:** Focused HTTP/security tests and live health request.
   - **Files:** `app/security.py`, `app/__main__.py`, `tests/test_core_foundation.py`,
     `tests/test_security.py`
   - **Dependencies:** P4-AUTH-PRIMITIVES
   - **Scope:** Medium

3. **P4-EVIDENCE:** Record Phase 4 evidence and update project status.
   - **Acceptance:** Auth, CSRF, headers, size, secret, network, audit, and
     secret-hygiene checks have exact evidence; unresolved limitations are
     explicit; migrations remain unchanged.
   - **Verify:** Full unittest, compileall, Compose config, diff check, and
     secret-pattern review.
   - **Files:** `tasks/evidence/phase-04.md`, `tasks/todo.md`, `README.md`,
     `.env.example`
   - **Dependencies:** P4-AUTH-PRIMITIVES, P4-BOUNDARY-CONTROLS
   - **Scope:** Small

### Phase 4 risks

| Risk | Impact | Mitigation |
|---|---|---|
| Authentication primitives are not yet wired to a persistent user store | High | Keep fail-closed primitives isolated; defer persistence until approved schema work |
| API key rotation/revocation needs canonical state | High | Expose verification contract only; do not invent in-memory production state |
| HTTPServer is a foundation server, not a complete API framework | Medium | Test headers and limits at the existing boundary; avoid adding unapproved routes |

## Phase 5 — Event and persistence reliability

Phase 4 was reviewed and approved for transition on 2026-10-17. Phase 5
implements the event envelope and delivery state machine against the existing
PostgreSQL outbox contract. The first slice is dependency-free and uses an
in-memory repository as a deterministic test double; it does not pretend that
an in-memory test is proof of PostgreSQL availability.

### Phase 5 task list

1. **P5-EVENT-CONTRACT:** Add a validated versioned event envelope and an
   outbox state model aligned with migrations `0001_foundation` and
   `0002_event_reliability`.
   - **Acceptance:** Required identifiers/types are validated; payloads are
     bounded JSON-like data; secrets/raw prompts are rejected; invalid state
     transitions fail explicitly.
   - **Verify:** Focused event contract tests.
   - **Files:** `app/events.py`, `tests/test_events.py`
   - **Dependencies:** Phase 4 approval
   - **Scope:** Medium

2. **P5-DELIVERY:** Implement commit-before-publish, idempotent consumer
   processing, retry/backoff, dead-letter, and reconciliation behavior.
   - **Acceptance:** Publish cannot occur before durable commit; duplicate
     events are no-ops; retry delay is bounded and deterministic; exhausted
     events become dead letters with a reason; reconciliation returns pending
     and stale processing records without silent success.
   - **Verify:** Focused delivery tests and full unittest discovery.
   - **Files:** `app/events.py`, `tests/test_events.py`
   - **Dependencies:** P5-EVENT-CONTRACT
   - **Scope:** Medium

3. **P5-EVIDENCE:** Record Phase 5 evidence and update project status.
   - **Acceptance:** Event envelope/version, durability, idempotence, retry,
     dead-letter, reconciliation, and duplicate/failure checks have exact
     evidence; PostgreSQL integration limitations are explicit.
   - **Verify:** Full unittest, compileall, Compose config, migration contract,
     and diff checks.
   - **Files:** `tasks/evidence/phase-05.md`, `tasks/todo.md`, `README.md`
   - **Dependencies:** P5-EVENT-CONTRACT, P5-DELIVERY
   - **Scope:** Small

### Phase 5 risks

| Risk | Impact | Mitigation |
|---|---|---|
| In-memory tests cannot prove PostgreSQL transaction behavior | High | Keep repository interface explicit and record live DB integration as a separate verification requirement |
| Publisher crash windows can leave processing records stale | High | Reconciliation exposes stale processing records for safe reclaim |
| Consumer side effects may not be naturally idempotent | High | Durable processed-event claim is required before acknowledging a duplicate |

## Phase 6 — Recon MVP

Phase 5 was reviewed and approved for transition on 2026-10-17. Phase 6
implements the approved `recon-boundary` capability with fixed real-tool
adapters, injected fakes for deterministic tests, and read-only S3 checks.
Execution is limited to approved synthetic or isolated-lab scopes.

### Phase 6 task list

1. **P6-CONTRACTS:** Implement validated scopes, fixed profiles, normalized
   observations, lifecycle states, and bounded execution contracts.
   - **Acceptance:** Expired/out-of-scope targets and unknown profiles are
     rejected; targets, output, result, rate, and concurrency limits are
     explicit; lifecycle states preserve partial and failed outcomes.
   - **Verify:** Focused recon contract tests.
   - **Files:** `app/recon.py`, `tests/test_recon.py`
   - **Dependencies:** Phase 5 approval
   - **Scope:** Medium

2. **P6-ADAPTERS:** Add fixed-profile Subfinder, Nmap, TLS, and read-only S3
   adapters with strict parsing and bounded subprocess/network behavior.
   - **Acceptance:** No shell interpolation or caller-controlled flags reach
     execution; malformed output, non-zero exits, timeouts, cancellation,
     certificate failures, and S3 denial/rate-limit states are visible.
   - **Verify:** Synthetic adapter tests and isolated command-parser tests;
     no external targets.
   - **Files:** `app/recon.py`, `tests/test_recon.py`
   - **Dependencies:** P6-CONTRACTS
   - **Scope:** Medium

3. **P6-ORCHESTRATION:** Persist normalized results before appending scan and
   asset events, with idempotent run creation and explicit failure states.
   - **Acceptance:** Results precede events; duplicate requests do not create
     duplicate runs; adapter/persistence/event failures never become success.
   - **Verify:** Focused orchestration tests and full unittest discovery.
   - **Files:** `app/recon.py`, `tests/test_recon.py`
   - **Dependencies:** P6-ADAPTERS
   - **Scope:** Medium

4. **P6-EVIDENCE:** Record exact Phase 6 evidence, risks, and remaining live
   PostgreSQL/real-lab integration limitations.
   - **Acceptance:** All gate criteria have PASS/BLOCKED evidence, command
     output is recorded, no external targets were scanned, and Phase 7 is not
     authorized until human signoff.
   - **Verify:** Full unittest, compileall, Compose config, migration contract,
     and diff checks.
   - **Files:** `tasks/evidence/phase-06.md`, `tasks/todo.md`, `README.md`
   - **Dependencies:** P6-CONTRACTS, P6-ADAPTERS, P6-ORCHESTRATION
   - **Scope:** Small

### Phase 6 risks

| Risk | Impact | Mitigation |
|---|---|---|
| Real scanner binaries may be absent or differ by platform | High | Fixed adapter contracts, explicit degraded state, injected fakes, and isolated-lab integration as a separate check |
| Scope validation may be bypassed before process/network access | Critical | Validate scope/profile/target before adapter invocation and test negative paths |
| Untrusted scanner output may cause parser/resource issues | High | Output caps, strict schemas, safe XML parsing, field limits, and partial failure states |
| In-memory persistence does not prove PostgreSQL transaction behavior | High | Preserve repository boundary and record live integration as a blocked follow-up |
| S3 credentials or destructive operations could leak into Recon | Critical | Read-only adapter contract, no write/delete methods, and no credentials in scan payloads |

### Phase 6 operational integration tasks

5. **P6-DB:** Add the forward-only Recon PostgreSQL schema and repository.
   - **Acceptance:** Scope, run, asset, service, observation, and idempotency
     state use parameterized queries; canonical writes and outbox insertion
     share one transaction; duplicate keys with changed hashes are rejected.
   - **Verify:** Migration contract tests and disposable PostgreSQL tests when
     the service is available.
   - **Files:** `migrations/0003_recon.sql`, `app/recon_pg.py`,
     `tests/test_recon_persistence.py`
   - **Dependencies:** P6-CONTRACTS
   - **Scope:** Medium

6. **P6-API:** Add FastAPI Recon routes with auth/RBAC, structured errors,
   idempotency, and polling/cancellation contracts.
   - **Acceptance:** Viewer is read-only; Operator is required for mutations;
     scope ownership is enforced; request limits and generic error envelopes
     are visible.
   - **Verify:** API tests with synthetic repository and queued worker.
   - **Files:** `app/api.py`, `tests/test_recon_api.py`, `pyproject.toml`
   - **Dependencies:** P6-DB, P4 security primitives
   - **Scope:** Medium

7. **P6-LAB:** Execute real tools only against an explicitly authorized lab.
   - **Acceptance:** Tool path/version, process group, timeout, cancellation,
     parser, and partial-failure behavior are evidenced.
   - **Verify:** Human-supplied local/lab authorization and exact run evidence.
   - **Files:** `tasks/evidence/phase-06.md`
   - **Dependencies:** P6-API
   - **Scope:** Small

8. **P6-EVIDENCE-REOPEN:** Re-run full verification and update the phase gate.
   - **Acceptance:** Operational evidence is complete or blocked explicitly;
     S3 deferral and missing lab authorization remain visible.
   - **Verify:** Full unittest, compileall, Compose config, migration, and diff checks.
   - **Files:** `tasks/evidence/phase-06.md`, `tasks/todo.md`, `README.md`
   - **Dependencies:** P6-DB, P6-API, P6-LAB
   - **Scope:** Small

## Scope authorization verification slice

The next implementation slice adds proof-of-control before any real Recon
execution. It is independent of Intel and must remain synthetic in tests.

1. **P6-AUTH-SPEC:** Approve the scope-authorization contract.
   - **Acceptance:** Domain challenge, explicit lab authorization, threat model,
     expiry, replay, owner, profile, and no-SSRF boundaries are recorded.
   - **Verify:** Human reviews `docs/SPEC-scope-authorization.md`.
   - **Files:** `docs/SPEC-scope-authorization.md`
   - **Dependencies:** P6 human signoff
   - **Scope:** Small

## Phase 7 — Intel boundary

Phase 7 implements the approved Intel specification in independently
verifiable vertical slices. Production feeds remain deferred until synthetic
and disposable PostgreSQL verification passes.

### Architecture decisions

- Feed adapters use fixed configured NVD, EPSS, and CISA KEV endpoints.
- Network transport is injected in tests, bounded by timeout/body limits, and
  rejects redirects.
- Intel facts store provenance and digests rather than unrestricted raw feeds.
- Matching is exact CPE first, then exact vendor/product with compatible
  version evidence; ambiguous matches remain unmatched.
- Initial priority formula `intel-priority-v1`:
  `100 * confidence * (0.35 * cvss + 0.30 * epss + 0.25 * kev + 0.10 * exposure)`.
  Missing CVSS/EPSS/KEV components are omitted from the numerator and the
  available-weight denominator is renormalized; missingness remains explicit.
  `cvss` is CVSS/10, `epss` is `[0,1]`, `kev` is `1` or `0`, and `exposure`
  is `1` for an exposed service and `0` otherwise.
- API ingestion is operator-only and idempotent; findings are paginated and
  scope-filtered for viewers/operators.
- External feed access is disabled in automated verification; live provider
  access requires a separate operational approval.

### Task list

1. **P7-MODEL:** Implement typed vulnerability facts, provenance, CPE
   normalization, freshness, and the frozen priority formula.
   - **Acceptance:** Invalid identities/ranges fail; missingness is explicit;
     priority is bounded, explainable, and monotonic.
   - **Verify:** `py -m unittest tests.test_intel -v`
   - **Files:** `app/intel.py`, `tests/test_intel.py`
   - **Dependencies:** Phase 6 approval
   - **Scope:** Medium

2. **P7-FEEDS:** Implement fixed NVD/EPSS/KEV parsers and bounded transport.
   - **Acceptance:** Untrusted fixtures are strictly validated; redirects,
     oversized responses, malformed records, and out-of-range values fail
     visibly; revisions are idempotent.
   - **Verify:** Focused feed tests with injected transport.
   - **Files:** `app/intel_feeds.py`, `tests/test_intel.py`
   - **Dependencies:** P7-MODEL
   - **Scope:** Medium

3. **P7-DB:** Add the forward-only Intel schema and parameterized repository.
   - **Acceptance:** Facts, revisions, provenance, ingestion state, and
     findings persist transactionally with outbox insertion.
   - **Verify:** Migration contract and repository tests.
   - **Files:** `migrations/0004_intel.sql`, `app/intel_pg.py`,
     `tests/test_intel_persistence.py`, `tests/test_migrations.py`
   - **Dependencies:** P7-MODEL, P7-FEEDS
   - **Scope:** Medium

4. **P7-CORRELATION:** Implement deterministic service-to-CVE matching and
   finding generation.
   - **Acceptance:** Exact matches succeed with evidence; ambiguous and
     incomplete matches remain unmatched; freshness and formula metadata are
     preserved.
   - **Verify:** Synthetic correlation and monotonicity tests.
   - **Files:** `app/intel.py`, `tests/test_intel.py`
   - **Dependencies:** P7-MODEL, P7-DB
   - **Scope:** Medium

5. **P7-API:** Add ingestion-status and paginated findings routes with RBAC.
   - **Acceptance:** Operators ingest only allowlisted sources; viewers read
     only authorized scopes; idempotency conflicts and generic errors follow
     the existing API contract.
   - **Verify:** `py -m unittest tests.test_intel_api -v`
   - **Files:** `app/intel_api.py`, `tests/test_intel_api.py`
   - **Dependencies:** P7-CORRELATION
   - **Scope:** Medium

6. **P7-EVIDENCE:** Run integrated Phase 0–7 verification and record the
   evidence gate.
   - **Acceptance:** Full regression, compile, Compose, migration contract,
     dependency review, and diff checks pass; production feed access remains
     explicitly deferred.
   - **Verify:** Full repository commands below.
   - **Files:** `tasks/evidence/phase-07.md`, `tasks/todo.md`, `README.md`
   - **Dependencies:** P7-API
   - **Scope:** Small

### Phase 7 verification commands

```powershell
py -m unittest discover -s tests -v
py -m compileall -q app scripts
docker compose --profile core config --quiet
docker compose --profile full config --quiet
docker compose --profile dev config --quiet
git diff --check
```

### Phase 7 risks

| Risk | Impact | Mitigation |
|---|---|---|
| Malformed or adversarial feed data | Critical | Strict schemas, bounds, caps, provenance, no execution |
| False positive service matching | High | Exact evidence, ambiguity rejection, confidence metadata |
| Stale vulnerability facts | High | Per-source freshness state and visible degraded ingestion |
| Duplicate feed revisions | Medium | Source/revision uniqueness and idempotent ingestion |
| Feed provider outage | Medium | Bounded retries, last-known facts, explicit degraded state |
| Priority formula drift | High | Versioned equation, monotonicity tests, human approval |

### Open questions

- Confirm the proposed `intel-priority-v1` weights before implementation.
- Confirm whether production feed access remains deferred after Phase 7 tests.

2. **P6-AUTH-CONTRACT:** Implement challenge creation and synthetic DNS
   verification.
   - **Acceptance:** Normalized domains, bounded single-use challenges,
     generic failures, and explicit lab records are enforced.
   - **Verify:** Focused `unittest` suite with injected resolver fixtures.
   - **Files:** `app/recon_authorization.py`,
     `tests/test_scope_authorization.py`
   - **Dependencies:** P6-AUTH-SPEC
   - **Scope:** Medium

3. **P6-AUTH-INTEGRATION:** Require an active authorization at the Recon API
   boundary.
   - **Acceptance:** Owner, target, profile, environment, and expiry are
     checked before queueing; failed checks invoke no adapter.
   - **Verify:** Focused API tests and full regression.
   - **Files:** `app/recon_api.py`, `tests/test_recon_api.py`
   - **Dependencies:** P6-AUTH-CONTRACT
   - **Scope:** Medium

4. **P6-AUTH-EVIDENCE:** Record exact verification and remaining production
   DNS/lab limitations.
   - **Acceptance:** No public target is contacted; commands and results are
     recorded; live execution remains gated until separately authorized.
   - **Verify:** Full unittest, compileall, Compose config, and diff checks.
   - **Files:** `tasks/evidence/phase-06.md`, `tasks/todo.md`, `README.md`
   - **Dependencies:** P6-AUTH-INTEGRATION
   - **Scope:** Small

## Phase 0–7 completion hardening

This follow-up closes requirements identified by comparing the authoritative
project documentation with the current phase gates. It does not claim
completion of Phases 8–18.

### Contract and acceptance criteria

1. **P5-RUNTIME:** Provide a real PostgreSQL outbox repository and a
   Redis/Valkey Streams publisher/consumer boundary, with restart, retry,
   duplicate, and dead-letter tests using disposable local services.
2. **P6-SAFETY:** Enforce Recon rate/concurrency limits, bounded retry behavior,
   DNS resolution gates, inventory-delta observations, and explicit raw-output
   provenance without enabling destructive operations.
3. **P7-OPERATIONS:** Add NVD pagination/incremental checkpoints, conditional
   cache metadata, bounded 429/backoff handling, malformed-record quarantine,
   last-known-good snapshots, merged EPSS/KEV facts, and real paginated finding
   queries with scope isolation.
4. **P0-7-INTEGRATION:** Wire PostgreSQL readiness and a deterministic
   Recon-to-Intel-to-readiness integration harness. Real scanner execution
   remains blocked unless the user supplies an authorized isolated lab target.
5. **P0-7-EVIDENCE:** Update phase evidence to distinguish implemented,
   integration-verified, and authorization-blocked criteria; do not mark a
   gate PASS when its operational prerequisite was not executed.

### Verification commands

```powershell
py -m unittest discover -s tests -v
py -m compileall -q app scripts
docker compose --profile core config --quiet
docker compose --profile full config --quiet
docker compose --profile dev config --quiet
docker compose --profile dev up -d postgres
$env:DATABASE_URL = "postgresql://zerotrace:zerotrace-dev-only@127.0.0.1:5432/zerotrace"
py scripts/run_migrations.py
py scripts/run_migrations.py
git diff --check
```

### Risks and human gates

- Live Recon requires an exact authorized isolated-lab target, ownership or
  authorization evidence, profile, and expiry; no arbitrary public URL will be
  scanned.
- Live NVD/EPSS/KEV retrieval is read-only but requires explicit outbound
  network approval and will not be part of unit tests.
- Redis/Valkey and PostgreSQL execution may require Docker availability; if a
  service cannot run, the evidence must say BLOCKED rather than PASS.
- XGBoost evaluation, Guard, dashboard, remediation, and release performance
  remain later project phases and are not silently pulled into this scope.

## Phase 8 — Correlation completeness

The approved Phase 8 contract is recorded in
[SPEC-phase-08-correlation.md](../docs/SPEC-phase-08-correlation.md).

### Entry gate

- Phase 6 and Phase 7 evidence reviewed by a human.
- Phase 0–7 completion hardening is either complete or explicitly marked
  BLOCKED with an owner and next action.
- No live Recon execution is authorized by this specification.

### Phase 8 tasks

1. Add uncertain-match records and deterministic correlation coverage.
2. Persist and expose scope-isolated correlation evidence.
3. Verify pagination, provenance, freshness, and negative cases.
4. Record Phase 8 evidence and human signoff.

## Phase 14 — Integration and End-to-End Validation

Entry gate: Phase 13 signed off. Implementation authorized 2026-10-21.

Acceptance criteria:

1. A deterministic synthetic flow covers Recon → Intel → Guard → readiness →
   remediation proposal → verification.
2. Duplicate scan/idempotency, bounded retry, restart persistence, Guard
   upstream outage, partial Recon failure, proposal tamper detection, and
   missing optional inputs are exercised.
3. Failures are visible as error envelopes, partial states, or unknown
   readiness components; they are never reported as empty success or zero.
4. Evidence records exact commands, results, and exceptions.

Evidence: [phase-14.md](evidence/phase-14.md).

## Phase 15 — Resource and Reliability

Entry gate: Phase 14 evidence recorded. Implementation authorized 2026-10-21.

Acceptance criteria:

1. Cold start, peak/per-service memory, CPU, Guard latency, concurrent Recon/
   Guard/Intel activity, SQLite query latency/size, swap, and host headroom are
   measured on the target laptop.
2. `core`, `full`, and `dev` profile budgets are recorded; optional Ollama
   absence is reported as degraded, not zero.
3. Measurements and exceptions are reproducible with
   `python -m scripts.performance_report`.
4. The full-profile 9 GB target is not claimed as proven without a measured
   model-stack run.

Evidence: [phase-15.md](evidence/phase-15.md).
