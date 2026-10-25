# ZeroTrace Task Tracker

## Completed

| ID | Phase | Task | Status |
|---|---|---|---|
| P0-ENV-BASELINE | 0 | Review baseline files and record environment evidence | Verified |
| P0-DOCKER-BASELINE | 0 | Recheck Docker daemon availability | Verified |
| P0-DATA-POLICY | 0 | Decide what project data may be sent to hosted Copilot | Verified |
| P0-WORKTREE-BASELINE | 0 | Review and approve the pre-existing dirty worktree state | Verified |

## Phase 1 — Specification and architecture lock

| ID | Task | Status | Dependencies |
|---|---|---|---|
| P1-DECISIONS | Close durable events, score missingness, auth/key lifecycle, Guard failure, retention, scan scope, and Compose profile decisions | Verified | None |
| P1-CONTRACTS | Reconcile approved decisions into service, entity, API, event, auth, score, and security contracts | Verified | P1-DECISIONS |
| P1-SECURITY-BOUNDARIES | Record enforceable trust, validation, privacy, and failure boundaries | Verified | P1-DECISIONS |
| P1-EVIDENCE | Run checks and prepare Phase 1 exit evidence | Verified | P1-CONTRACTS, P1-SECURITY-BOUNDARIES |

## Checkpoint: Phase 1 architecture lock

- [x] All Phase 1 decisions are closed or explicitly block dependent work.
- [x] Contracts are internally consistent.
- [x] Phase 1 evidence is reviewed and human-signed.

## Phase 2 — Skeleton and core domain

| ID | Task | Status | Dependencies |
|---|---|---|---|
| P2-CONFIG-ERRORS | Add settings, errors, logging, health, and startup entrypoint | Verified | Phase 1 |
| P2-MIGRATIONS | Add PostgreSQL foundation migration and runner | Verified | P2-CONFIG-ERRORS |
| P2-EVIDENCE | Run Phase 2 checks and record exit evidence | Verified | P2-CONFIG-ERRORS, P2-MIGRATIONS |

## Checkpoint: Phase 2 skeleton/core domain

- [x] App starts with health response.
- [x] Invalid configuration fails clearly.
- [x] Disposable migration applies idempotently.
- [x] Foundation tests pass.
- [x] Phase 2 evidence is reviewed and human-signed.

## Phase 3 — Readiness score

| ID | Task | Status | Dependencies |
|---|---|---|---|
| P3-SCORE-CONTRACT | Implement versioned deterministic AEI/VUI/AIET calculations and explicit unknown state | Verified | Phase 2 approval |
| P3-SCENARIOS | Add synthetic bounds, monotonicity, unknown, recovery, reproducibility, and discrepancy fixtures | Verified | P3-SCORE-CONTRACT |
| P3-EVIDENCE | Record Phase 3 evidence and update project status | Verified | P3-SCORE-CONTRACT, P3-SCENARIOS |

## Checkpoint: Phase 3 readiness score

- [x] Formula and component definitions are frozen and versioned.
- [x] Synthetic scenario calculations and discrepancy resolution are recorded.
- [x] All Phase 3 tests and repository checks pass.
- [x] Human reviews and signs Phase 3 evidence before Phase 4.

## Phase 4 — Auth and platform security

| ID | Task | Status | Dependencies |
|---|---|---|---|
| P4-AUTH-PRIMITIVES | Implement password/API-key primitives, secret loading, and role authorization | Verified | Phase 3 approval |
| P4-BOUNDARY-CONTROLS | Add CSRF, request-size, and security-header controls | Verified | P4-AUTH-PRIMITIVES |
| P4-EVIDENCE | Record Phase 4 evidence and update project status | Verified | P4-AUTH-PRIMITIVES, P4-BOUNDARY-CONTROLS |

## Checkpoint: Phase 4 auth/platform security

- [x] Unauthenticated and role-negative tests pass.
- [x] Password/API-key handling, CSRF, headers, size limits, and secret loading are tested.
- [x] Private service networking and audit permissions are evidenced.
- [x] Secret hygiene and full repository checks pass.
- [x] Human reviews and signs Phase 4 evidence before Phase 5.

## Phase 5 — Event and persistence reliability

| ID | Task | Status | Dependencies |
|---|---|---|---|
| P5-EVENT-CONTRACT | Implement validated event envelope and outbox state model | Verified | Phase 4 approval |
| P5-DELIVERY | Implement commit-before-publish, idempotence, retries, dead letters, and reconciliation | Verified | P5-EVENT-CONTRACT |
| P5-EVIDENCE | Record Phase 5 evidence and update project status | Verified | P5-EVENT-CONTRACT, P5-DELIVERY |

## Checkpoint: Phase 5 event/persistence reliability

- [x] Event envelope/version and durability design are implemented.
- [x] Commit-before-publish, idempotence, retry/backoff, dead-letter, and reconciliation tests pass.
- [x] Duplicate and failure paths do not report silent success.
- [x] Human reviews and signs Phase 5 evidence before Phase 6.

## Phase 6 — Recon MVP

| ID | Task | Status | Dependencies |
|---|---|---|---|
| P6-CONTRACTS | Implement validated scopes, fixed profiles, normalized observations, lifecycle states, and limits | Verified | Phase 5 approval |
| P6-ADAPTERS | Add fixed-profile Subfinder, Nmap, TLS, and read-only S3 adapters | Verified | P6-CONTRACTS |
| P6-ORCHESTRATION | Persist normalized results before appending events and preserve failures | Verified | P6-ADAPTERS |
| P6-EVIDENCE | Record Phase 6 evidence and update project status | Verified | P6-CONTRACTS, P6-ADAPTERS, P6-ORCHESTRATION |
| P6-DB | Add PostgreSQL Recon schema and repository | Verified | P6-CONTRACTS |
| P6-API | Add FastAPI Recon routes and queued polling contract | Verified | P6-DB |
| P6-LAB | Verify real tools only against an authorized isolated lab | blocked | P6-API |
| P6-EVIDENCE-REOPEN | Reopen Phase 6 evidence after operational integration | Verified | P6-DB, P6-API, P6-LAB |

## Checkpoint: Phase 6 Recon MVP

- [x] All Phase 6 focused and regression tests pass.
- [x] Scope, process, network, output, and S3 safety controls are evidenced.
- [x] No external target was scanned.
- [x] PostgreSQL schema/repository and FastAPI route contracts are covered by focused tests.
- [ ] Real scanner execution remains blocked until isolated-lab authorization.
- [ ] Human reviews and signs Phase 6 evidence before Phase 7.

### Scope authorization verification

| ID | Task | Status | Dependencies |
|---|---|---|---|
| P6-AUTH-SPEC | Approve scope-authorization contract | Verified | P6 human signoff |
| P6-AUTH-CONTRACT | Implement challenge and lab authorization contracts | Verified | P6-AUTH-SPEC |
| P6-AUTH-INTEGRATION | Enforce authorization before Recon queueing | Verified | P6-AUTH-CONTRACT |
| P6-AUTH-EVIDENCE | Record authorization verification evidence | Verified | P6-AUTH-INTEGRATION |

## Phase 7 — Intel boundary

| ID | Task | Status | Dependencies |
|---|---|---|---|
| P7-MODEL | Implement Intel facts, provenance, freshness, and priority formula | done | Phase 6 approval |
| P7-FEEDS | Implement bounded NVD/EPSS/KEV feed adapters | done | P7-MODEL |
| P7-DB | Add Intel migration and transactional repository | done | P7-MODEL, P7-FEEDS |
| P7-CORRELATION | Match Recon services to CVEs and generate findings | done | P7-DB |
| P7-API | Add Intel ingestion and findings API routes | done | P7-CORRELATION |
| P7-EVIDENCE | Record Phase 7 evidence and signoff gate | done | P7-API |

### Checkpoint: Phase 7 Intel contract

- [ ] Proposed `intel-priority-v1` formula and weights approved.
- [ ] Production feed access remains deferred unless separately authorized.

## Phase 0–7 completion hardening

| ID | Task | Status | Dependencies |
|---|---|---|---|
| P5-RUNTIME | Wire PostgreSQL outbox and Redis/Valkey Streams runtime contracts | Verified | P5-EVIDENCE |
| P6-SAFETY | Enforce Recon rate/concurrency, retry, DNS-gate, and inventory-delta controls | Verified | P6-API |
| P7-OPERATIONS | Add feed pagination, incremental sync, cache, quarantine, last-known-good, merge, and real pagination | Verified | P7-API |
| P0-7-INTEGRATION | Wire readiness and deterministic Recon-to-Intel integration harness | Verified | P5-RUNTIME, P6-SAFETY, P7-OPERATIONS |
| P0-7-EVIDENCE | Reconcile all phase evidence and record exact operational blockers | Verified | P0-7-INTEGRATION |

### Completion contract

- [x] Phase 0–7 criteria are implemented, not only unit-tested.
- [x] PostgreSQL migrations run twice against a disposable local database, including `0005_recon_inventory`.
- [x] Valkey pending-message recovery and acknowledgement are exercised with a disposable local service; application worker restart tests pass.
- [x] Recon DNS gating and inventory-delta calculation are enforced before active adapter execution and persisted through the PostgreSQL contract.
- [x] Runtime composition creates PostgreSQL Recon/Intel repositories from the configured database URL.
- [x] Recon and Intel API factories accept persistence hooks so production composition can persist successful results before returning.
- [x] Intel ingestion preserves last-known-good data and quarantines malformed records without replacing valid snapshots in the synthetic contract.
- [x] A deterministic Recon-to-Intel-to-readiness integration test passes.
- [ ] Real lab scanning remains blocked unless explicit target authorization is supplied.

### Runtime API completion contract

- Acceptance: one FastAPI composition exposes Recon and Intel routes; asset and finding reads are owner/scope filtered, bounded, deterministic, and backed by PostgreSQL repository methods; existing synthetic factories remain compatible.
- Verification: focused runtime tests, full unittest discovery, compilation, Compose configuration, and `git diff --check`.
- Risk: scanner execution and identity provisioning remain environment-specific gates and cannot be inferred from repository tests.

## Phase 8 entry preparation

| ID | Task | Status | Dependencies |
|---|---|---|---|
| P8-SPEC | Define deterministic correlation completeness contract | done | P0-7-EVIDENCE |
| P8-MATCHING | Add uncertain-match records and negative-case coverage | Verified | P8-SPEC |
| P8-PERSISTENCE | Persist scope-isolated correlation evidence | Verified | P8-MATCHING |
| P8-API | Expose bounded, provenance-bearing correlation results | Verified | P8-PERSISTENCE |
| P8-EVIDENCE | Record Phase 8 evidence and human signoff | Verified | P8-API |

## Phase 9 — Vulnerability Prioritization

| ID | Task | Status | Dependencies |
|---|---|---|---|
| P9-BASELINE | Extend intel-priority-v1 with business criticality input | Verified | P8-EVIDENCE |
| P9-MODEL | Add model/pipeline versioning with artifact checksums | Verified | P9-BASELINE |
| P9-QUEUE | Add 48-hour SLA remediation queue | Verified | P9-MODEL |
| P9-EXPLAIN | Add explainable ranking output | Verified | P9-QUEUE |
| P9-EVIDENCE | Record Phase 9 evidence and human signoff | Verified | P9-EXPLAIN |

## Phase 10 — Assisted Remediation and Auto-Fix Safety

| ID | Task | Status | Dependencies |
|---|---|---|---|
| P10-PROPOSAL | Generate remediation proposals (never execute) | Verified | P9-EVIDENCE |
| P10-VALIDATE | Validate proposals, reject unsafe/destructive ops | Verified | P10-PROPOSAL |
| P10-QUEUE | Track proposals through PROPOSED/APPROVED/REJECTED | Verified | P10-VALIDATE |
| P10-APPROVAL | Require admin role for approve/reject | Verified | P10-QUEUE |
| P10-PROVENANCE | Attach SHA-256 digest, prompt/model version | Verified | P10-PROPOSAL |
| P10-SECRETS | Scrub secrets from environment facts | Verified | P10-PROPOSAL |
| P10-EVIDENCE | Record Phase 10 evidence and human signoff | Verified | P10-APPROVAL |

## Phase 11 — Guard MVP (LLM Security Middleware)

| ID | Task | Status | Dependencies |
|---|---|---|---|
| P11-CONFIG | GuardConfig with API key secret/digest, upstream allowlist | Verified | P10-EVIDENCE |
| P11-RATELIMIT | Per-client rate limiter (token bucket) | Verified | P11-CONFIG |
| P11-PROMPT-DETECT | Prompt injection detection (regex/heuristic) | Verified | P11-CONFIG |
| P11-PII-SCAN | PII response scanning (SSN, email, credit card) | Verified | P11-CONFIG |
| P11-API | FastAPI /v1/chat/completions, /health, /ready | Verified | P11-PROMPT-DETECT |
| P11-AUTH | HMAC-SHA256 API key authentication | Verified | P11-CONFIG |
| P11-EVENTS | attack_blocked and guard_request event emission | Verified | P11-API |
| P11-HEADERS | Security headers middleware (CSP, nosniff, DENY) | Verified | P11-API |
| P11-EVIDENCE | Record Phase 11 evidence and human signoff | Verified | P11-EVENTS |

## Phase 12 — Integration and End-to-End Validation

| ID | Task | Status | Dependencies |
|---|---|---|---|
| P12-RECON-INTEL | Recon discovers assets, Intel matches CVEs | Verified | P11-EVIDENCE |
| P12-INTEL-GUARD | Intel findings feed Guard, Guard blocks attacks | Verified | P12-RECON-INTEL |
| P12-READINESS | All three traces feed into readiness score | Verified | P12-INTEL-GUARD |
| P12-REMEDIATION | Remediation proposals through full lifecycle | Verified | P12-READINESS |
| P12-EVIDENCE | Record Phase 12 evidence and human signoff | Verified | P12-REMEDIATION |

## Phase 13 — Dashboard (Open Design)

| ID | Task | Status | Dependencies |
|---|---|---|---|
| P13-DESIGN-TOKENS | React design tokens and shared console primitives | Verified | P12-EVIDENCE |
| P13-API | Flask BFF routes and React pages for Recon, Intel, Guard, Targets, and Settings | Verified | P13-DESIGN-TOKENS |
| P13-SECURITY | Server-side API-key custody, loopback-only engine URL, CSRF/origin checks, security headers | Verified | P13-API |
| P13-CLI | Standalone dashboard CLI | Removed (superseded; see ADR-008) | P13-API |
| P13-INTEGRATION | Recon → Intel → Guard → Readiness data flow | Verified | P13-SECURITY |
| P13-EVIDENCE | Record Phase 13 evidence and human signoff | Verified (signed off 2026-10-21) | P13-INTEGRATION |

## Phase 14 — Integration and End-to-End Validation

| ID | Task | Status | Dependencies |
|---|---|---|---|
| P14-E2E | Synthetic Recon → Intel → Guard → readiness → proposal → verification harness | Verified | P13-EVIDENCE |
| P14-FAILURE | Duplicate, retry, restart, outage, partial-failure, tamper, and degraded-input checks | Verified | P14-E2E |
| P14-EVIDENCE | Record Phase 14 evidence | Verified (signoff pending) | P14-FAILURE |

## Phase 15 — Resource and Reliability

| ID | Task | Status | Dependencies |
|---|---|---|---|
| P15-MEASURE | Cold start, peak/per-service RAM, CPU, Guard latency, concurrency, DB latency/size, swap, headroom | Verified | P14-EVIDENCE |
| P15-PROFILES | Core/full/dev profile budgets and degraded optional-model reporting | Verified | P15-MEASURE |
| P15-EVIDENCE | Record Phase 15 measurements on the target laptop | Verified (signoff pending) | P15-PROFILES |

## Phase 16 — Gap Closure

| ID | Task | Status | Dependencies |
|---|---|---|---|
| P16-AUTH | Local login, opaque sessions, CSRF, viewer/operator/admin RBAC, CLI accounts | Verified (evidence recorded; signoff pending) | P15-EVIDENCE |
| P16-POSTGRES | Disposable PostgreSQL BFF smoke and `demo_event_outbox` collision fix | Verified | P16-AUTH |
| P16-LAB | Real Nmap/TLS/Subfinder run against the loopback isolated lab | Verified | P16-POSTGRES |
| P16-SCHEDULE | Scheduled NVD/EPSS/KEV ingestion with persisted status and real KEV/EPSS runs | Verified (full NVD live sync is a recorded exception) | P16-AUTH |
| P16-BACKUP | SQLite and PostgreSQL backup, SHA-256 verify, and restore | Verified | P16-POSTGRES |
| P16-EVIDENCE | Record Phase 16 evidence and request signoff | Verified (signoff pending) | P16-LAB, P16-SCHEDULE, P16-BACKUP |

## Phase 17 — Production Hardening

| ID | Task | Status | Dependencies |
|---|---|---|---|
| P17A1 | PostgreSQL live-store contract, migration 0007, and focused tests | Verified (225 root tests with PostgreSQL) | P16-EVIDENCE |
| P17A2 | Live-engine PostgreSQL switch, pooling, migration/rollback proof | Verified (migration apply/rollback test) | P17A1 |
| P17A3 | OIDC/SAML, MFA, password reset/disable, session inventory, auth matrix, managed secrets | Implemented (MFA/OIDC/reset/sessions/audit; SAML deferred; OIDC not live-provider tested) | P17A2 |
| P17B1 | Gunicorn, TLS reverse proxy, security headers, request limits, edge rate limits | Implemented (Caddy custom image validated; 2-request test returned 200/200/429) | P17A3 |
| P17B2 | Reproducible images, health/readiness, non-root, resource limits, rollback proof | Implemented (images built and health-checked; multi-worker schema race fixed; migration rollback drill passed locally) | P17B1 |
| P17C1 | Queue concurrency, per-target rate limits, cancellation, timeouts, output caps | Implemented (queue depth/cooldown plus existing limits) | P17B2 |
| P17C2 | Pinned scanner versions, sandboxing, target allow/deny, scheduled-scope path | Implemented (runtime version gates, target policy, container hardening, schedule API/persistence; no schedule UI) | P17C1 |
| P17D1 | Encrypted off-host backups, retention, restore drill, RPO/RTO | Implemented locally (encrypted PostgreSQL restore drill 8.81s; no production VPS/Supabase drill) | P17C2 |
| P17D2 | Structured logs, metrics, traces, dashboards, alerts, SLOs, runbooks | Implemented (Prometheus/Alertmanager/Grafana validated; overlay not run in production) | P17D1 |
| P17E1 | NVD pagination/retries/dedup/provenance, matching quality, freshness | Partial (feed-age metrics and last-known-good snapshots; full NVD hardening pending) | P17D2 |
| P17E2 | Guard evaluation, response scanning, policy, upstream allowlist, metrics | Implemented (40-case eval, block/redact, allowlist, key rotation, loopback proxy, Guard sidecar, authenticated BFF chat route; no live provider call) | P17E1 |
| P17E3 | Encryption, key rotation, retention/deletion, PII, residency, privacy/DPA | Partial (encrypted backups, PII policy, retention, data inventory; no automated erasure or counsel-reviewed DPA) | P17E2 |
| P17F1 | E2E, migration, load, security, dependency, container, restore tests; SBOM | Partial (migration/load/security/restore/dependency/SBOM evidence; no browser E2E) | P17E3 |
| P17F2 | Branch protection, changelog, semver, staged rollout, rollback, config validation | Partial (ruleset template, changelog, release workflow, rollout/rollback docs; not run in GitHub) | P17F1 |
| P18 | Release-readiness gate and human signoff | Pending (real deployment, signed release, and human signoff required) | P17F2 |

### Recorded human decision — 2026-10-22

- Phase 16 implementation: **authorized** to close the five recorded gaps
  while preserving the local, bounded, evidence-driven demo.

### Recorded human decision — 2026-10-21

- Phase 13 evidence: **approved**. The corrected React/BFF delivery and
  live-engine evaluation are accepted with the recorded exceptions.
- Phase 14 and Phase 15 implementation: **authorized**.

### Recorded human decision — 2026-10-18

- Phase 6 and Phase 7 runtime/evidence gates: **approved with exceptions**.
- Phase 8 implementation: **authorized**.
- Phase 9 implementation: **authorized**.
- Phase 10 implementation: **authorized**.
- Phase 11 implementation: **authorized**.
- Phase 12 implementation: **authorized**.
- Phase 13 implementation: **authorized**.
- Retained exceptions: real scanner execution requires a separately authorized isolated lab; XGBoost requires evidence of improvement over deterministic baseline; ONNX semantic detection requires separate evaluation; production identity/session provisioning is deployment-specific.
- No automatic remediation execution is authorized by this phase.
- Guard proxy only communicates with allowlisted HTTPS upstreams.
- Dashboard communicates only with local API routes; no external targets.

Use [tasks/plan.md](plan.md) for acceptance criteria and exact verification.
