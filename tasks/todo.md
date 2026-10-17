# ZeroTrace Task Tracker

## Completed

| ID | Phase | Task | Status |
|---|---:|---|---|
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
- [x] PostgreSQL schema/repository and FastAPI route contracts are covered by
      focused tests.
- [ ] Real scanner execution remains blocked until isolated-lab authorization.
- [ ] Human reviews and signs Phase 6 evidence before Phase 7.

Use [tasks/plan.md](plan.md) for acceptance criteria and exact verification.
