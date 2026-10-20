# Phase 01 Exit Record — Specification and Architecture Lock

- **Decision:** PASS pending final human phase signoff
- **Commit / diff:** Not committed
- **Environment:** Windows 11, Python 3.13.5, Docker Desktop 29.4.3, WSL2 2.7.14.0
- **Reviewer:** User approval recorded in chat
- **Date:** 2026-10-17

## Required criteria and evidence

| Criterion | Status | Evidence | Notes |
|---|---|---|---|
| Service boundaries documented | PASS | `docs/SPEC-phase-01-architecture.md`, service-boundary table | Dashboard, API, workers, Guard, state, event, audit, and optional model boundaries |
| Entities and relationships documented | PASS | `docs/SPEC-phase-01-architecture.md`, canonical-entities table | Scope, asset, service, observations, vulnerabilities, proposals, Guard, users, keys, events, snapshots |
| API and event contracts documented | PASS | `docs/SPEC-phase-01-architecture.md`, REST/Guard/event sections | Error envelope, statuses, pagination, idempotency, event envelope and event types |
| Authentication and roles documented | PASS | `docs/SPEC-phase-01-architecture.md`, auth section | Viewer, Operator, Admin; dashboard, API, Guard, and worker boundaries |
| Score semantics and denominator handling documented | PASS | `docs/SPEC-phase-01-architecture.md`, readiness section | Formula version, normalized CVSS, unknown coverage behavior, corrected combined fixture = 73 |
| Security boundaries documented | PASS | `docs/SPEC-phase-01-architecture.md`, trust-boundary section | Validation, SSRF, subprocess, secrets, model output, retention, failure visibility |
| Durable-event choice recorded | PASS | `copilot-zerotrace-loop/.../docs/DECISIONS.md`, D-001 | PostgreSQL outbox + Redis Streams |
| Open Phase 1 decisions resolved or blocking dependent work | PASS | D-001 through D-007 closed | Decisions approved by user on 2026-10-17 |
| Capability map approved | PASS | `docs/CAPABILITY_MAP.md` | User approved module boundaries and build order |
| Architecture specification approved | PASS | `docs/SPEC-phase-01-architecture.md` | User approved in chat on 2026-10-17 |

## Verification evidence

| Command | Result |
|---|---|
| `py -m unittest discover -s tests -v` | PASS — 1 test |
| `docker compose -f compose.yaml config --quiet` | PASS |
| `git diff --check` | PASS |

## Human-approved decisions

- Durable events: PostgreSQL transactional outbox + Redis Streams.
- Unknown readiness components: expose unknown and coverage; no false precise
  aggregate.
- Auth lifetimes: 8-hour dashboard session, 1-hour bearer token, expiring and
  rotating Guard keys.
- Guard failure: fail closed for limiter/audit failures, model absence is
  `DEGRADED`, upstream failure is 502.
- Retention: minimal metadata, no raw prompts/responses by default, 30 days.
- Scan authorization: canonical Scope records with target/profile/expiry/
  approval evidence.
- Compose: core/full/dev profiles, private data services, optional Ollama.

## Exceptions and unresolved risks

- No application implementation has started.
- Exact token refresh mechanism, retention deletion job implementation, and
  audit checkpoint export mechanism remain implementation details within the
  approved boundaries.
- The repository contains pre-existing staged and untracked changes; none were
  reset or overwritten.
- No commit has been created.

## Decision

- [x] All Phase 1 criteria have evidence and the specification/decisions are
  approved.
- [ ] Blocked; required action: none currently.

**Human signoff:** User approved the Phase 1 specification, plan, and decision
choices in chat on 2026-10-17.
