# ZeroTrace Phase 1 Capability Map

This map is the Phase 1 boundary contract. Module IDs are stable and must be
used by later specifications, plans, and tasks.

| Module ID | Responsibility | Depends on |
|---|---|---|
| `platform-contracts` | Shared identifiers, error envelope, configuration boundaries, event envelope, correlation metadata, and versioning rules | — |
| `canonical-state` | PostgreSQL-owned entities, relationships, provenance, migrations, and transaction boundaries | `platform-contracts` |
| `identity-access` | Dashboard sessions, API bearer authentication, Guard API keys, roles, and authorization policy | `platform-contracts`, `canonical-state` |
| `event-reliability` | Commit-before-publish delivery, idempotent consumers, retries, dead letters, and reconciliation | `canonical-state`, `platform-contracts` |
| `readiness-scoring` | AEI, VUI, AIET, formula versioning, missingness, denominator handling, score bands, and snapshots | `canonical-state`, `platform-contracts` |
| `recon-boundary` | Authorized scan scopes, safe scanner profiles, normalized assets/services, observations, and scan provenance | `canonical-state`, `event-reliability`, `identity-access` |
| `intel-boundary` | NVD/EPSS/KEV ingestion, service-to-CVE evidence, prioritization inputs, and freshness | `canonical-state`, `event-reliability` |
| `guard-boundary` | OpenAI-compatible proxy, request policy, upstream allowlist, PII policy, rate limiting, and audit metadata | `canonical-state`, `event-reliability`, `identity-access` |
| `remediation-proposals` | Schema-validated, provenance-bearing remediation proposals and approval/rollback lifecycle | `intel-boundary`, `canonical-state`, `identity-access` |
| `operator-surface` | Dashboard/API views, status visibility, cross-module navigation, and operator actions | `identity-access`, `readiness-scoring`, `recon-boundary`, `intel-boundary`, `guard-boundary` |
| `deployment-profiles` | Core/full/dev Compose profiles, network exposure, optional model services, health checks, and resource boundaries | all runtime modules |

## Build order

```text
platform-contracts
  → canonical-state
  → identity-access
  → event-reliability
  → readiness-scoring
  → recon-boundary, intel-boundary, guard-boundary
  → remediation-proposals
  → operator-surface
  → deployment-profiles
```

`recon-boundary`, `intel-boundary`, and `guard-boundary` can be specified and
implemented independently after their shared contracts, state, identity, and
event dependencies are approved.

## Phase 1 scope

Phase 1 must document, approve, or explicitly block:

- Service and module boundaries.
- Canonical entities and relationships.
- REST and Guard API contracts.
- Event envelope and event names.
- Authentication and role boundaries.
- Readiness-score semantics and zero-denominator behavior.
- Security boundaries and untrusted-input rules.
- Durable-event choice: PostgreSQL transactional outbox, Redis Streams, or a
  documented combination.

No application implementation is authorized by this map.
