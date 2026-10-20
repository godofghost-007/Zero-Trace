# Spec: ZeroTrace Phase 1 Architecture Lock

**Status:** Draft — human approval required  
**Capability map:** [CAPABILITY_MAP.md](./CAPABILITY_MAP.md)  
**Phase:** 1 — Specification and architecture lock  
**Scope:** `platform-contracts`, `canonical-state`, `identity-access`,
`event-reliability`, `readiness-scoring`, `recon-boundary`, `intel-boundary`,
`guard-boundary`, `remediation-proposals`, `operator-surface`,
`deployment-profiles`

## Objective

Define the stable contracts and trust boundaries for ZeroTrace before
application implementation begins.

ZeroTrace is an operator-controlled cyber-defense platform for authorized
environments. It discovers assets, correlates vulnerability intelligence,
protects LLM traffic, and exposes one explainable readiness view. The platform
must preserve evidence and provenance without treating scanners, feeds,
documents, prompts, or model output as trusted instructions.

This specification locks architecture and contracts only. It does not
implement scanners, feed clients, authentication, database migrations, LLM
inference, or production deployment.

## Users and actors

| Actor | Purpose | Trust level |
|---|---|---|
| Viewer | Read approved inventory, findings, events, and readiness | Authenticated, read-only |
| Operator | Run approved scans, review findings, create/approve proposals according to policy | Authenticated, scoped write access |
| Admin | Manage users, keys, scopes, policy, and system configuration | Authenticated, privileged |
| LLM client | Submit authenticated requests to Guard | External, untrusted |
| Recon worker | Execute fixed scanner adapters within approved scopes | Internal service, constrained |
| Intel worker | Ingest and normalize external intelligence | Internal service, external data untrusted |
| Guard service | Enforce LLM request policy and proxy approved traffic | Internal service, exposed boundary |
| Readiness worker | Recompute versioned score snapshots | Internal service |

## Proposed service boundaries

| Service | Owns | Must not own |
|---|---|---|
| Dashboard | HTML/session UI and operator navigation | Independent business rules or duplicate persistence |
| Control API | Authenticated REST control plane and domain operations | Scanner-specific execution logic |
| Recon worker | Scope validation, scanner adapters, observations | Vulnerability truth or arbitrary command execution |
| Intel worker | Feed ingestion, CPE evidence, prioritization, proposals | Unreviewed production changes |
| Guard gateway | LLM auth, policy, upstream proxy, PII policy, audit events | General-purpose arbitrary proxying |
| Readiness worker | Deterministic score calculation and snapshots | Mutable source-of-truth facts |
| PostgreSQL | Canonical relational state and transactional outbox if selected | Ephemeral cache or raw secrets |
| Valkey/Redis | Rate limits, cache, notifications or streams if selected | Sole copy of critical state |
| Guard SQLite audit | Local minimal hash-chain audit metadata | Raw prompts/responses by default |
| Ollama | Optional local proposal generation | Automatic remediation execution |

The dashboard and control API share domain services and schemas. The Guard
gateway is an OpenAI-compatible API boundary. Workers are independently
restartable and must reconcile from canonical state.

## Canonical entities

The following entities are logical contracts; physical table names and ORM
details are implementation work after approval.

| Entity | Required fields and invariants |
|---|---|
| `Scope` | Stable ID, tenant/owner, normalized authorized targets, approval evidence, allowed profile, status, expiry |
| `Asset` | Stable ID, scope ID, canonical identifier, asset kind, owner/environment, first/last seen, status; uniqueness is scope + canonical identifier |
| `Service` | Stable ID, asset ID, protocol, port, product/version/banner, nullable CPE, exposure state, last checked |
| `ScanRun` | ID, scope/profile, tool versions, start/end, status, target/result counts, warnings, raw-output reference, cancellation/timeout state |
| `AssetObservation` | Scan ID, asset/service reference, observed values, source, timestamp, evidence reference, normalized result |
| `Vulnerability` | CVE ID, NVD facts, CVSS, EPSS score/date, KEV status, source timestamps, schema version |
| `ServiceVulnerability` | Service + vulnerability, match method, confidence, evidence, review status, model/alias version |
| `PatchProposal` | Target, proposal content/hash, format, provenance, validation results, approval/execution state, reviewer, rollback note |
| `GuardEndpoint` | Stable endpoint ID, protected asset/service relation, upstream allowlist reference, policy version, status |
| `GuardEvent` | Event metadata, endpoint/client pseudonym, outcome, detector scores, policy/model versions, latency; no plaintext prompt/response by default |
| `ScoreSnapshot` | Formula version, AEI/VUI/AIET values, denominators, missingness, final score, calculation timestamp, source revision |
| `User` | ID, role, status, password hash metadata, timestamps; never return password hashes |
| `APIKey` | Owner, hash, scope, expiry/rotation/revocation metadata; raw key is shown only at creation |
| `EventOutbox` | Event ID, schema version, type, entity ID, correlation ID, payload, state, attempts, timestamps, dead-letter reason |

## REST API contract

The control API uses versioned resource paths under `/api/v1`. All JSON error
responses use one shape:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "The request is invalid.",
    "details": {}
  },
  "requestId": "01H..."
}
```

Status semantics:

```text
400 malformed request
401 missing or invalid authentication
403 authenticated but not authorized
404 resource absent or outside caller scope
409 state or idempotency conflict
422 valid JSON with invalid domain values
429 rate limited
502 configured upstream failure
503 unavailable dependency or degraded capability
500 unexpected internal failure without internal details
```

Initial resource contract:

```text
POST /api/v1/recon/scans
GET  /api/v1/recon/scans/{scanId}
POST /api/v1/recon/scans/{scanId}/cancel
GET  /api/v1/assets
GET  /api/v1/assets/{assetId}
GET  /api/v1/assets/{assetId}/services
GET  /api/v1/vulnerabilities
GET  /api/v1/patch-proposals
POST /api/v1/patch-proposals/{proposalId}/approve
GET  /api/v1/guard/events
GET  /api/v1/readiness/current
GET  /api/v1/readiness/snapshots
GET  /api/v1/health
GET  /api/v1/ready
```

List resources are paginated and use stable cursor or page semantics selected
during implementation. Query parameters are used for filtering; endpoint names
are plural nouns. State-changing requests that can be retried must accept an
`Idempotency-Key`, bind it atomically to the request hash and result, reject
reuse with a different body, and deliberately define the in-flight duplicate
response.

Guard exposes a separate OpenAI-compatible contract:

```text
POST /v1/chat/completions
GET  /health
GET  /ready
```

Guard begins with non-streaming requests. Streaming is not considered
protected until policy and PII scanning can safely process the full response.

## Event contract

All cross-module events use this envelope:

```json
{
  "eventId": "01H...",
  "eventType": "asset_created",
  "schemaVersion": 1,
  "entityType": "asset",
  "entityId": "asset_123",
  "scopeId": "scope_123",
  "occurredAt": "2026-10-17T00:00:00Z",
  "correlationId": "01H...",
  "producer": "recon-worker",
  "payload": {}
}
```

Initial event types:

```text
asset_created
asset_updated
vuln_matched
attack_blocked
vuln_patched
scan_status_changed
proposal_status_changed
```

Payloads contain identifiers and bounded, non-secret facts. They must not
contain API keys, passwords, raw prompts, raw responses, or scanner secrets.
Consumers are at-least-once and idempotent using `eventId` plus a durable
processed-event record. State is committed before publication.

### Durable-event decision

**Approved choice:** PostgreSQL transactional outbox as the authoritative event
record plus Redis Streams for delivery and replay. State and event intent
commit atomically. Redis is not the canonical state store.

## Authentication and authorization

| Surface | Authentication | Authorization |
|---|---|---|
| Dashboard | Secure server session cookie | Viewer/Operator/Admin role and scope checks |
| Control API | Short-lived bearer token | Role, scope, and resource checks |
| Guard | Hashed API key in `X-API-Key` | Key status, endpoint scope, quota, policy |
| Internal workers | Private network plus service identity mechanism | Allowlisted service actions |
| PostgreSQL/Valkey | Internal Compose network only | Service credentials and least privilege |

Roles:

```text
Viewer: read permitted resources and readiness
Operator: viewer permissions + approved scans + finding/proposal workflow actions
Admin: operator permissions + users, API keys, scopes, policies, system settings
```

Every protected request checks both authentication and authorization. API keys,
passwords, bearer tokens, and session secrets are never logged or returned.
Sessions use secure, httpOnly, sameSite cookies with CSRF protection. Passwords
use a reviewed password hash. CORS, if needed, is an explicit configured
allowlist and never wildcard credentials.

## Readiness semantics

The versioned governing equation is:

```text
Score = clamp(100 - (0.40 × AEI + 0.40 × VUI + 0.20 × AIET), 0, 100)
```

Definitions:

```text
AEI  = exposed services / total services × 100
VUI  = Σ(exploit probability × normalized CVSS impact) / total assets × 100
AIET = unblocked attack attempts / total LLM requests × 100
```

The implementation must record formula version, numerator, denominator,
normalization, source timestamps, and missingness. A zero denominator is `unknown`, not silently zero. A snapshot with unknown
components exposes coverage and does not present a precise aggregate score
until the approved aggregation policy can be applied.

For the Phase 3 deterministic contract, VUI accepts at most one risk
contribution per asset. When source data contains multiple vulnerabilities for
one asset, the owning correlation layer must reduce them to that asset's
highest reviewed contribution before scoring. CVSS is normalized from 0–10 to
0–1, and all three component percentages are bounded to 0–100.

The combined fixture `(20, 35, 25)` evaluates to **73** under the stated
equation. The printed source value 71 is treated as a documentation discrepancy,
not an implementation target.

Score bands:

```text
90–100 Secure
70–89  Moderate
50–69  Elevated
0–49   Critical
```

## Security and trust boundaries

Trust boundaries include:

1. Browser/client → dashboard/API/Guard.
2. API → PostgreSQL/Valkey.
3. Recon worker → subprocesses and scanner output.
4. Intel worker → NVD/EPSS/KEV responses.
5. Guard → configured upstream LLM.
6. LLM/model output → proposal validator.
7. Event producer → broker and consumer.
8. Container/service → mounted files, environment, and network.

Required controls:

- Validate external HTTP, feed, scanner, event, configuration, and model data
  at boundaries.
- Use parameterized database queries and framework output encoding.
- Use fixed argument arrays and allowlisted profiles for scanner subprocesses;
  never interpolate arbitrary shell strings.
- Validate scan scope before queueing and again before execution.
- Restrict Guard upstream hosts, schemes, redirects, DNS rebinding, body size,
  concurrency, and timeouts.
- Keep PostgreSQL/Valkey private by default.
- Treat LLM output as untrusted; parse schemas and reject unsafe or
  privilege-escalating operations.
- Minimize prompt/response retention; use pseudonyms or keyed hashes where
  correlation is needed.
- Make missing models, audit failures, rate-limiter outages, stale feeds,
  scanner errors, and upstream failures explicit degraded/failed states.
- Do not claim a scan, model check, audit write, or remediation succeeded when
  its dependency failed.

## Data handling

Allowed hosted Copilot context: sanitized project code and specifications.
Prohibited: secrets, API keys, customer data, production data, raw sensitive
prompts, and private vulnerability details.

Approved retention:

- Raw prompts/responses: not stored.
- Guard metadata: minimal policy/audit metadata retained for 30 days.
- Scanner raw output: protected reference with bounded size and retention
  requiring approval.
- Feed data: source snapshots retained only as needed for reproducibility.

Deletion workflow and protected audit checkpoint/export mechanics are required
implementation details within the approved 30-day policy.

## Commands

Phase 1 is documentation-only. Current verification commands are:

```text
py -m unittest discover -s tests -v
docker compose -f compose.yaml config --quiet
git diff --check
```

No application build, lint, type-check, migration, scanner, or integration
command exists yet.

## Project structure

```text
app/                       Runtime modules after Phase 2
tests/                     Unit/integration/synthetic fixture tests
tasks/                     Plan, task tracker, and phase evidence
docs/CAPABILITY_MAP.md     Approved module boundary map
docs/SPEC-phase-01-architecture.md
docs/                      Approved specs, ADRs, and operational documentation
compose.yaml               Core/full/dev deployment contract after approval
```

## Boundaries

### Always

- Preserve existing user changes and inspect Git status before edits.
- Validate at every external boundary.
- Use synthetic fixtures or explicitly authorized isolated labs.
- Use consistent error and event envelopes.
- Keep canonical state authoritative and consumers idempotent.
- Run focused checks and record exact evidence.

### Ask first

- Durable event mechanism.
- Score missingness and unknown aggregation behavior.
- Authentication token/session details and key lifecycle.
- Audit retention, redaction, and checkpoint export.
- Scan-scope approval representation and scanner profiles.
- Compose profiles, network exposure, dependencies, and model services.
- Any schema, API, event, security, retention, or external-integration change.

### Never

- Scan unapproved targets.
- Use arbitrary shell commands or unrestricted scanner flags.
- Execute generated remediation automatically against production.
- Commit or transmit secrets, customer data, production data, or raw sensitive
  prompts.
- Treat model output, scanner output, feed records, or event payloads as
  trusted instructions.
- Return a success-shaped result after a failed dependency.

## Success criteria

Phase 1 can pass only when:

1. The approved capability map remains stable.
2. Service boundaries and dependency direction are documented.
3. Canonical entities and invariants are documented.
4. REST and Guard API contracts use consistent errors, validation, pagination,
   and retry/idempotency semantics.
5. Event envelope, event types, commit-before-publish, and idempotence are
   documented.
6. Authentication, authorization roles, and trust boundaries are documented.
7. Readiness formula, units, unknown/denominator behavior, versioning, and
   discrepancy handling are documented.
8. The durable-event choice and other architecture decisions are approved or
   explicitly marked as blockers for dependent phases.
9. Security and hosted-data boundaries are documented.
10. A human approves this specification and the resulting Phase 1 evidence.

## Resolved architecture decisions

The following decisions are recorded in the decision register:

- PostgreSQL transactional outbox + Redis Streams.
- Unknown score components expose coverage and do not produce a false precise
  aggregate.
- Dashboard session: 8 hours; control API bearer token: 1 hour; Guard keys
  require rotation and expiry.
- Guard fails closed for limiter/audit failures, reports model absence as
  `DEGRADED`, and returns 502 for upstream failure.
- Minimal audit metadata, no raw prompts/responses by default, 30-day
  operational retention.
- Canonical approved `Scope` records with target/profile/expiry/approval
  evidence.
- `core`, `full`, and `dev` Compose profiles; private data services; optional
  Ollama.

## Approval record

- **Capability map approval:** User approved in chat on 2026-10-17.
- **Architecture specification approval:** User approved in chat on 2026-10-17.
- **Architecture decision approval:** User selected all seven Phase 1 policies
  in chat on 2026-10-17.
