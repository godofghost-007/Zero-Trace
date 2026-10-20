# Spec: Phase 7 Intel Boundary

## Objective

Implement the first `intel-boundary` slice from the approved capability map.
Intel ingests bounded NVD, EPSS, and CISA KEV records as untrusted external
data, normalizes them into versioned vulnerability facts, correlates those
facts with Recon services, and exposes explainable prioritized findings to an
authenticated viewer or operator.

Phase 7 does not exploit targets, execute remediation, or treat feed content,
CPE strings, descriptions, URLs, or model output as instructions.

## Scope

### Included

- Versioned Intel data model and PostgreSQL persistence contract.
- Fixed feed adapters for NVD, EPSS, and CISA KEV.
- Bounded HTTP retrieval with allowlisted endpoints, timeouts, response-size
  limits, and conditional requests.
- Strict parsing, field allowlists, schema validation, and provenance.
- CVE/CPE normalization and deterministic service-to-CVE matching.
- Prioritization using CVSS, EPSS, KEV status, exposure, confidence, and
  freshness.
- Viewer/operator API routes for findings and ingestion status.
- Synthetic feed fixtures and end-to-end correlation tests.

### Excluded

- Exploitation or active vulnerability validation.
- Arbitrary feed URLs or user-provided HTTP destinations.
- Automatic patching, Python remediation generation, or command execution.
- LLM-generated severity decisions.
- Public-target scanning; Recon authorization remains governed separately.
- Automatic acceptance of ambiguous product/version matches.

## Data contracts

### Vulnerability fact

Required fields:

- canonical CVE ID;
- source name and source record identifier;
- source retrieval timestamp and record publication/modification timestamps;
- schema version;
- summary and references after bounded sanitization;
- CVSS version/vector/base score when present;
- EPSS score and score date when present;
- CISA KEV status and due date when present;
- normalized CPE evidence;
- raw payload digest, never unrestricted raw feed content by default.

Unknown values remain unknown. The implementation must not substitute zero for
missing CVSS, EPSS, or KEV data.

### Service-vulnerability finding

Required fields:

- stable finding ID;
- Recon scope, asset, and service identifiers;
- canonical CVE ID;
- deterministic match method and confidence;
- matched CPE/product/version evidence;
- prioritization inputs and formula version;
- freshness state;
- review status;
- source revision and provenance references;
- created/updated timestamps.

### Freshness

Each source has a configured freshness window. Findings distinguish:

- `fresh`;
- `stale`;
- `unknown`.

Stale data remains visible but cannot be presented as current. Feed outages
produce a degraded ingestion status and preserve the last known provenance.

## Feed boundaries

The default adapters use fixed configured endpoints only:

- NVD CVE API 2.0;
- FIRST EPSS API;
- CISA KEV catalog.

Endpoints are configuration, not request fields. Responses are untrusted and
must pass size, content-type, JSON shape, identifier, numeric range, and
timestamp validation. Redirects are disabled. No API key, bearer token, or
feed response content is written to logs or exposed in error bodies.

Ingestion is idempotent by `(source, source_record_id, source_revision)`.
Changed records create a new revision; retries do not duplicate facts.

## Matching and prioritization

Matching is deterministic and evidence-bearing:

1. exact normalized CPE match;
2. otherwise exact vendor/product plus compatible version range;
3. otherwise no match.

Ambiguous aliases and missing versions remain unmatched rather than being
guessed. Every match records its method, evidence, and confidence.

The initial prioritization formula is `intel-priority-v1`:

- KEV membership is a bounded high-impact signal;
- EPSS is used only when present and within `[0, 1]`;
- CVSS is normalized only when present and within its version range;
- exposure and match confidence are explicit bounded inputs;
- missingness is recorded and lowers confidence, not silently converted to a
  favorable score.

The response includes the formula version and component inputs so an operator
can explain the rank. The exact weighted equation must be frozen in the plan
after human review and covered by monotonicity tests.

## API contract

All routes use `/api/v1`, existing Principal role semantics, and the project
error envelope.

```text
POST /api/v1/intel/ingestions
GET  /api/v1/intel/ingestions/{ingestionId}
GET  /api/v1/findings?page=1&pageSize=20&status=active
GET  /api/v1/findings/{findingId}
```

- Viewer may read findings and ingestion status.
- Operator may request ingestion for an allowlisted source.
- Admin-only source configuration is outside this phase.
- List responses are paginated and scoped to the caller’s authorized data.
- Ingestion requests require `Idempotency-Key`.
- A reused key with a different payload returns `409`.

## Threat model and controls

| Threat | Control |
|---|---|
| Feed response injection | Strict schemas, field allowlists, no execution |
| SSRF via source URL | Fixed endpoint registry, redirects disabled |
| False vulnerability match | Exact evidence, deterministic matcher, ambiguity rejection |
| Stale intelligence | Source freshness state and degraded ingestion status |
| Duplicate ingestion | Revision key and idempotency claim |
| DoS through feeds | Timeout, body cap, page/result limits, bounded retries |
| Cross-scope disclosure | Owner/role checks on findings and services |
| Sensitive leakage | Digests/provenance only; generic external errors |

## Commands

Focused tests:

```powershell
py -m unittest tests.test_intel -v
py -m unittest tests.test_intel_api -v
```

Full regression:

```powershell
py -m unittest discover -s tests -v
py -m compileall -q app scripts
docker compose --profile core config --quiet
docker compose --profile full config --quiet
docker compose --profile dev config --quiet
git diff --check
```

No public feed or target is contacted by automated tests; all feed responses
use synthetic fixtures or injected HTTP transports.

## Project structure

- `app/intel.py` — models, parsers, matcher, freshness, and priority formula.
- `app/intel_feeds.py` — fixed feed adapters and bounded transport boundary.
- `app/intel_pg.py` — parameterized PostgreSQL persistence.
- `app/intel_api.py` — role-checked ingestion and findings routes.
- `migrations/0004_intel.sql` — forward-only Intel schema.
- `tests/test_intel.py` — unit and synthetic feed/correlation tests.
- `tests/test_intel_api.py` — API and authorization tests.
- `tasks/evidence/phase-07.md` — reproducible Phase 7 evidence.

## Code style

Use frozen dataclasses, typed protocols, allowlisted registries, explicit
enums, and structured error results. External records are parsed into typed
facts before matching:

```python
record = source.parse(response)
fact = VulnerabilityFact.from_record(record, provenance)
finding = matcher.match(service, fact)
```

No parser returns a success-shaped fact when required identity or provenance
is invalid.

## Testing strategy

Use `unittest` with synthetic NVD/EPSS/KEV JSON fixtures and injected
transports. Cover malformed records, unknown values, numeric bounds, duplicate
revisions, retries, freshness transitions, exact/ambiguous/no matches,
prioritization monotonicity, pagination, role enforcement, scope isolation,
generic errors, and idempotency conflicts.

## Boundaries

- **Always:** treat feeds as untrusted; use fixed endpoints; cap network and
  data work; preserve provenance; validate every match; keep missingness
  explicit; require auth/RBAC; run full regression.
- **Ask first:** new feed providers, new target classes, database migration,
  retention changes, external credentials, formula changes, or production feed
  access.
- **Never:** fetch user-supplied URLs, execute feed content, guess ambiguous
  matches, expose raw secrets, exploit services, or run remediation.

## Acceptance criteria

- NVD, EPSS, and KEV synthetic records normalize into versioned facts.
- Invalid, oversized, malformed, or out-of-range records fail visibly.
- Ingestion is bounded, fixed-endpoint, idempotent, and provenance-bearing.
- Recon services correlate only on deterministic evidence.
- Ambiguous matches are rejected or remain unmatched.
- Freshness is explicit and stale data remains visibly stale.
- Priority output is explainable, bounded, versioned, and monotonic.
- Viewer/operator routes enforce authorization, pagination, and idempotency.
- Full Phase 0–6 regression remains green, with new Phase 7 tests passing.
- No external feed, public target, or remediation action is contacted or
  executed by automated verification.

## Human decisions required before planning

1. Approve this Phase 7 Intel contract.
2. Approve the initial `intel-priority-v1` weighting after it is proposed in
   the implementation plan.
3. Confirm whether production feed access remains deferred until after all
   synthetic tests and disposable PostgreSQL verification pass.
