# Spec: Phase 6 Recon MVP

## Objective

Implement the first `recon-boundary` slice from the approved Phase 1 capability
map. An authenticated operator must be able to create a scan run only for an
explicitly approved synthetic or isolated-lab scope, select one fixed safe
scanner profile, observe bounded progress and failure states, cancel or time
out a run, and retrieve normalized asset/service observations after durable
commit. A scan-status event must be appended only after the corresponding
canonical result state is committed.

The MVP must make unsafe actions impossible through the interface: no arbitrary
shell strings, unrestricted scanner flags, unapproved targets, destructive S3
operations, secret-bearing output, or success-shaped results after scanner
failure.

## Assumptions

1. Phase 6 uses real Subfinder, Nmap, TLS, and read-only S3 adapters only
   against synthetic fixtures or explicitly authorized isolated-lab scopes.
   Tests use injected fake adapters and never scan external targets.
2. PostgreSQL and Redis remain optional integration boundaries until a separate
   service-integration task is approved; deterministic in-memory repositories
   may be used for the MVP contract tests.
3. Existing `EventEnvelope` and `InMemoryOutbox` contracts remain stable.
4. Operators and scopes are represented by validated internal principals and
   scope records; Phase 6 does not redesign authentication or role storage.

## Contract

### Scope

A scope contains:

- stable scope ID;
- owner/principal ID;
- normalized allowlisted targets;
- `synthetic` or `isolated_lab` environment classification;
- one or more permitted profile IDs;
- explicit approval status and expiry;
- no credentials or raw scanner command text.

Targets must be canonicalized before comparison. A requested target must match
an approved target exactly or be an approved child according to the profile's
explicit target rule. Ambiguous, expired, unapproved, malformed, or
credential-bearing targets are rejected with a typed validation/authorization
error.

### Fixed profiles

Profiles are immutable allowlisted definitions. Each profile declares an ID,
adapter name, target kind, timeout ceiling, request/rate budget, and whether it
may access only synthetic fixtures or an isolated lab. Callers may select a
profile ID but cannot provide executable arguments, binaries, shell syntax,
URLs outside the scope, or destructive operations.

The initial profile set is adapter-based and fixed:

- `passive_subdomain_v1`: passive Subfinder/certificate discovery for an
  approved domain scope;
- `service_inventory_v1`: fixed Nmap top-100 TCP connect profile for approved
  resolved targets;
- `tls_metadata_v1`: bounded certificate and handshake inspection;
- `s3_read_only_v1`: explicitly authorized read-only public exposure checks.

Real adapters are enabled only for an approved isolated-lab scope. Synthetic
fake adapters remain mandatory for deterministic tests.

No unrestricted Nmap flags, active discovery outside the selected profile,
S3 write/delete operation, or real external target is part of this MVP.

### Scan lifecycle

Scan runs use explicit states:

`queued`, `running`, `completed`, `partial`, `cancelled`, `timed_out`,
`failed`.

The lifecycle records profile, scope, start/end times, counts, warnings,
timeout/cancellation state, and a safe result reference. Raw scanner output is
not persisted by default. Partial observations are retained only when the
adapter reports which work completed and which failed.

### Execution controls

- one bounded execution context per run;
- hard timeout and cooperative cancellation;
- bounded target count and fixture/result size;
- deterministic rate budget;
- no shell interpolation or user-controlled process arguments;
- explicit failure state when an adapter, fixture, or event dependency fails;
- no empty-success result for a failed scan.

### Result and event ordering

Normalized assets, services, observations, and scan status are committed to
the canonical repository before the corresponding `scan_status_changed` event
is appended/published through the existing outbox contract. If persistence or
event append fails, the run is visibly failed or degraded and must not report
completed success.

### Error envelope

Boundary errors use the existing structured error semantics:

- invalid scope/profile/input: validation error;
- scope not approved or expired: authorization error;
- missing scan: not found;
- duplicate state-changing request: conflict;
- rate/size/timeout limit: explicit limit or timeout error;
- adapter/persistence/event failure: failed or degraded state without internal
  exception details.

## Commands

Focused tests:

```powershell
py -m unittest tests.test_recon -v
```

Full regression:

```powershell
py -m unittest discover -s tests -v
py -m compileall -q app scripts
git diff --check
```

Compose configuration checks:

```powershell
docker compose --profile core config --quiet
docker compose --profile full config --quiet
docker compose --profile dev config --quiet
```

All fixtures and manual checks must remain synthetic or inside an explicitly
authorized isolated lab.

### Remediation boundary

Recon and Intel may produce bounded evidence and a remediation finding, but
Phase 6 does not generate or execute Python fixes. A later remediation phase
may generate a schema-validated Python proposal and display it to the operator.
The operator decides whether to run it; ZeroTrace never runs it automatically
against a real target. Any disposable-lab validation requires a separate
approval and isolated fixture.

## Project Structure

- `app/recon.py` — validated scope/profile contracts, lifecycle, adapter
  orchestration, cancellation/timeout/limits, and normalized results.
- `tests/test_recon.py` — synthetic contract, negative, lifecycle, limit,
  partial-failure, persistence-order, and event-order tests.
- `tasks/plan.md` — approved Phase 6 implementation plan and checkpoints.
- `tasks/todo.md` — Phase 6 task tracker.
- `tasks/evidence/phase-06.md` — reproducible phase exit evidence.
- `docs/SPEC-recon-boundary.md` — this approved module specification.

## Code Style

Use frozen dataclasses and allowlisted registries, matching the existing
event/security modules. Boundary methods return explicit typed state or raise a
specific domain error; they do not return `None`, empty success, or swallowed
exceptions for invalid input.

```python
profile = PROFILE_REGISTRY.get(request.profile_id)
if profile is None:
    raise ReconValidationError("profile is not allowlisted")
scope.require_target(request.target, profile)
```

Adapters receive validated typed inputs and return normalized observations.
They never receive raw shell text or unrestricted flags.

## Testing Strategy

Tests use `unittest` and synthetic fixtures only. Required coverage includes:

- exact scope and expiry enforcement;
- profile allowlisting and rejection of command/flag injection fields;
- target, fixture, result-size, rate, timeout, and cancellation limits;
- successful, partial, failed, cancelled, and timed-out lifecycle states;
- no success-shaped result after adapter failure;
- normalized asset/service/observation output;
- persistence-before-event ordering;
- duplicate/idempotent scan request behavior where applicable;
- secrets and raw sensitive scanner output rejected or omitted.

## Boundaries

- **Always:** validate scope and profile at the boundary; use fixed adapters;
  cap work and data; preserve explicit failure states; use synthetic or
  authorized lab fixtures; run focused and full regression tests.
- **Ask first:** real network scanner subprocesses; new dependencies; database
  migrations; Redis integration; new target classes; changes to auth/RBAC,
  event durability, retention, or network exposure.
- **Never:** scan an unapproved target; execute arbitrary shell input; accept
  unrestricted scanner flags; perform destructive S3 actions; persist secrets,
  credentials, raw prompts, or private customer data; execute remediation.

## Success Criteria

1. Only approved, unexpired synthetic/lab scopes and immutable profile IDs can
   create runs.
2. No user-controlled shell command, binary path, or unrestricted scanner
   argument reaches execution.
3. Timeout, cancellation, rate, target, and result limits are enforced and
   observable.
4. Adapter failures produce `failed` or `partial` state with warnings, never
   empty successful results.
5. Normalized results are persisted before `scan_status_changed` is appended.
6. Synthetic tests prove all required positive and negative behavior.
7. Phase 0–5 regression tests remain green and no migration is changed.

## Approved decisions

1. Use real constrained Subfinder, Nmap, TLS, and read-only S3 adapters behind
   fixed profiles; tests use injected fake adapters.
2. Include authorized scope validation, passive discovery, service discovery,
   TLS metadata, and read-only S3 checks in Phase 6.
3. Remediation output is proposal-only and shown to the user for a decision;
   automatic execution is prohibited. Python proposal generation belongs to
   the later assisted-remediation phase.
4. Use deterministic in-memory repositories for the MVP contract tests, with
   PostgreSQL persistence as a separately gated integration slice.

## Operational decisions

- FastAPI is approved for the versioned control routes.
- Queued background execution with polling and cancellation is approved.
- A forward-only PostgreSQL Recon migration and disposable database tests are
  approved; existing migrations remain immutable.
- S3 provider integration is deferred. The read-only adapter contract remains
  tested, but no provider dependency or credential flow is added in this
  slice.
- Live scanner execution is blocked until an explicitly authorized isolated
  lab target is supplied. No public, production, or customer target may be
  selected by the implementation.

## Operational integration expansion

The following work is required to call Phase 6 operationally complete. It is
ordered as vertical slices and must preserve the contract above.

### 1. PostgreSQL canonical persistence

Add a forward-only migration for approved scopes, scan runs, assets, services,
observations, and scan idempotency claims. The repository must use parameterized
queries and one transaction for canonical result writes plus the event-outbox
append. A unique idempotency constraint must atomically claim a request and
reject the same key with a different request hash.

The migration must not modify `0001_foundation.sql` or
`0002_event_reliability.sql`. Migration tests must verify required tables,
constraints, indexes, and rerun behavior against the existing migration
contract.

### 2. HTTP control routes

Add the approved `/api/v1/recon` routes:

```text
POST /api/v1/recon/scans
GET  /api/v1/recon/scans/{scanId}
POST /api/v1/recon/scans/{scanId}/cancel
GET  /api/v1/assets
GET  /api/v1/assets/{assetId}
```

The route boundary must validate JSON, require authentication, require the
Operator role for scan creation/cancellation, apply scope ownership checks,
honor `Idempotency-Key`, enforce request-size/rate limits, and return the
existing structured error envelope. Viewer access is read-only. Internal
errors must not be returned to callers.

The existing foundation HTTP server may be extended only if the route behavior
can remain clearly bounded and tested. Adding a web framework is a separate
dependency decision and requires approval.

### 3. Real isolated-lab execution

Run real Subfinder and Nmap only when the scope is explicitly classified as
`isolated_lab` and the operator has supplied an approved lab authorization
record. The worker must verify fixed executable paths and versions, use
argument arrays with `shell=False`, cap output, enforce process-group
termination, and avoid host networking or privileged Nmap modes by default.

The live check must use a local synthetic lab fixture or an explicitly
authorized lab target supplied by the human reviewer. No internet or
production target is permitted.

### 4. Provider-backed read-only S3

Implement a provider client only after choosing the provider and dependency.
The client may perform only the approved public-read/public-list/permission
checks, must use least-privilege credentials from environment/secret storage,
must enforce the approved bucket/account scope, and must classify denied,
unknown, transient, public-readable, and public-listable outcomes. Upload,
delete, object mutation, and broad account enumeration are prohibited.

Provider integration must be tested against an isolated local S3-compatible
fixture or an explicitly authorized cloud test account. Credentials must never
appear in source, fixtures, logs, events, or hosted context.

### 5. Remediation boundary

Remediation proposal generation remains a later phase. Phase 6 may expose
normalized evidence and a finding reference, but it must not generate,
display, or execute Python remediation scripts. The later proposal phase will
show a schema-validated script to the user, who decides whether to run it.
Automatic execution remains prohibited.

## Expanded success criteria

In addition to the MVP criteria above, operational Phase 6 requires:

1. PostgreSQL persistence and event-outbox ordering are proven with disposable
   database tests and restart/failure scenarios.
2. HTTP routes enforce authentication, role, scope ownership, size/rate
   limits, structured errors, and idempotency.
3. At least one authorized isolated-lab run proves real Subfinder/Nmap process
   execution, timeout/cancellation, parsing, and partial failure behavior.
4. A provider-backed S3 read-only check is proven in an isolated fixture or
   explicitly authorized test account.
5. All Phase 0–5 regressions remain green and no production/customer data or
   secrets are used.

## Decisions required before operational implementation

1. **HTTP stack:** extend the standard-library `HTTPServer`, or approve adding
   FastAPI and its dependency set?
2. **Database execution:** approve a new forward-only Recon migration and
   disposable PostgreSQL integration tests?
3. **Live lab:** provide or authorize a local isolated fixture/target and
   confirm whether Subfinder and Nmap binaries may be installed/used on this
   machine?
4. **S3 provider:** choose `localstack`, `MinIO`, or an explicitly authorized
   AWS test account. Approve the required client dependency and credential
   handling.
5. **Execution mode:** keep scans synchronous for the first HTTP slice, or
   require a queued background worker with polling from the start? The latter
   is safer for timeouts but is a larger integration surface.
