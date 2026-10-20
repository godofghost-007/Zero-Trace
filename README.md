# ZeroTrace

ZeroTrace is a planned three-module cyber-defense platform:

- **Recon** discovers authorized assets and exposed services.
- **Intel** correlates vulnerability intelligence and prioritizes remediation.
- **Guard** protects LLM traffic through an OpenAI-compatible gateway.

This repository is currently at **Phase 11 â€” Guard MVP**. Phases 0â€“11 are
implemented and verified: runnable foundation, deterministic readiness-score
contract, tested security primitives, event delivery state model, constrained
Recon contracts/adapters with safety controls, Intel boundary with correlation
completeness, vulnerability prioritization with intel-priority-v2, assisted
remediation with human-gated approval, and Guard middleware with LLM security
protection.

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

- Phases 0â€“4 are complete with recorded evidence (settings, errors, logging,
  health, migrations, readiness score, auth/security primitives).
- Phase 5 provides event reliability (commit-before-publish, idempotent
  consumer, retry/backoff, dead-letter, reconciliation) plus the PostgreSQL
  outbox and Redis/Valkey Streams runtime contracts in `app/events_pg.py`.
- Phase 6 provides approved-scope enforcement, fixed-profile Subfinder/Nmap/TLS
  and read-only S3 adapter boundaries, untrusted-output parsing, normalized
  observations, explicit timeout/cancellation/partial/failure states,
  idempotent run creation, result-before-event ordering, rate limiting before
  run creation, bounded concurrency, configurable retry for transient failures,
  and DNS gating before active adapter execution. Tests use synthetic fixtures
  only; no external target was scanned.
  - P6-LAB (real scanner execution) is **blocked** pending an explicitly
    authorized isolated lab target (`testsite.zerotrace.local` per Project
    Documentation v2.0, Section 11.1) and subfinder/nmap availability.
- Phase 7 provides normalized, provenance-bearing NVD/EPSS/KEV intelligence,
  bounded fixed-endpoint feed adapters with pagination/checkpoints,
  malformed-record quarantine, last-known-good snapshots, merged EPSS/KEV
  facts, deterministic service-to-CVE matching, explainable
  `intel-priority-v1` prioritization, PostgreSQL persistence, and role-checked
  ingestion/finding API contracts. Feed operations (pagination, quarantine,
  backoff, last-known-good) are implemented in `app/intel_feeds.py`.
- Phase 8 provides deterministic exact-CPE and unique fallback correlation,
  explicit uncertain-match evidence, end-to-end persisted correlation
  orchestration (`CorrelationBatch`, `correlate_scope()`, `save_correlation()`),
  PostgreSQL persistence, and scope-filtered paginated
  `/api/v1/uncertain-matches` route.
- Phase 9 provides `intel-priority-v2` vulnerability prioritization with
  business criticality input, model/pipeline versioning with artifact checksums,
  48-hour SLA remediation queue, and explainable ranking output.
- Phase 10 provides assisted remediation: safe remediation proposals generated
  and validated (no secrets, no privilege escalation, no destructive ops),
  SHA-256 digest provenance, admin-only approve/reject, **no automatic
  execution** â€” ZeroTrace never runs a proposed fix against any target.
- Phase 11 provides Guard MVP â€” LLM security middleware through an
  OpenAI-compatible gateway: `/v1/chat/completions` endpoint, API key
  authentication (HMAC-SHA256), per-client rate limiting, regex/heuristic
  prompt injection detection, PII response scanning, upstream allowlist
  (HTTPS-only, no SSRF), security headers, `attack_blocked` events, and
  `/health`/`/ready` endpoints. ONNX semantic detection, streaming, and Ollama
  integration are deferred to later phases.
- No scanners or external targets are used during development setup.
- No generated remediation is executed automatically.
- Secrets and production/customer data must not be placed in source, fixtures,
  logs, or hosted Copilot context without an approved data-handling decision.

## Local verification

### Test-only authorization harness

For demonstrations, use the removable
[TestOnlyAuthorizationRegistry](app/test_authorization.py). It is not a
production bypass:

- It only initializes for `ZEROTRACE_ENV=test` or `development`.
- It requires an `admin` principal and the code `ZEROTRACE-TEST-ONLY` by
  default. Set `ZEROTRACE_TEST_AUTH_CODE` to use a local replacement.
- It accepts only `.test` domains and `localhost`/`host.docker.internal`;
  public domains, IP addresses, paths, and arbitrary URLs are rejected.
- Authorizations expire after ten minutes by default and are labelled as
  synthetic test authorization.

Example:

```python
from app.security import Principal
from app.test_authorization import TestOnlyAuthorizationRegistry

authorization = TestOnlyAuthorizationRegistry(environment="test").authorize(
    Principal("guide-admin", "admin"),
    code="ZEROTRACE-TEST-ONLY",
    target="lab.example.test",
    profile_id="synthetic_inventory_v1",
)
```

Remove this module before a production release if the demonstration harness is
not needed. Production authorization continues to require the exact-domain
DNS TXT challenge or an explicitly recorded isolated-lab authorization.

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
endpoint returns HTTP 200. `/ready` probes PostgreSQL and returns degraded
status when the dependency is unavailable.

Run the automated checks:

```powershell
py -m unittest discover -s tests -v
py -m compileall -q app scripts
docker compose --profile core config --quiet
docker compose --profile full config --quiet
docker compose --profile dev config --quiet
git diff --check
```



