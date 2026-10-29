# ZeroTrace Production Readiness Review

Date: 2026-10-25
Baseline: `feature/phase-17-production-hardening` at the Phase 17A-17F
working tree
Scope: single-tenant, loopback-local demo and the path to a self-hosted service

## 1. Honest scorecard

| Measure | Current state | Assessment |
|---|---|---|
| Local demo completeness | React UI, Flask BFF, FastAPI engine, real Nmap/Subfinder/TLS adapters, scope authorization, auth/RBAC, audit, KEV sync, readiness panel | **~90%** |
| Single-tenant production readiness | PostgreSQL live-engine store, versioned migrations, MFA/OIDC/password reset, Caddy + container deployment, edge rate limits, scanner policy/version gates, schedules, encrypted backup/restore, metrics/logs/alerts, CI/SBOM/audit, production config validation; real VPS/Supabase deployment, egress proof, browser E2E, signed release, and Phase 18 gate remain | **~80%** |
| Multi-tenant SaaS readiness | No tenant data plane, no per-tenant isolation, no billing/onboarding/SCIM | **not started** |

The project is a working full-stack application with a credible self-hosted
deployment path. It is not yet a production-ready release: no real VPS or
Supabase deployment has been performed, and the Phase 18 release gate and human
signoff are still open. The remaining gap is mostly operational proof, not
missing core logic.

## 2. What is already real

- **Full-stack wiring**: the browser talks only to Flask; Flask holds the engine
  API key and forwards to a loopback-only FastAPI engine.
- **Real Recon adapters**: a two-stage Nmap adapter (bounded discovery, then
  service/vulnerability scripts only on open ports), a passive
  certificate-transparency Subfinder adapter, and a single-read TLS metadata
  adapter. No exploitation, brute force, or automatic remediation. The Nmap NSE
  `vuln` scripts are detection-only and run against the fixed high-value port
  list.
- **Explicit authorization**: the BFF requires an operator acknowledgement for
  scope and scan creation. The operator console exposes four fixed services
  (Nmap, Subfinder, TLS Metadata, Synthetic Inventory) with no elevated level
  selector. The legacy High/Deep API path retains its DNS TXT ownership
  challenge and `isolated_lab` scope. Scans can only use targets and profiles in
  an approved, time-bounded scope.
- **Auth/RBAC**: opaque session cookie, per-session CSRF token, ordered
  `viewer < operator < admin` roles, login rate limiting, database-backed
  lockout, TOTP MFA, optional OIDC, password reset, session inventory and
  revocation, and auth audit events. See `docs/AUTH-MATRIX.md`.
- **Durable demo state**: SQLite remains the zero-dependency demo fallback.
- **PostgreSQL live path**: the live engine selects PostgreSQL when
  `DATABASE_URL` is set, uses pooled connections, and has versioned migrations
  with apply/rollback tests. SQLite remains available for the local demo.
- **Deployment path**: Caddy TLS/security headers, non-root BFF and engine
  containers, a loopback Guard sidecar with separate provider secrets,
  healthchecks, resource limits, loopback-only engine URL, and a documented
  Supabase/migration/backup runbook in `deploy/README.md`.
- **Intel**: CISA KEV ingestion is exposed in the UI; NVD and EPSS remain
  API/schedule-only. The demo does not invent feed results.
- **Encrypted recovery**: Fernet-encrypted `.ztb` backups with inner/outer
  SHA-256 manifests, a destructive PostgreSQL restore drill, retention pruning,
  and RPO/RTO targets. See `docs/BACKUP-RESTORE.md`.
- **Observability**: in-process metrics, JSON logs, request IDs, trace
  propagation, Prometheus rules, Alertmanager, a Grafana dashboard, SLOs, and an
  operations runbook. See `docs/SLO.md` and `docs/RUNBOOK-OPERATIONS.md`.
- **Guard boundary**: a loopback-only OpenAI-compatible proxy with a
  server-side provider key, strict upstream allowlist, model allowlist, PII
  block/redact policy, key rotation, and a deterministic evaluation corpus. See
  `docs/GUARD-EVALUATION.md`.
- **Quality evidence**: 265 root tests (including disposable PostgreSQL
  databases), 61 BFF tests, 6 frontend tests, frontend type-check, production
  build, dependency audit, SBOM generation, runtime security smoke, and a
  smoke-level load test passed at this baseline.
- **New service selection**: the ZeroTrace console exposes four toggle buttons
  for Nmap, Subfinder, TLS Metadata, and Synthetic Inventory. All four are
  selected by default. There are no level dropdowns; the engine runs only the
  selected services, in fixed priority order (Nmap, Subfinder, TLS Metadata,
  Synthetic Inventory). Nmap uses the bounded two-stage script flow; Subfinder
  uses passive certificate-transparency records and performs no target DNS or
  HTTP probe.

## 3. What is still demo-grade

### P0 — required before a single-tenant production pilot

1. **PostgreSQL as the live data path** — **implemented for the live engine**
   - Scopes, scans, Intel facts/findings, Guard counters, readiness snapshots,
     and scheduler state use dedicated `live_*` tables with pooled connections.
   - Versioned migrations and an apply/rollback test exist.
   - BFF auth tables are bootstrapped once with `flask init-schema`; BFF
     operational tables still need a full versioned migration set before a
     production pilot.

2. **Production identity** — **partially implemented**
   - TOTP MFA, optional OIDC, password reset/disable, session inventory, forced
     revocation, and a per-tenant authorization matrix exist.
   - SAML, tenant-wide MFA enforcement, idle timeout, and a managed secret store
     are still open.

3. **Production deployment** — **partially implemented**
   - Gunicorn behind Caddy, HSTS/secure cookies/CSP, request-size limits,
     per-client edge rate limits, non-root images, healthchecks, resource
     limits, and a rollback runbook exist.
   - Egress allowlist proof and a real VPS/Supabase deployment remain open.

4. **Scanner safety and capacity** — **implemented, with sandbox caveats**
   - Four bounded services, queue depth, per-target cooldown, concurrency limit,
     retries, cancellation, hard timeouts, and output caps exist.
   - Runtime scanner version verification, an explicit target allow/deny policy,
     and scheduled-scope revalidation exist. See `docs/SCHEDULES.md`.
   - The container is hardened, but there is no per-scan network namespace or
     separate filesystem jail beyond the container controls.
   - The operator UI uses the four fixed services and requires the BFF
     acknowledgement. The legacy elevated-profile API path retains DNS TXT
     ownership verification. No service enables exploitation, brute force, or
     automatic remediation; Nmap's detection-only `vuln` scripts run only on open
     ports.

5. **Backups and disaster recovery** — **implemented locally, production drill open**
   - Encrypted backups, retention, a destructive restore drill, RPO/RTO targets,
     and a recovery runbook exist.
   - The drill used a local Docker PostgreSQL, not a production VPS or Supabase
     project. Off-host copy used a local directory, not rclone/S3.

6. **Observability and operations** — **implemented, production overlay open**
   - Metrics, JSON logs, request IDs, trace propagation, dashboards, alerts,
     SLOs, and runbooks exist.
   - The overlay has not run against a production stack, and the shipped
     Alertmanager receiver is null. On-call ownership is still an operator
     decision.

### P1 — required before general production use

7. **Intel pipeline hardening** — **partial**
   - Last-known-good snapshots, feed-age metrics, and NVD/EPSS/KEV scheduling
     exist.
   - Full live NVD pagination, retry/backoff, deduplication, provenance,
     CVE-to-service matching quality, and false-positive review remain open.
   - EPSS and KEV freshness indicators are not yet in the UI.

8. **Guard hardening** - **implemented, provider evaluation open**
   - A 40-case labeled corpus, response block/redact policy, upstream model
     allowlisting, strict HTTPS-origin checks, key rotation, a loopback proxy,
     and an authenticated BFF `POST /api/v1/guard/chat` route exist.
   - The detector is regex-based and English-only. No live provider or external
     classifier was evaluated.
   - The external detector and Intel model slots are reserved, not implemented.
   - Guard protects only traffic routed through it.

9. **Data protection and lifecycle** — **partial**
   - TLS, encrypted backups, MFA-secret encryption, key rotation, retention
     pruning, PII block/redact, and a data inventory exist.
   - There is no automated data-subject export/erasure endpoint, no tenant
     isolation, and no counsel-reviewed DPA or privacy notice.
   - Encryption at rest depends on the database and backup provider.

10. **Testing and quality gates** — **partial**
    - Migration apply/rollback, encrypted restore, security smoke, smoke-level
      load, dependency audit, SBOM, and container builds exist.
    - No browser E2E suite covers login, scope creation, multi-profile scans,
      KEV sync, Guard inspection, and failure states.
    - Accessibility and cross-browser checks remain open.

11. **Release engineering** — **implemented, not exercised**
    - CI, CodeQL, dependency audit, SBOM, signed-release workflow, ruleset
      template, semver/changelog policy, and a staged-rollout/rollback runbook
      exist.
    - No git remote is configured, so branch protection and the release
      workflow have not run. No signed release exists.

### P2 — product and commercial readiness

12. Tenant onboarding, user administration, notifications, reporting/export,
    API documentation, support workflows, and usage metering.
13. Compliance workstream: SOC 2/ISO 27001 readiness, DPIA, terms, security
    questionnaire answers, and a vulnerability disclosure policy.
14. Multi-tenant isolation only after the single-tenant baseline is stable:
    tenant-scoped keys, row-level isolation, per-tenant rate limits, and
    cross-tenant test coverage.

## 4. Delivery estimate

| Target | Estimate | Main work |
|---|---|---|
| Demo / pilot build | **2–3 working days** | Restart/verify the demo, close packaging and configuration gaps, add the multi-profile flow, run the acceptance script |
| Single-tenant production | **5-8 working days** | Real VPS/Supabase deployment, OIDC against a live IdP, egress proof, browser E2E, signed release, and the Phase 18 gate |
| Multi-tenant SaaS | **4–6 weeks** | Tenant data plane, isolation, onboarding, billing/support, compliance and scale testing |

These estimates assume one experienced full-stack/DevOps engineer and no
procurement or compliance blockers. They are engineering estimates, not a
commitment.

## 5. Definition of done for the single-tenant pilot

- A new operator can sign in through the production identity provider with MFA.
- The live engine reads and writes PostgreSQL through migrations.
- A scope can be created, Nmap/Subfinder/TLS selected, and all selected scans
  complete or fail visibly with per-profile state.
- The browser never receives the engine key; the engine is not publicly
  reachable.
- TLS, secure cookies, CSP, rate limits, and egress controls are enforced.
- A backup can be restored into a clean environment within the documented RTO.
- Dashboards and alerts cover API availability, scan queue lag, feed freshness,
  and failed scans.
- The acceptance test covers login, authorization, scan selection, result
  reconciliation, audit verification, backup/restore, and rollback.
- The demo-only claims remain clearly labeled; no fixture result is presented as
  a live measurement.

Current evidence for the local, pre-deployment baseline:

- `tasks/evidence/postgres-backup-restore.json` - encrypted backup and
  destructive restore drill.
- `tasks/evidence/migration-rollback.json` - migration apply/rollback drill.
- `tasks/evidence/guard-evaluation.json` - deterministic Guard detector
  evaluation.
- `tasks/evidence/security-smoke.json` and `tasks/evidence/load-test.json` -
  runtime boundary and smoke-load checks.
- `tasks/evidence/sbom-python.json`, `tasks/evidence/sbom-frontend.json` -
  dependency SBOMs.

These do not prove a production deployment. The Phase 18 gate requires a real
deployment and human signoff.

## 6. Deliberate safety boundary

The console does **not** start Nmap or Subfinder merely because a URL was typed.
That would bypass the authorization and scope boundary. The implemented flow is:

1. operator enters a target;
2. operator selects one or more profiles;
3. operator confirms written authorization;
4. the scope is created;
5. one scan is queued per selected profile;
6. results are polled and combined.

If automatic execution is required later, the safe design is a **pre-approved
scope plus a scheduled or event-triggered run**, with the same authorization,
rate limits, and audit trail. It should not be an implicit side effect of an
input field.
