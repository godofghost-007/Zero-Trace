# ZeroTrace Production Readiness Review

Date: 2026-10-25
Baseline: `feature/phase-17-production-hardening` at the Phase 17A/17B/17F
working tree
Scope: single-tenant, loopback-local demo and the path to a self-hosted service

## 1. Honest scorecard

| Measure | Current state | Assessment |
|---|---|---|
| Local demo completeness | React UI, Flask BFF, FastAPI engine, real Nmap/Subfinder/TLS adapters, scope authorization, auth/RBAC, audit, KEV sync, readiness panel | **~90%** |
| Single-tenant production readiness | PostgreSQL live-engine store, versioned migrations, MFA/OIDC/password reset, Caddy + container deployment, CI, production config validation; observability, encrypted offsite backup, restore drill, and release gate remain | **~70%** |
| Multi-tenant SaaS readiness | No tenant data plane, no per-tenant isolation, no billing/onboarding/SCIM | **not started** |

The project is a working full-stack application with a credible self-hosted
deployment path. It is not yet a production-ready release: Phase 17C–17E and
the Phase 18 gate are still open. The gap is mostly operational evidence,
observability, backup/restore, scanner runtime controls, and release process,
not missing UI or missing core logic.

## 2. What is already real

- **Full-stack wiring**: the browser talks only to Flask; Flask holds the engine
  API key and forwards to a loopback-only FastAPI engine.
- **Real Recon adapters**: four Nmap levels (Normal through Deep), four
  Subfinder levels, and a single-read TLS metadata adapter. No exploitation,
  brute force, NSE scripts, or automatic remediation.
- **Explicit authorization**: the BFF requires an operator acknowledgement for
  scope and scan creation. High and Deep profiles additionally require a DNS TXT
  ownership challenge and an `isolated_lab` scope. Normal and Medium are bounded
  and do not require DNS TXT, but can opt into the same blue DNS TXT check. Scans
  can only use targets and profiles in an approved, time-bounded scope.
- **Auth/RBAC**: opaque session cookie, per-session CSRF token, ordered
  `viewer < operator < admin` roles, login rate limiting, database-backed
  lockout, TOTP MFA, optional OIDC, password reset, session inventory and
  revocation, and auth audit events. See `docs/AUTH-MATRIX.md`.
- **Durable demo state**: SQLite remains the zero-dependency demo fallback.
- **PostgreSQL live path**: the live engine selects PostgreSQL when
  `DATABASE_URL` is set, uses pooled connections, and has versioned migrations
  with apply/rollback tests. SQLite remains available for the local demo.
- **Deployment path**: Caddy TLS/security headers, non-root BFF and engine
  containers, healthchecks, resource limits, loopback-only engine URL, and a
  documented Supabase/migration/backup runbook in `deploy/README.md`.
- **Intel**: CISA KEV ingestion is exposed in the UI; NVD and EPSS remain
  API/schedule-only. The demo does not invent feed results.
- **Quality evidence**: 225 root tests (including disposable PostgreSQL
  databases), 32 BFF tests, 6 frontend tests, frontend type-check, production
  build, and both container builds passed at this baseline.
- **New profile selection**: the Targets console lets the operator select Nmap,
  Subfinder, TLS, and synthetic inventory. Nmap and Subfinder each have their
  own Normal/Medium/High/Deep dropdown inside the profile card. It queues one
  scan per selected profile and combines the results. The default is Nmap +
  Subfinder at Normal when both adapters are installed. The blue DNS TXT check
  is required for High/Deep and optional for Normal/Medium.

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
     non-root images, healthchecks, resource limits, and a rollback runbook exist.
   - Edge rate limiting, egress allowlist proof, and a real VPS/Supabase
     deployment remain open.

4. **Scanner safety and capacity** — **partially implemented**
   - Four bounded levels, queue depth, per-target cooldown, concurrency limit,
     retries, cancellation, hard timeouts, and output caps exist.
   - Runtime scanner version verification, sandbox proof, and explicit
     target allow/deny policy remain open.
   - Normal and Medium are bounded and require the BFF acknowledgement. High and
     Deep require DNS TXT ownership verification. No level enables exploitation,
     brute force, NSE scripts, or automatic remediation.

5. **Backups and disaster recovery** — **open**
   - Encrypted off-host backups, retention, restore drills, RPO/RTO targets, and
     a recovery runbook are still required.

6. **Observability and operations** — **open**
   - Structured logs with request IDs exist; metrics, traces, dashboards, alerts,
     error tracking, SLOs, and on-call ownership are still required.

### P1 — required before general production use

7. **Intel pipeline hardening**
   - Full live NVD pagination, feed retries/backoff, deduplication, provenance,
     CVE-to-service matching quality, and false-positive review.
   - EPSS and KEV freshness indicators in the UI.
   - Rate-limit and API-key handling for NVD.

8. **Guard hardening**
   - Evaluate the regex/heuristic detector against a labeled corpus.
   - Add response scanning/redaction, policy configuration, upstream model
     allowlisting, and false-positive/negative metrics.
   - Keep inspect-only as the default; the optional OpenAI-compatible upstream
     gateway is behind explicit configuration and still needs evaluation.

9. **Data protection and lifecycle**
   - Encryption at rest and in transit, key rotation, retention/deletion
     policies, PII handling, data residency, and tenant export/delete.
   - Privacy review and a data-processing agreement for real customer data.

10. **Testing and quality gates**
    - End-to-end browser tests for login, scope creation, multi-profile scans,
      KEV sync, Guard inspection, and failure states.
    - Migration tests, load/performance tests, security tests, dependency and
      container scanning, SBOM, and a restore test in CI.
    - Accessibility and cross-browser checks for the operator console.

11. **Release engineering**
    - CI/CD with signed artifacts, branch protection, changelog, semantic
      versioning, staged rollout, and a rollback gate.
    - Environment configuration validation and a production configuration
      checklist.

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
| Single-tenant production | **10–15 working days** | PostgreSQL live path, SSO/MFA, deployment hardening, backups, observability, E2E and security gates |
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
