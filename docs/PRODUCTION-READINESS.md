# ZeroTrace Production Readiness Review

Date: 2026-10-24
Baseline: local `main` at `6e932a9` plus the current working tree
Scope: single-tenant, loopback-local demo and the path to a production service

## 1. Honest scorecard

| Measure | Current state | Assessment |
|---|---|---|
| Local demo completeness | React UI, Flask BFF, FastAPI engine, real Nmap/Subfinder/TLS adapters, scope authorization, auth/RBAC, audit, KEV sync, readiness panel | **~90%** |
| Single-tenant production readiness | SQLite live engine, local admin account, development Flask server, no SSO/MFA, no production deployment or observability | **~60%** |
| Multi-tenant SaaS readiness | No tenant data plane, no per-tenant isolation, no billing/onboarding/SCIM | **not started** |

The project is a working full-stack application. It is not yet a production
service. The gap is mostly operational hardening, identity, durable storage,
deployment, and evidence, not missing UI or missing core logic.

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
  `viewer < operator < admin` roles, login rate limiting, session revocation,
  and an audit chain.
- **Durable demo state**: SQLite persistence for scopes, scans, intel snapshots,
  Guard counters, and readiness; backup/restore has been exercised.
- **PostgreSQL path**: a disposable PostgreSQL smoke test exists; it is not yet
  the live engine's production data path.
- **Intel**: CISA KEV ingestion is exposed in the UI; NVD and EPSS remain
  API/schedule-only. The demo does not invent feed results.
- **Quality evidence**: 218 root tests, 25 BFF tests, 6 frontend tests, frontend
  type-check, and a production build passed at this baseline.
- **New profile selection**: the Targets console lets the operator select Nmap,
  Subfinder, TLS, and synthetic inventory. Nmap and Subfinder each have their
  own Normal/Medium/High/Deep dropdown inside the profile card. It queues one
  scan per selected profile and combines the results. The default is Nmap +
  Subfinder at Normal when both adapters are installed. The blue DNS TXT check
  is required for High/Deep and optional for Normal/Medium.

## 3. What is still demo-grade

### P0 — required before a single-tenant production pilot

1. **PostgreSQL as the live data path**
   - Move scopes, scans, intel facts, findings, Guard events, readiness
     snapshots, users, sessions, and audit records to PostgreSQL.
   - Add versioned migrations, connection pooling, transaction boundaries, and
     a migration/rollback test.
   - Replace the current "smoke-tested path" claim with a live-engine run.

2. **Production identity**
   - SSO via OIDC or SAML; MFA; password reset/disable flows.
   - Session/device inventory, forced revocation, and idle/absolute timeouts.
   - Per-tenant role checks and an authorization matrix; remove the single local
     bootstrap account as the only identity path.
   - Secrets in a managed secret store, not local files or environment defaults.

3. **Production deployment**
   - Run Flask under a production WSGI server (for example Gunicorn) behind a
     TLS-terminating reverse proxy.
   - HSTS, secure cookies, strict CSP, request-size limits, edge rate limits,
     and egress allowlists.
   - Reproducible container images, health/readiness probes, resource limits,
     non-root users, and a documented rollback.

4. **Scanner safety and capacity**
   - Keep the four bounded levels, then add queue concurrency limits, per-target
     rate limits, cancellation, hard timeouts, output caps, and scanner
     sandboxing.
   - Package or pin Nmap/Subfinder and verify their versions at startup.
   - Add explicit target allow/deny policy and a pre-approved-scope path for
     scheduled or automatic runs.
   - Normal and Medium are bounded and require the BFF acknowledgement. High and
     Deep require DNS TXT ownership verification. No level enables exploitation,
     brute force, NSE scripts, or automatic remediation.

5. **Backups and disaster recovery**
   - Encrypted database and object backups, off-host copies, retention policy,
     restore drills, RPO/RTO targets, and a documented recovery runbook.
   - Current local backup files are not production-grade.

6. **Observability and operations**
   - Structured logs with request IDs, metrics, traces, dashboards, alerts, and
     error tracking.
   - SLOs for API availability, scan completion, feed freshness, and queue lag.
   - On-call ownership, incident response, upgrade/rollback runbooks, and
     capacity planning.

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
   - Keep the current inspect-only guarantee until the upstream gateway is
     implemented and tested.

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
