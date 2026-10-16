# Trace Recon — attack surface discovery

[← Wiki index](index.md) · Related: [Architecture](architecture.md) · [Intel](trace-intel.md) · [Development plan](development-plan.md)

## Mission

Find authorized assets and exposed services, retain evidence and provenance, flag inventory drift (potential Shadow IT), and hand normalized records to Intel. Recon is a discovery system, not an exploit tool. Its output must be limited to explicitly scoped targets.

## Inputs and outputs

**Inputs:** authorized root domain/CIDR or account scope; known inventory; scan profile; concurrency/rate/time limits; optional provider credentials for source APIs.

**Outputs:** canonical assets, services, SSL status, S3 findings, scan run and provenance, inventory delta, structured warnings and partial-result status. Emit `asset_created` only after the transaction commits. Repeated scans upsert stable identities and append observations instead of duplicating assets.

## Pipeline

1. **Scope validation:** normalize and check target against an allowlist and proof/approval record. Reject wildcard or out-of-scope targets. Do not launch on a raw user-supplied hostname without scope validation.
2. **Passive discovery:** query certificate transparency feeds and Subfinder. Preserve source names, timestamps and confidence. Subfinder's passive mode discovers subdomains from online sources; some providers require API keys. DNS-resolve candidates and mark unresolved entries rather than silently treating them as live.
3. **Service scan:** run Nmap on authorized resolved targets, default to top 100 TCP ports as specified by the source. Use controlled flags, bounded concurrency, per-target timeouts and structured XML output. Scan findings are observations, not proof that a service is vulnerable.
4. **S3 checks:** check bucket naming/access/configuration only through approved public checks or explicitly authorized cloud credentials. Distinguish public-readable, public-listable, denied, unknown, and transient error. Never upload/delete objects or attempt access beyond the permission test.
5. **TLS checks:** connect with a timeout, record certificate subject/SAN, issuer, validity window, chain/handshake error, and check time. Separate “expired”, “expires soon”, “unreachable”, and “unknown”.
6. **Shadow IT delta:** compare normalized discoveries with a reviewed inventory/owner mapping. Flag new/unowned/stale assets as “unmanaged candidate”; do not assert maliciousness solely from absence in inventory.
7. **Persist + publish:** transactionally upsert assets/services and observations, then publish durable `asset_created`/updated events via the outbox. Intel consumes changes for matching.

## Data and API contract

Suggested API: `POST /api/recon/scans` creates a job (202 + `scan_id`); `GET /api/recon/scans/{scan_id}` returns state and progress; `GET /api/assets` and `GET /api/assets/{id}` return normalized inventory with last-seen and provenance. Operator role may scan only approved scopes; viewer is read-only. Idempotency key prevents duplicate jobs on retries.

Record `scan_id`, `scope_id`, tool/version, exact safe profile, start/end, exit code, parse status, target count, result count, warnings and a protected reference to raw output. Do not store scanner secrets in result payloads.

## Error handling (source requirements)

| Failure | Detection | Recovery |
|---|---|---|
| Subfinder timeout | Exceeds 120 s in source target | Terminate process, retain partial results, warn; make timeout configurable per profile |
| Nmap returns zero open ports | No open findings | Mark “no ports observed / may be filtered”; do not claim host is safe |
| S3 API HTTP 429 | Rate limit | Exponential retry; source says 3 attempts at 30/60/120 s (this represents three waits/retries; implement bounded policy and honor Retry-After) |
| SSL connection refused | Handshake/connect failure | Mark unreachable; continue other checks |
| DNS NXDOMAIN | Resolver response | Return target error; do not queue dependent active scans |
| Scanner process failure | Non-zero exit or malformed output | Mark partial/failed with stderr excerpt sanitized; never parse failure as an empty successful scan |

## Operational controls

Default safe rates; global worker semaphore; per-scope caps; hard timeout; cancel endpoint; process-group termination; output size limit; no shell interpolation (argument arrays); container filesystem read-only where possible. Nmap raw packet scanning may require privileges; prefer unprivileged connect scans, avoid host networking/capabilities unless documented and needed. Re-run variability only as an evaluation mode; production does not need three full scans for each target.

## Evaluation targets from the source

- Subdomain recall ≥90% and precision ≥95% against declared-scope domains.
- Nmap parity with standalone on the same controlled lab, not internet targets.
- S3 false positives ≤5%; false negatives ≤10% on 25 known-public + 25 known-private fixtures.
- SSL expiry accuracy 100% against 50 known certificates.
- Detect all 10 intentionally planted inventory-only assets.
- Full run on 50 subdomains ≤10 minutes.

Track sample size, ground-truth date, source coverage, tool version, allowed scan profile and confidence intervals; these source targets are acceptance goals, not measured results.
