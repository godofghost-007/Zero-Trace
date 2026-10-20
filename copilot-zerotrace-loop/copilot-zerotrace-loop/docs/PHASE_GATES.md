# ZeroTrace Phase Gates (0–18)

Use the supplied *ZeroTrace Development Phases* as the source order. Each gate needs a record in `tasks/evidence/phase-NN.md` and human signoff. A checklist is not proof: include commands, outputs, test results, links, and unresolved risks. If a relevant criterion is not met, mark the phase BLOCKED; never bypass it by renumbering.

| Phase | Exit gate evidence |
|---|---|
| 0 — Environment baseline | Actual OS, Docker/WSL2/Python/Git versions and available RAM/disk recorded; repo root confirmed; clean startup/test baseline; `.env.example`, ignore rules and README checked; hosted-data policy decided. |
| 1 — Specification/architecture lock | Service boundaries, entities, API/event contracts, auth roles, score semantics, denominator handling and security boundaries documented; outbox-vs-Streams choice recorded; open decisions resolved or explicitly block dependent work. |
| 2 — Skeleton/core domain | App starts; config validation fails clearly; migrations run on disposable DB; domain/error/logging/health code has unit tests; reproducible setup command recorded. |
| 3 — Readiness score | Formula and component definitions/version frozen; scenario fixtures independently calculated; bounds, monotonicity, unknown/zero denominator, recovery and reproducibility tests pass; discrepancies (including combined case) resolved in writing. |
| 4 — Auth/platform security | Unauthenticated and role-negative tests pass; password/API key handling, CSRF, headers, size limits, secret loading, private service networking and audit permissions tested; secrets absent from repo/logs. |
| 5 — Event/persistence reliability | Event envelope/version and durability design implemented; commit-before-publish, idempotence, retry/backoff, dead-letter/reconcile and duplicate/failure tests pass; no silent loss. |
| 6 — Recon MVP | Only approved lab/scope; fixed safe scanner profiles and scope enforcement tested; no shell interpolation/unrestricted flags/destructive S3; timeout/cancel/rate limits/partial failures visible; results persisted and event-after-commit tested. |
| 7 — Intel ingestion | NVD/EPSS/KEV adapters validated; pagination/incremental sync/rate-limit/cache behavior tested; idempotence, malformed quarantine, last-known-good and freshness behavior proven. |
| 8 — Asset/CVE correlation | Deterministic fixture matches pass; version ranges/evidence recorded; uncertain match remains unconfirmed/reviewable; product-name similarity alone cannot confirm; rematching preserves observation. |
| 9 — Prioritization | Transparent baseline exists; model used only if measured improvement is justified; time-split leakage checks, calibration, model/feature version and artifact checksum recorded; 48-hour queue semantics and explanations tested. |
| 10 — Assisted remediation | Proposals are schema-validated and never auto-run in production; dangerous/privilege-escalating operations rejected; static/syntax checks and disposable-fixture tests pass; provenance, digest, approval and rollback notes recorded. |
| 11 — Guard MVP | Non-streaming proxy schema/auth/rate/size/timeout/upstream TLS allowlist/error envelopes tested; attack and benign fixtures evaluated; PII policy tested; missing model/dependency and audit failure states explicit; audit-chain tamper test passes. |
| 12 — Guard/local model integration | Exact model/tokenizer/labels/license/checksum pinned; latency/RAM measured; absence/timeout yields explicit degraded behavior; core profile works without Ollama; concurrency bounded. |
| 13 — Dashboard/unified workflow | Authorized roles see appropriate assets, services, CVEs, queue, Guard and score; asset→service→vuln→endpoint trace verified; stale/degraded/error status visible; no sensitive prompt leakage. |
| 14 — Integration/E2E | End-to-end synthetic/lab flow Recon→Intel→Guard→score→proposal→verification passes; duplicate/retry/restart/outage/partial failure/tamper scenarios tested; unavailable optional services report degraded. |
| 15 — Resource/reliability | Cold start, per-service/peak RAM, CPU, model load, Guard latency, scan concurrency, DB latency/size, swap and concurrent profile measured on exact target laptop; 9GB is treated as an unproven target; core/full/dev profile and headroom documented. |
| 16 — Security hardening | Threat review covers auth, CSRF, SSRF, scanner scope/processes, S3, SQL, secrets, retention, audit limits, Docker, dependencies, remediation, backup, rate limits and DoS; no unresolved critical/high issues without explicit risk acceptance; negative tests pass. |
| 17 — Packaging/operations | README covers clean install, profiles/env/migrations/backup/restore/model licenses/scan authorization/privacy/health/logs/rollback; clean-machine deployment and safe no-real-credential demo succeed; restore tested. |
| 18 — Release readiness | Full tests, type/lint/build, security review, integration, measured resource targets, docs, dependency/license review, restore and degraded-state checks complete; no auto-production remediation; scanning authorization confirmed; history/diff reviewed; human signs release. |

## Phase transition record

For every phase, record: phase ID; commit/hash; date/environment; criteria and PASS/FAIL/BLOCKED; exact command/test and result; manual checks; risks/accepted exceptions; approver and decision. Exceptions cannot waive legal authorization or secret handling. Any architecture or scope change updates the spec/ADR first and may invalidate downstream evidence.
