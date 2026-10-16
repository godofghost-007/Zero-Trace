# ZeroTrace — compiled project wiki

> **Purpose:** CPU-optimized, open-source cyber defense for one laptop: Recon discovers assets, Intel prioritizes vulnerabilities, and Guard protects LLM traffic. PostgreSQL is the shared source of state; Redis/Valkey carries events; SQLite stores a local tamper-evident Guard audit chain.

**Compiled from:** `ZeroTrace—ProjectDocumentationv2.0.pdf` (version 2.0, August 2026), treated as the immutable source. This wiki is the maintained, navigable interpretation; when it differs from the source, record the discrepancy here and in the affected page rather than silently rewriting the source.

## Navigation

| Page | Scope | Readiness |
|---|---|---|
| [Architecture](architecture.md) | Topology, ERD, events, hardware and deployment boundaries | Compiled; resource budget needs measurement |
| [Trace Recon](trace-recon.md) | Discovery, scans, shadow IT, errors | Compiled; implementation and authorization controls pending |
| [Trace Intel](trace-intel.md) | NVD/EPSS, asset-CVE matching, model, patch queue, assisted fixes | Compiled; training data/model validation pending |
| [Trace Guard](trace-guard.md) | OpenAI-compatible gateway, injection controls, PII and audit | Compiled; classifier, policy, and fail-open decisions need validation |
| [Operational Readiness](operational-readiness.md) | Score formula, interpretation, evaluation matrix | Compiled; source arithmetic has unresolved inconsistency |
| [Development Plan](development-plan.md) | 14-week development schedule and phase gates | Compiled; proposed schedule, not evidence of completion |
| [Execution Options](execution-options.md) | Scratch architecture and battle-tested reuse/merge strategy | Researched; licensing and integration tests remain gates |

## System at a glance

- **Recon:** passive subdomain enumeration (Subfinder/certificate streams), Nmap top-100 service discovery, S3 configuration checks, TLS certificate expiry monitoring, and inventory-difference/Shadow IT flags.
- **Intel:** incremental NVD CVE and daily FIRST EPSS ingestion; CPE/service-version correlation; XGBoost-based exploit likelihood prioritization; a rolling 48-hour urgency focus; generated remediation proposals with mandatory review and isolated validation.
- **Guard:** FastAPI `/v1/chat/completions` reverse proxy; cheap regex/heuristic prefilter; CPU ONNX DistilBERT semantic detector; response PII scanner; per-client token-bucket rate limiting; SQLite SHA-256 chained audit records.
- **Integration:** durable relational state in PostgreSQL; Redis-compatible event bus (Valkey is a drop-in project choice); deterministic readiness score recomputation on `asset_created`, `vuln_matched`, `attack_blocked`, and `vuln_patched`.
- **Deployment target:** Docker Compose, CPU-only, 16 GB RAM minimum in the source; user-stated goal is approximately 9 GB total on a 16 GB laptop. Treat this as a benchmark target, not a proven footprint.

## Readiness snapshot

| Area | State | Evidence / next gate |
|---|---|---|
| Source ingestion | Complete | Full 26-page PDF extracted once during initial setup |
| Wiki compilation | Complete | Requested pages plus execution-options page linked above |
| Architecture decision | Drafted | Validate exact service boundaries, event delivery guarantees, and memory on target laptop |
| Recon / Intel / Guard code | Not started | Follow phased implementation and tests |
| Evaluation | Not run | Use the matrix in [Operational Readiness](operational-readiness.md) |
| Production hardening | Not ready | Threat model, review gates, auth, secrets, backups, scan authorization, and fail modes must be implemented and tested |

## Source interpretation and known discrepancies

1. The PDF’s memory map names 20 GB as the tested/comfortable baseline and lists OS/WSL, Ollama, and services separately. It does not substantiate a measured 9 GB *whole laptop* footprint on 16 GB. Measure peak resident memory with the selected model loaded and scanning; optimize or provide a reduced profile if needed.
2. The stated score formula gives `100 − (0.40×AEI + 0.40×VUI + 0.20×AIET)`. The validation row for combined indexes `20, 35, 25` yields **73**, not the printed 71. The end-to-end sequence also includes values inconsistent with the shown formula. See [Operational Readiness](operational-readiness.md); preserve the equation as the governing definition until product owners correct the scenario fixture.
3. The 48-hour patch queue is an operational ranking window, not the EPSS forecast horizon. FIRST describes EPSS as a probability of exploitation in the next 30 days. Keep those semantics distinct.
4. User brief says “S3”; the source calls for S3 misconfiguration checks but does not define API provider or credential model. Default to passive/public checks and explicit opt-in for authenticated account checks.
5. “Auto-fix” is assistance, not autonomous production change: source explicitly calls for syntax validation, sandboxing, and human review. Never execute generated scripts against a real target by default.

## Operating contract

1. Read this `index.md` first on later sessions; then open only the relevant page(s), never the immutable PDF or a raw dump unless explicitly instructed to audit a source claim.
2. Keep each concern in its owning page and link across pages rather than duplicating detailed specifications.
3. Label facts from the source versus implementation decisions and unresolved assumptions.
4. Update readiness states only when an implementation artifact or test evidence exists.
5. External scanning must be limited to assets the operator is authorized to assess; set timeouts, rate limits, concurrency bounds, and an allowlist.
