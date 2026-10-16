# 14-week ZeroTrace development plan

[← Wiki index](index.md) · Related: [Architecture](architecture.md) · [Readiness](operational-readiness.md) · [Execution Options](execution-options.md)

This is the selected 14-week development timeline, based on the project source. Weeks intentionally overlap where module work can proceed in parallel. Gates are targets; none is passed until test results or other evidence are recorded.

## Timeline

| Weeks | Focus | Deliverable | Evaluation gate |
|---|---|---|---|
| 1–2 | Skeleton: FastAPI, PostgreSQL, dashboard shell, authentication | `/health` works, login page and empty dashboard render | pytest: 5/5 health checks pass |
| 3–4 | Recon MVP: subdomain enumeration, Nmap, S3 checker, SSL expiry, Shadow IT | 3+ assets appear in the dashboard | `test_recon.py` passes (≥8/8 tests) |
| 5–7 | Intel MVP: NVD ingestion, EPSS correlation, ML scoring, fix-script proposals | Asset detail shows CVEs and exploit probability; proposal action available | `test_intel.py` passes (≥10/10); XGBoost top-20 achieves ≥60% CISA KEV overlap |
| 7–9 | Guard MVP: FastAPI gateway, regex filters, ONNX classifier, Ollama upstream, PII scanner | Jailbreak fixture blocked; normal prompt allowed | `test_guard.py` passes (≥12/12); ≥92% detection target on JailbreakBench |
| 9–11 | Integration: readiness score, unified dashboard, event bus | Score changes when assets, vulnerabilities, and attacks change | Full integration cycle passes; score follows the documented equation |
| 11–12 | Polish: Docker Compose, error handling, health checks, security headers | `docker compose up` works on a fresh machine | `make test` passes all 45+ tests |
| 13 | Target hardware evaluation | Demo script rehearsed; CPU/RAM and performance results recorded | Evaluation targets from [Operational Readiness](operational-readiness.md) measured on target hardware |
| 14 | Documentation and demo | GitHub repository, README, API docs, evaluation report, 5-minute demo | Reproducible setup and documentation complete |

## Phase guidance and exit criteria

### Weeks 1–2 — foundation

Freeze schema ownership, authentication model, Compose networks, migration workflow, logging policy, and CPU resource limits. Establish CI with PostgreSQL and Valkey, health checks, and a secure dashboard shell. Do not expose data stores to the host.

### Weeks 3–4 — Recon

Build the authorized-scope registry before scanner execution. Add fixtures, bounded timeouts, structured output parsing and provenance. Persist normalized assets and services; verify Shadow IT means inventory drift, not a claim of maliciousness. Gate: `test_recon.py` ≥8/8.

### Weeks 5–7 — Intel

Build repeatable NVD/EPSS snapshots, CPE matching evidence, and a transparent non-ML baseline before training XGBoost. Evaluate on time-separated data and compare to EPSS/CVSS/KEV. Generated remediation scripts remain proposals with isolated validation and human approval. Gate: `test_intel.py` ≥10/10 and KEV overlap target.

### Weeks 7–9 — Guard

Implement non-streaming OpenAI-compatible proxy behavior first, then classifier, PII scan and rate limiting. Calibrate thresholds using held-out malicious and benign datasets. Choose and document outage behavior for model, Redis and audit store; degraded protection must be visible. Gate: `test_guard.py` ≥12/12 and combined detection target.

### Weeks 9–11 — integration

Use durable/outbox event handling, idempotent consumers and replay/reconciliation. Connect Recon discoveries to Intel matching, vulnerability context to Guard prioritization, Guard outcomes to readiness, and patch events to verification rescans. Correct readiness fixtures using the equation in [Operational Readiness](operational-readiness.md); the combined sample computes to 73, not the source table's 71.

### Weeks 11–12 — polish

Test clean-machine Compose startup, migrations, failure recovery, health checks, authentication/RBAC, security headers, backups and restore. Run the full automated suite. Document configuration and safe scanning defaults.

### Week 13 — target-hardware evaluation

Run the defined module and integration test matrix on the target laptop, including CPU/RAM under concurrent scanning, ONNX inference and Ollama if enabled. The source identifies a 20 GB test machine and 16 GB minimum; report which profile and hardware were actually tested. Do not claim the approximate 9 GB target without measurement.

### Week 14 — documentation and demo

Complete setup instructions, API documentation, architecture and threat-model notes, evaluation results, known limitations, and a reproducible five-minute demonstration. Record all unmet targets and carry them into the post-plan backlog.

## Cross-cutting gates

- **Security:** threat-model review before exposing APIs; secrets never committed; least privilege; authorization scope enforcement; dependency scanning; upstream allowlists; audit integrity checks.
- **Reliability:** test NVD/EPSS outages, Redis outage, missing/slow models, malformed scanner output, upstream timeouts, database restore, and idempotent event replay.
- **Performance:** measure CPU/RSS under concurrent workloads; test the claimed ~9 GB target or document a reduced `core` profile and its tradeoffs.
- **Reproducibility:** pin images, model checksums, data/dataset versions and fixtures; record test commands, hardware, results and evaluation report.
- **Safety:** generated remediation is reviewed and tested in isolation; active Recon scans remain limited to authorized assets.
