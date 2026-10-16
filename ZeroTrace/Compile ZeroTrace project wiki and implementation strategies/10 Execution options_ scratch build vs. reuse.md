# Execution options: scratch build vs. reuse

[← Wiki index](index.md) · Related: [Architecture](architecture.md) · [Development plan](development-plan.md)

## Approach A — scratch build, minimal paper architecture

Build the orchestration and domain model yourself, but delegate scanning and model inference to mature libraries/binaries. Keep each module a thin adapter and avoid building a generic SIEM, custom ORM, or frontend bundle.

### Suggested repository layout

```text
zerotrace/
├── compose.yaml
├── .env.example
├── pyproject.toml
├── README.md
├── app/
│   ├── api/                 # FastAPI routes, schemas, auth dependencies
│   ├── dashboard/           # Flask UI, HTMX templates, Alpine sprinkles
│   ├── domain/              # Asset, CVE, policy and readiness rules
│   ├── db/                  # SQLAlchemy models, Alembic migrations, session
│   ├── events/              # outbox, publisher, idempotent subscribers
│   ├── recon/               # scope, subfinder/nmap/S3/TLS adapters
│   ├── intel/               # feeds, CPE matcher, ranking, proposal validation
│   ├── guard/               # proxy, regex, ONNX, PII, rate limiter, audit
│   └── settings.py
├── templates/               # Jinja2 + HTMX
├── static/                  # minimal CSS, Alpine.js
├── migrations/
├── models/                   # checksummed ONNX/model metadata, not huge weights in git
├── scripts/                  # model download, admin bootstrap, backup/restore
├── tests/                    # unit, integration, controlled fixtures
└── docs/
```

### Lightweight implementation plan

- **FastAPI** for typed control API, OpenAPI docs, async upstream proxy and Guard interface.
- **Flask + HTMX + Alpine.js** only for server-rendered dashboard; Flask-Login session and CSRF. Share domain/service layer and SQLAlchemy models; do not call internal HTTP endpoints for every template action unless separate process boundary is intentional.
- **PostgreSQL + SQLAlchemy 2 + Alembic** as durable canonical state; bind internally. **Valkey** for event notifications, cache and token buckets. Add outbox if event loss is unacceptable.
- **SQLite** in Guard for small append-only audit metadata chain. Use WAL/transaction discipline, canonical row encoding, previous-hash linking, startup integrity verification, and exported checkpoints.
- **Subfinder / Nmap** as subprocess adapters with argument arrays, no shell, safe profiles, bounded concurrency, strict target allowlist, output parsing and timeouts.
- **ONNX Runtime** CPU inference for Guard. Pin the classifier, tokenizer and label map; cache session; cap sequence length; measure p95 latency.
- **XGBoost** optional until a baseline proves it adds value. Put model behind `Scorer` interface; keep feature transformation/version in code.
- **Ollama** optional profile for Qwen2.5-Coder proposal generation only. No generated script auto-execution.

A paper architecture can start with one FastAPI process plus one background worker and a Flask UI, then split workers when scale/testing warrants it. HTMX and Alpine are small frontend dependencies, but the true RAM budget is dominated by the local LLM and database/model loading, not frontend libraries.

## Approach B — customize and integrate mature upstream projects

“Reuse” should mean use the maintained project at its stable boundary, not copy source wholesale. Pin versions/digests, preserve upstream licenses and notices, isolate adapters, and build ZeroTrace-specific scope, normalization, evidence, policy and tests around them.

| Capability | Candidate and boundary | Integration/customization plan |
|---|---|---|
| Passive subdomains | [ProjectDiscovery Subfinder](https://github.com/projectdiscovery/subfinder), CLI/JSONL or Go library; MIT | Package pinned binary in `recon-worker`; invoke `-d <authorized-domain> -json`; parse JSONL into normalized observation; retain provider/source provenance; configure API keys via secrets and rate limits; avoid active discovery unless authorized. |
| Port/service discovery | [Nmap](https://github.com/nmap/nmap) binary + XML output; Nmap has a custom license, not simply GPLv2 | Install only in Recon image; call safe, fixed profiles and `-oX -`; parse XML, store product/version/CPE evidence. Review license before redistribution; users can install separately if redistribution terms are incompatible. Never expose a general arbitrary-argument scan endpoint. |
| Python parsing wrapper | [python-nmap](https://github.com/home-assistant-libs/python-nmap) optional adapter, not scanner | Consider if its maintenance/API fit is validated; direct XML parser may be smaller and reduce dependency surface. Nmap itself must be installed. |
| Vulnerability feeds | [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities), [FIRST EPSS](https://www.first.org/epss/) official API/CSV | Use direct clients and durable normalized tables; NVD pagination/incremental modified windows; cache last-good; ingest EPSS daily with source date. Do not wrap a third-party SDK without checking API freshness/rate behavior. |
| ONNX export/runtime | [Hugging Face Optimum ONNX](https://huggingface.co/docs/optimum-onnx/en/onnx/usage_guides/export_a_model), [Optimum ONNX repo](https://github.com/huggingface/optimum-onnx) | Choose an actually trained prompt-injection classifier (DistilBERT architecture alone is not a detector); pin model revision, tokenizer, labels and license; export/validate ONNX; run CPU provider; evaluate on disjoint JailbreakBench/benign sets and calibrate threshold. Ship weights outside git with checksum and reproducible download. |
| LLM gateway | [LiteLLM](https://github.com/BerriAI/litellm) / [proxy docs](https://docs.litellm.ai/docs/) or a small FastAPI-native proxy | LiteLLM already offers an OpenAI-compatible gateway, auth/keys, logging and guardrail hooks. Prototype it as an upstream gateway with a custom guardrail integration. If memory/dependency weight or callback semantics are unsuitable, implement only the narrow FastAPI `/v1/chat/completions` proxy; do not merge LiteLLM source into ZeroTrace. Verify streaming, exception behavior, and local Ollama routing. |
| API service framework | [FastAPI](https://github.com/fastapi/fastapi) | Use routers/dependencies/middleware, OpenAPI schemas, lifespan hooks and test client; custom code only for ZeroTrace policies and domain model. |
| XGBoost | [xgboost](https://github.com/dmlc/xgboost) | Use CPU histogram predictor with small pinned model; compare against EPSS/KEV baseline and persist model/feature metadata. |

### Merge and adoption sequence

1. Create adapter interfaces first (`SubdomainProvider`, `PortScanner`, `CveFeed`, `ExploitScorer`, `PromptDetector`, `LlmUpstream`). Tests should use fake implementations.
2. Pilot each upstream independently in a container with resource/network limits. Capture license, version/commit, image digest, data/model revision and SBOM.
3. Add only the binary/library/runtime and adapter. Avoid vendoring or forking unless an upstream bug cannot be worked around; if a fork is unavoidable, track upstream remote, patch set and rebase plan.
4. Normalize outputs into ZeroTrace-owned schemas; never let upstream tool-specific schema become the shared database contract.
5. Add golden-fixture tests and controlled lab integration tests before enabling a tool in normal Compose profile.
6. Pin by release and container digest; automate dependency/security updates; review breaking changes and licenses. Nmap redistribution requires special attention.
7. Keep degraded/fallback behavior explicit. A missing ONNX file, stale feed or unavailable model must produce a visible status—not an apparently healthy result.
8. Compare CPU/RAM and correctness against scratch adapter before deciding whether to keep the dependency.

## Recommended path

Use a **hybrid**: write ZeroTrace’s schema, scope controls, event/outbox, score engine, dashboard and policy layer from scratch; integrate Subfinder, Nmap, official NVD/EPSS feeds, ONNX Runtime/Optimum tooling, and Ollama at stable process/API boundaries. Pilot LiteLLM for proxy functionality, but retain a small FastAPI proxy as a viable fallback where lean resource use and precise pipeline control outweigh the integration breadth. This keeps domain logic understandable while avoiding reimplementing scanners or inference runtimes.

## Sources and current-upstream checks

- Subfinder README documents passive subdomain discovery, JSONL output, source provenance and optional provider credentials: [repository](https://github.com/projectdiscovery/subfinder).
- Nmap repository documents its custom license and directs users to its official install/manual pages: [repository](https://github.com/nmap/nmap).
- NVD documents paginated CVE API 2.0 and change-history endpoints: [developer documentation](https://nvd.nist.gov/developers/vulnerabilities).
- FIRST describes daily 0–1 EPSS probabilities, 30-day horizon, API and CSV: [EPSS](https://www.first.org/epss/).
- Hugging Face documents ONNX export and ONNX Runtime model loading: [Optimum ONNX guide](https://huggingface.co/docs/optimum-onnx/en/onnx/usage_guides/export_a_model).
- LiteLLM documents its self-hosted OpenAI-compatible proxy and guardrails: [docs](https://docs.litellm.ai/docs/).
