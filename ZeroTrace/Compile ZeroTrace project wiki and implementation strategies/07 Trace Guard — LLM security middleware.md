# Trace Guard — LLM security middleware

[← Wiki index](index.md) · Related: [Architecture](architecture.md) · [Intel](trace-intel.md) · [Operational Readiness](operational-readiness.md)

## Contract

FastAPI reverse proxy exposing an OpenAI-compatible `/v1/chat/completions` interface. Authenticated LLM clients send requests through Guard; Guard applies rate limits, fast regex/heuristic rules, an ONNX DistilBERT semantic classifier, forwards accepted traffic to a configured upstream (including local Ollama), scans output for possible PII, then returns a compatible response and records minimal audit metadata.

Support non-streaming first. Streaming requires incremental policy decisions and response PII scanning; do not claim full output protection until the stream can be buffered or scanned safely. Preserve status/error semantics, timeouts, cancellation and request IDs. Restrict upstream hosts to configured allowlists to prevent SSRF.

## Request pipeline

1. Enforce request body size, JSON schema, client API key and per-client token bucket.
2. Normalize prompt text while retaining message boundaries and modality metadata; do not flatten untrusted context into privileged instructions.
3. Apply fast regex and heuristic rules. Hard-block only high-confidence policies; record rule/version.
4. Run ONNX DistilBERT classifier under a strict CPU time budget. Use validated local tokenizer/model files and calibration threshold. Score is a signal, not proof; threshold decisions are measured against false positive/negative costs.
5. On allowed requests, proxy upstream with a bounded timeout and request correlation ID.
6. Scan response text for possible PII (SSN, emails, card numbers, API-key patterns). Redact only according to explicit policy; distinguish `potential PII` from confirmed matches and preserve the original response only if an approved, access-controlled retention policy requires it.
7. Append event to SQLite audit chain; return response and Guard headers/metadata. Record block reason and classifier/rule versions without persisting prompt/response plaintext by default.
8. Publish `attack_blocked` and linked endpoint context to event bus; Intel CVE association can elevate priority.

## Components and interfaces

- FastAPI route compatible with `/v1/chat/completions`; include `/health`, `/ready`, and internal diagnostics with no sensitive data.
- Detector interface: `classify(messages) -> {score, label, model_version, latency_ms}`; deterministic regex detector is usable if model unavailable, with health state `DEGRADED`.
- PII scanner returns typed candidate spans and confidence; tests cover false positives and redaction boundaries.
- Rate limiting via Valkey token bucket keyed by hashed client identity. Never use raw API keys as Redis keys or logs.
- SQLite append-only logical table fields: sequence, UTC timestamp, event type, client pseudonym, endpoint ID, outcome, scores, rule/model versions, previous hash, row hash. Hash canonicalized serialized event + previous hash using SHA-256. Add periodic signed/exported checkpoints if stronger tamper evidence is needed.

## Audit integrity and privacy

A hash chain detects interior modification/deletion when a trusted prior/final checkpoint exists; it does **not** prevent an administrator from deleting the whole file or rewriting all rows. Keep filesystem permissions restrictive, use append-only transactions, run `verify_audit_integrity()` on startup and scheduled checks, and export checkpoints to a separate protected location. Minimize data: prompt hash or keyed HMAC, lengths, detector outcomes and endpoint identifiers are preferred to raw prompt text. Hashes of low-entropy prompts can be guessable; use HMAC with a secret if correlation is needed. Document retention and access.

## Source error behavior and policy decisions

| Failure | Source behavior | Recommended implementation note |
|---|---|---|
| ONNX missing/version mismatch | Regex-only; critical warning; dashboard DEGRADED | Make semantic bypass visible and configurable; do not represent as full protection |
| Inference >200 ms | Skip semantic check and forward with unverified flag | For high-risk deployment, consider fail-closed or queue/deny; source specifies fail-open forwarding |
| Upstream unreachable | 502, log error, no cache | Return OpenAI-compatible error envelope and correlation ID |
| PII likely false positive | Log `potential PII`, require manual review | Avoid destructive redaction without policy; don’t log the sensitive span |
| Redis rate limiter unavailable | Source says fail-open and critical alert | Security-critical tradeoff; use local bounded limiter or fail closed by policy, and test outage behavior |
| SQLite append failure | Not specified | Recommended: fail closed for protected requests if audit is mandatory, or explicit degraded mode and alert; never silently discard audit |

## Security boundaries

Guard has dedicated API-key auth; keys stored as hashes, rotated and scoped. Use request/response size limits, concurrency caps, per-client quotas, upstream TLS verification, SSRF allowlists, DNS rebinding precautions, timeouts, and safe exception handling. Never pass secrets through classifier prompts or logs. A blocked prompt is not necessarily a verified attack; mark classifier confidence and outcome separately.

## Evaluation targets from source

- Regex catches ≥60% of 500 JailbreakBench prompts.
- Semantic classifier catches ≥85%; full pipeline ≥92% on that set.
- ≤5% false positives on 500 legitimate ShareGPT prompts.
- PII recall ≥90% on 100 responses containing seeded SSN/API key/email/card patterns; false-positive redaction ≤10% on 100 clean responses.
- Guard adds ≤50 ms to a nominal 500 ms direct response; regex ≤5 ms; ONNX ≤20 ms per prompt.
- Of 100 requests in 10 seconds from one client, ≤10 processed under configured limiter.

Record dataset versions, prompt policy, model checksum, threshold, CPU/hardware and whether the evaluation uses the same distributions as tuning. Separate detection recall from actual harmful-output prevention; benchmark values are targets, not evidence of production security.
