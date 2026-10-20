# Phase 11 Evidence — Guard MVP (LLM Security Middleware)

- **Decision:** Phase 11 implementation complete; Guard MVP with OpenAI-compatible
  gateway, API key authentication, rate limiting, prompt injection detection,
  PII scanning, and upstream allowlisting
- **Environment:** Windows, Python 3.13
- **Date:** 2026-10-17
- **Authorization:** Phase 11 implementation authorized by human approval

## Scope

Phase 11 adds the Guard module — an OpenAI-compatible LLM security gateway that
protects LLM traffic from prompt injection, jailbreak attacks, PII leakage, and
unauthorized access. This is the third trace in ZeroTrace's three-module
architecture (Recon → Intel → Guard).

## Required criteria and evidence

| Criterion | Status | Evidence |
|---|---|---|
| OpenAI-compatible /v1/chat/completions endpoint | PASS | `tests.test_guard.GuardAppTests.test_valid_request_returns_completion` |
| Non-streaming requests only (MVP) | PASS | `stream: False` enforced in upstream request |
| Client API key authentication | PASS | `test_request_without_api_key_is_rejected`, `test_request_with_invalid_api_key_is_rejected` |
| HMAC-SHA256 digest verification | PASS | `GuardConfig.api_key_secret` + `api_key_digest` with constant-time compare |
| Per-client rate limiting | PASS | `tests.test_guard.RateLimiterTests` (budget, per-client, window reset) |
| Prompt injection detection | PASS | `tests.test_guard.PromptInjectionDetectionTests` (jailbreak, DAN, system extraction) |
| Normal prompts allowed | PASS | `test_regex_allows_normal_prompts` |
| PII response scanning | PASS | `tests.test_guard.PIIScannerTests` (SSN, email, credit card) |
| Upstream allowlist (HTTPS only) | PASS | `test_config_rejects_non_https_upstream`, `_is_allowlisted_upstream` |
| Request schema validation | PASS | `_validate_chat_completion_request` (model, messages, temperature, max_tokens) |
| Request size limits | PASS | `config.max_request_bytes` enforced |
| Security headers | PASS | `test_security_headers_present` (CSP, X-Content-Type-Options, X-Frame-Options) |
| Generic error envelopes | PASS | `test_error_response_does_not_expose_internal_details` |
| /health and /ready endpoints | PASS | `test_health_endpoint_returns_healthy`, `test_ready_endpoint_returns_healthy` |
| attack_blocked event emission | PASS | `tests.test_guard.EventEmissionTests.test_attack_blocked_event_is_emitted` |
| No internal details in errors | PASS | No tracebacks or stack traces in error responses |
| Full repository verification | PASS | `py -m unittest discover -s tests -v` — 172 tests passed; compileall and `git diff --check` passed |

## Safety boundaries

- Model output is treated as untrusted input (LLM05) — never into eval, SQL, shell, or file path
- Prompts can be hijacked (LLM01) — system prompt is not a security boundary; permissions enforced in code
- No secrets, tenant data, or full system prompt in context window
- Server-side fetches validated against allowlist (no SSRF)
- Error responses don't expose internal details
- Rate limiting per client to prevent DoS
- No automatic execution — Guard blocks or allows; never executes remediation
- No public target scanning — Guard proxies to allowlisted upstreams only

## Verification

```powershell
py -m unittest discover -s tests -v
py -m compileall -q app scripts
git diff --check
```

## Human signoff

**Human signoff:** Approved on 2026-10-17. Guard MVP with LLM security
middleware is complete. This approval does not authorize ONNX semantic
detection (deferred to later phase), streaming responses, or Ollama
integration.