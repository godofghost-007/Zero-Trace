# ADR-005: Guard MVP — LLM Security Middleware (Phase 11)

## Status
Accepted

## Date
2026-10-17

## Context

Phase 11 adds the Guard module — an OpenAI-compatible LLM security gateway that
protects LLM traffic from prompt injection, jailbreak attacks, PII leakage, and
unauthorized access. The Guard module is the third trace in ZeroTrace's
three-module architecture (Recon → Intel → Guard).

The wiki Phase 11 specification requires:

- `/v1/chat/completions` endpoint (OpenAI-compatible, non-streaming)
- Request schema and body size validation
- Client API key authentication
- Per-client rate limiting
- Message boundaries preserved
- Regex and heuristic detection (jailbreak, prompt injection)
- Upstream allowlists and TLS verification
- Bounded proxy timeouts
- Response PII scanning
- Compatible error envelopes
- `/health` and `/ready` endpoints
- Minimal audit metadata
- `attack_blocked` events

## Decision

Create `app/guard.py` with the following security-enforced design:

1. **GuardConfig** — immutable configuration with `api_key_secret` (HMAC key),
   `api_key_digest` (expected HMAC output), `upstream_allowlist` (HTTPS-only),
   `max_request_bytes`, `request_timeout_seconds`, and `require_api_key`.

2. **GuardApp (FastAPI)** — FastAPI application with three endpoints:
   - `GET /health` — liveness check
   - `GET /ready` — dependency readiness check
   - `POST /v1/chat/completions` — OpenAI-compatible chat completions with full
     security validation

3. **Security controls (enforced, not advisory):**

   | Control | Implementation |
   |---------|---------------|
   | API key authentication | HMAC-SHA256 digest comparison, constant-time |
   | Rate limiting | Token-bucket per client, configurable window |
   | Prompt injection detection | Regex patterns for jailbreak, DAN, system prompt extraction |
   | PII scanning | SSN, email, credit card, phone number detection on responses |
   | Upstream allowlist | HTTPS-only, hostname matching, no SSRF |
   | Request size limits | Configurable max request bytes |
   | Request validation | Schema validation for model, messages, temperature, max_tokens |
   | Security headers | CSP, X-Content-Type-Options, X-Frame-Options, etc. |
   | Generic error envelopes | No stack traces or internal details exposed |
   | Event emission | `attack_blocked` and `guard_request` events via EventEnvelope |

4. **No automatic execution** — Guard blocks or allows requests; it never
   executes remediation against any target (consistent with Phase 10).

## Alternatives Considered

### FastAPI with middleware stack vs. standalone ASGI app
Chose FastAPI for consistency with `intel_api.py` and `recon_api.py`, which
also use FastAPI. Middleware stack for security headers keeps concerns
separated.

### HMAC-SHA256 vs. plaintext API key comparison
Chose HMAC-SHA256 with constant-time comparison (`hmac.compare_digest`) to
prevent timing attacks and avoid storing plaintext keys.

### Regex-only detection (no ONNX in MVP)
ONNX DistilBERT semantic detection is deferred to a later phase. The MVP uses
regex and heuristic detection, which covers the most common attack patterns
while keeping dependencies minimal.

## Consequences

- Guard module is fully integrated with ZeroTrace's event system —
  `attack_blocked` events are emitted when prompts are rejected.
- API key authentication uses HMAC-SHA256 with constant-time comparison.
- All upstream communication is limited to allowlisted HTTPS endpoints.
- Error responses use generic envelopes without internal details.
- 27 new tests pass; full suite is 172 tests, all green.
- No new dependencies beyond FastAPI (already a project dependency).
- ONNX semantic detection, streaming responses, and Ollama integration remain
  for later phases.