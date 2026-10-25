# Phase 17E evidence - Guard, data protection, and Intel boundary

Date: 2026-10-25

## Implemented

- Guard is an OpenAI-compatible reverse proxy. The **Guard upstream** slot is
  wired: the BFF calls `POST /api/v1/guard/chat`, adds the BFF-to-Guard key, and
  Guard calls the allowlisted upstream with the provider key that only Guard
  holds. The built-in detector is deterministic regex/PII inspection. The
  external `GUARD_DETECTOR_*` and `INTEL_MODEL_*` slots are reserved and are not
  wired to a model in this release.
- `HttpGuardTransport` re-checks the upstream origin, rejects userinfo, query
  strings, fragments, non-root paths, non-443 ports, redirects, and oversized
  responses.
- API-key rotation: Guard accepts the current digest and an optional previous
  digest, so the BFF can be redeployed without a Guard outage.
- Model allowlist and PII response policy:
  - `block` is the default;
  - `redact` replaces detected values with typed placeholders and sets
    `X-ZeroTrace-PII-Redacted: true`;
  - a `response_blocked` event is emitted on block.
- Deterministic Guard evaluation corpus and evidence generator.
- Guard credential generator and a loopback-only runner (`scripts.guard_proxy`).
- Retention job for operational runtime data. Audit-chain rows are not deleted
  from the middle of the chain.
- Privacy/data inventory, DPA checklist, residency, deletion, and Guard/provider
  limitations in `docs/PRIVACY-AND-DPA.md`.
- Guard evaluation, key rotation, and response-policy documentation in
  `docs/GUARD-EVALUATION.md`.

## Verification

```text
py -3.13 -m pytest tests/test_guard.py tests/test_guard_transport.py -q
35 passed

frontend\.venv\Scripts\python.exe -m pytest backend/tests/test_guard_api.py -q
15 passed
```

The BFF route rejects streaming, unknown fields, empty messages, unsupported
roles, out-of-range sampling values, and client-supplied upstream URLs. It
forwards the redaction header when Guard redacts a response.

The engine image also runs `python -m scripts.guard_proxy` with no network and
answers `/health` on loopback; see `tasks/evidence/guard-proxy-container.json`.

```text
py -3.13 -m scripts.evaluate_guard
{"f1": 0.9756, "falsePositiveRate": 0.05, "precision": 0.9524, "recall": 1.0}
```

Evidence: `tasks/evidence/guard-evaluation.json`.

The 40-case synthetic corpus has 20 attacks and 20 benign prompts. One benign
prompt that quotes the phrase "ignore previous instructions" is blocked, which
is recorded as a false positive rather than hidden. The corpus is English-only
and regex-based; a pass is regression evidence, not a security guarantee.

```text
python -m scripts.generate_guard_credentials
# prints a one-time BFF key and its HMAC digest
```

## Intel boundary

- NVD, EPSS, and KEV ingestion retain last-known-good snapshots and expose feed
  age through `zerotrace_intel_feed_age_seconds`.
- The Intel model slot is separate from the Guard data path.
- Full live NVD pagination, retry/backoff, deduplication, and matching-quality
  review were not completed in this phase. Treat P17E1 as partial.

## Known gaps

- No live NVIDIA or other provider call was made during this evaluation.
- The BFF-to-Guard route was tested with a fake Guard client, not a live Guard
  process and provider.
- The external detector and Intel model slots are reserved, not implemented.
- No external jailbreak classifier was evaluated.
- Guard protects only traffic routed through it. A SaaS client without a custom
  OpenAI-compatible base URL is outside the boundary.
- No automated data-subject export/erasure endpoint exists.
- No DPA or privacy notice was reviewed by counsel.
- No tenant isolation or multi-tenant DPA is supported in v1.
- Egress lockdown is documented but not enforced by a network policy in this
  local environment.
