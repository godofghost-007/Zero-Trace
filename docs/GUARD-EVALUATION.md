# Guard evaluation and response policy

Guard is an OpenAI-compatible reverse proxy between the BFF and an allowlisted
model provider. It is not a general-purpose security product and it is not a
claim that a regex detector stops every prompt injection.

## Slots

The deployment defines three independent model-related slots:

1. **Guard detector** - the shipped detector is deterministic and
   dependency-free. The external-classifier configuration names are reserved;
   no external classifier is wired in this release.
2. **Guard upstream** - the working OpenAI-compatible model provider that serves
   chat completions. The provider key stays in Guard.
3. **Intel model** - the reserved model slot for Intel enrichment or
   explanation. It is not on the Guard data path, must not receive raw scan
   secrets, and is **not wired in this release**.

Do not claim that the detector or Intel model slot is active until the
corresponding adapter exists and has evaluation evidence.

## BFF route

`POST /api/v1/guard/chat` is the authenticated application route. It requires
an operator session, CSRF token, and allowed origin. It accepts only `model`,
`messages`, `temperature`, `top_p`, and `max_tokens`; streaming is rejected.
The BFF adds `X-API-Key` from `ZEROTRACE_GUARD_BFF_API_KEY` and calls
`ZEROTRACE_GUARD_PROXY_URL` over loopback. The route never accepts a
client-supplied upstream URL.

## Adding your own OpenAI-compatible model

The working self-hosted path is the Guard upstream slot. Put the provider
credential only in the Guard-only environment file (`.env.guard` in the
production Compose stack):

```bash
ZEROTRACE_GUARD_PROVIDER_API_KEY=...
ZEROTRACE_GUARD_UPSTREAM_ALLOWLIST=https://your-provider.example
ZEROTRACE_GUARD_ALLOWED_MODELS=your-model-id
```

The upstream must be an HTTPS origin on port 443 with no path, query, userinfo,
or fragment. If the provider uses a different host, add that exact host to the
allowlist; subdomains require an explicit `https://*.example.com` entry. Keep
`ZEROTRACE_GUARD_PII_ACTION=block` unless you have reviewed the redaction
limits. The BFF does not need the provider key; it only needs the separate
BFF-to-Guard credential. The detector and Intel model slots are not wired in
this release, so do not configure them expecting enforcement or enrichment.

## Run the evaluation

```bash
python -m scripts.evaluate_guard
```

The command writes `tasks/evidence/guard-evaluation.json`. The corpus is 40
synthetic English cases. A pass is regression evidence, not a security
guarantee.

The evidence file records precision, recall, F1, false-positive rate, and every
mistake. Do not remove a mistake from the evidence to improve the score. Add a
regression case instead.

## Upstream allowlist

- Only HTTPS origins are accepted.
- Userinfo, query strings, fragments, non-root base paths, and non-443 ports are
  rejected.
- The transport re-checks the origin and refuses redirects.
- A client-supplied `upstream` field cannot escape the allowlist.
- The provider key is added by `app/guard_transport.py`, never by the browser or
  the BFF.

## Response policy

`ZEROTRACE_GUARD_PII_ACTION` controls what happens when the response contains a
detected email, SSN, phone number, or card-like value:

- `block` (default): return a generic `pii_detected` error and emit a
  `response_blocked` event.
- `redact`: replace the detected value with a typed placeholder such as
  `[REDACTED:EMAIL]`, return the response, and set
  `X-ZeroTrace-PII-Redacted: true`.

Redaction is a transformation, not a guarantee. It does not cover every
personal-data category, every jurisdiction, or arbitrary binary content.

## Key rotation

Guard accepts the current digest and an optional previous digest. To rotate
without downtime:

1. Generate a new BFF key and digest:
   `python -m scripts.generate_guard_credentials`.
2. Put the new key in the BFF secret store.
3. Put the new digest in Guard's current digest and move the old digest to the
   previous digest.
4. Restart Guard, then restart the BFF.
5. Verify a request succeeds, then remove the previous digest.

Never put the provider key in the BFF, the browser, the repository, or the
Guard audit log.

## Limitations

- English-only corpus and regex patterns.
- No external classifier was evaluated.
- A malicious provider can return content that the response policy does not
  recognize.
- Guard protects traffic routed through it. A SaaS client that cannot use a
  custom OpenAI-compatible base URL is outside Guard's boundary.
