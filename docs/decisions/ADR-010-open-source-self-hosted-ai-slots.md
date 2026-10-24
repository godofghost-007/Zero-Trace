# ADR-010: Open-source, self-hosted v1 with provider-agnostic AI slots

- Status: Accepted
- Date: 2026-10-25
- Decision owners: ZeroTrace maintainers
- Related: `docs/PRODUCTION-READINESS.md`, `docs/AUTH-MATRIX.md`

## Context

ZeroTrace is moving from a local-first demo to a release that another operator
can download, self-host, and operate without a hosted ZeroTrace account. The
release needs a permissive license, a free-tier-compatible deployment path, and
AI integration that does not lock users to one vendor.

The Guard and Intel surfaces have different trust requirements:

- **Guard** sits between the application/user prompt and an upstream model. It
  must inspect the inbound prompt, enforce policy, and only then forward to an
  allowlisted OpenAI-compatible upstream. The provider credential belongs to the
  Guard process, never to the browser or the application.
- **Intel** uses a model to summarize or enrich vulnerability evidence. It is
  not on the prompt path and must not be given secrets or unrestricted target
  data.
- **Guard detector** is a separate model slot. It is not the same as the
  upstream chat model.

## Decision

1. The first public release is **self-hosted only**, licensed **Apache-2.0**.
2. The deployment reference is a free VPS running Caddy/Nginx + Flask BFF +
   FastAPI engine + scanners. PostgreSQL is provided by Supabase; DNS/TLS is
   provided by Cloudflare. Vercel is limited to the landing/docs site.
3. There is no multi-tenancy, billing, public signup, SCIM, or per-tenant quota
   in v1. A single operator tenant is the supported shape.
4. AI integration exposes three independently configurable slots:
   - `GUARD_DETECTOR_*` — prompt-injection/jailbreak detector.
   - `GUARD_UPSTREAM_*` — OpenAI-compatible upstream chat model.
   - `INTEL_MODEL_*` — optional Intel enrichment model.
5. Operators may use NVIDIA's free API, another OpenAI-compatible provider, or
   a local model. The default documented NVIDIA choices are:
   - detector: `nvidia/nemoguard-jailbreak-detect`
   - upstream: `nvidia/nemotron-3.5-lightning-30b-a3b`
   - Intel: `deepseek-ai/deepseek-v4.1-flash`
   - fallback: `qwen/qwen3-coder-480b-a35b-instruct`
6. Guard must authenticate the BFF, not the end user. The provider key stays in
   Guard. The application must not be able to reach the provider directly;
   egress lockdown is a deployment requirement.
7. The Guard upstream is allowlisted by base URL. The detector endpoint is
   separate from the chat endpoint and is English-only in the NVIDIA reference.
8. The existing inspect-only Guard behavior remains the default until the
   upstream gateway is explicitly enabled and tested. Documentation must not
   claim that every third-party SaaS AI can be protected without an
   OpenAI-compatible base URL.
9. NVIDIA's free API is best-effort/trial capacity, not a production SLA. The
   release notes and operator runbook must say so.

## Consequences

- Users can self-host without paying for a ZeroTrace license or hosted control
  plane.
- The project must ship migrations, backup/restore, deployment, and identity
  documentation, not only application code.
- Supporting arbitrary SaaS AI products is out of scope unless they expose an
  OpenAI-compatible base URL that can be routed through Guard.
- Provider keys, model names, and base URLs become operator-managed secrets and
  must never be committed.
- The project cannot claim production readiness until the Phase 18 gate and
  human signoff are complete.

## Rejected alternatives

- **Hosted SaaS first:** rejected for v1 because it adds billing, tenancy, and
  abuse-handling work before the self-hosted product is proven.
- **Single hard-coded AI vendor:** rejected because it conflicts with the
  open-source/BYOM requirement and makes free-tier access brittle.
- **Guard as a library inside the BFF:** rejected because it weakens the trust
  boundary and makes it easier for application code to bypass inspection.
- **Automatic remediation:** rejected; remediation remains a reviewed proposal.
