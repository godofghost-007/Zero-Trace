# Phase 17B evidence - deployment and bounded scanning

Date: 2026-10-25

## Implemented

- `frontend/Dockerfile`: Python 3.13, non-root runtime, Gunicorn with threads,
  healthcheck, no demo defaults.
- `Dockerfile.engine`: Python 3.13, Nmap, pinned Subfinder release, non-root,
  healthcheck, loopback bind.
- `deploy/Caddyfile`: automatic TLS, HSTS and security headers, 1 MB request
  body limit, JSON access logs, reverse proxy to the BFF, and per-client edge
  rate limits for `/api/v1/auth/*` (10/min) and `/api/v1/*` (300/min).
- `deploy/compose.prod.yaml`: Caddy + BFF + engine, no published engine port,
  resource limits, `cap_drop: ALL`, `no-new-privileges`, healthchecks, named
  volumes.
- BFF and engine share the engine network namespace so the BFF uses the
  loopback-only engine URL `http://127.0.0.1:8765`.
- Scan queue depth and per-target cooldown settings; existing profile timeouts,
  output caps, rate limits, retries, concurrency limit, and cancellation path are
  retained.
- Scanner inventory now reports Nmap/Subfinder availability, resolved path, and
  first-line version output in `/api/v1/engine/status`; `/ready` exposes scanner
  availability without degrading the synthetic/TLS-only engine.

## Verification

```text
docker build -f Dockerfile.engine -t zerotrace-engine:ci .
docker build -t zerotrace-bff:ci frontend
docker run ... zerotrace-engine:ci   # /health -> {"status":"healthy"}
docker run ... zerotrace-bff:ci      # /api/v1/health -> 200
docker run --rm ... caddy:2.10-alpine caddy validate
# Valid configuration (stock image)
docker build -f deploy/Dockerfile.caddy -t zerotrace-caddy:ci deploy
docker run --rm -e ZEROTRACE_DOMAIN=zerotrace.example.test \
  -v "$PWD/deploy/Caddyfile:/etc/caddy/Caddyfile:ro" \
  zerotrace-caddy:ci caddy validate --config /etc/caddy/Caddyfile
# Valid configuration
# Rate-limit test with a 2-request zone: request 1 -> 200, request 2 -> 200,
# request 3 -> 429.
```

Evidence: `tasks/evidence/observability-config.json` includes the Caddy
validation and rate-limit result.

The engine health check was executed inside the container because the process
intentionally binds `127.0.0.1`, not the host-published interface. The BFF image
was also started with two Gunicorn workers and `AUTO_CREATE_SCHEMA=true`; the
schema bootstrap now tolerates concurrent `CREATE TABLE` races and returned
`200` from `/api/v1/health`.

## Known gaps

- Caddy edge rate limiting is configured with a pinned custom image
  (`deploy/Dockerfile.caddy`) and validated with a local two-request limit test.
  It keys on the direct peer address; Cloudflare proxying needs trusted-proxy
  configuration or it will key on Cloudflare's address.
- The production stack has not been deployed to a real VPS/Supabase project in
  this phase.
- Scanner runtime version gating and container hardening were completed in
  P17C2; there is still no per-scan network namespace or separate filesystem
  jail.
- Migration rollback was exercised locally in
  `tasks/evidence/migration-rollback.json`, but not against a live production
  deployment.
