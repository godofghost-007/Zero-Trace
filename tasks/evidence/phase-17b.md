# Phase 17B evidence — deployment and bounded scanning

Date: 2026-10-25

## Implemented

- `frontend/Dockerfile`: Python 3.13, non-root runtime, Gunicorn with threads,
  healthcheck, no demo defaults.
- `Dockerfile.engine`: Python 3.13, Nmap, pinned Subfinder release, non-root,
  healthcheck, loopback bind.
- `deploy/Caddyfile`: automatic TLS, HSTS and security headers, 1 MB request
  body limit, JSON access logs, reverse proxy to the BFF.
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
# Valid configuration
```

The engine health check was executed inside the container because the process
intentionally binds `127.0.0.1`, not the host-published interface. The BFF image
was also started with two Gunicorn workers and `AUTO_CREATE_SCHEMA=true`; the
schema bootstrap now tolerates concurrent `CREATE TABLE` races and returned
`200` from `/api/v1/health`.

## Known gaps

- Caddy edge rate limiting is not configured; the BFF and engine retain their
  application-level limits. A Caddy rate-limit module or provider WAF is needed
  for edge protection.
- The production stack has not been deployed to a real VPS/Supabase project in
  this phase.
- Scanner runtime version gating and sandbox proof are pending (P17C2).
- Rollback was implemented and tested for migrations, but not rehearsed against
  a live production deployment.
