# Self-hosted production deployment

This is the reference deployment for a single-tenant, self-hosted ZeroTrace
v1. It is intentionally conservative: the engine is not published, the BFF is
the only public application, and Caddy terminates TLS.

## 1. Prerequisites

- A Linux VPS with at least 2 vCPU, 4 GB RAM, and 20 GB disk. Check the
  provider's acceptable-use policy before enabling scanners; some free tiers
  prohibit outbound port scanning.
- A domain whose DNS is managed by Cloudflare (or another provider that can
  point an A/AAAA record at the VPS).
- A Supabase project. Use the **transaction pooler** URL for the app and the
  **direct** URL for migrations.
- Docker Engine and the Compose plugin.

## 2. DNS and TLS

1. Create an `A` record (and `AAAA` if you have IPv6) for
   `zerotrace.example.com` pointing at the VPS.
2. Keep Cloudflare proxying optional. If you enable the orange cloud, set SSL/TLS
   mode to **Full (strict)** and allow Caddy to obtain a certificate through the
   HTTP-01 challenge, or use a Cloudflare Origin Certificate.
3. Open only `80/tcp`, `443/tcp`, and `443/udp` in the host firewall. Do not
   publish `8765` or `5432`.

## 3. Configuration

Copy `.env.example` to `.env.production` on the server and set at least:

```dotenv
ZEROTRACE_ENV=production
FLASK_SECRET_KEY=<64+ random characters>
DATABASE_URL=postgresql://...@...pooler.supabase.com:6543/postgres
ZEROTRACE_COOKIE_SECURE=true
AUTO_CREATE_SCHEMA=false
DEMO_MODE=false
ZEROTRACE_MFA_ENCRYPTION_KEY=<Fernet key>
ZEROTRACE_ENGINE_API_KEY=<long random value>
ZEROTRACE_ENGINE_URL=http://127.0.0.1:8765
ZEROTRACE_TRUST_PROXY=true
```

Generate the MFA key with:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Do not commit `.env.production`. The production startup check fails closed if
the secret key, PostgreSQL URL, secure cookies, schema auto-creation, demo mode,
MFA key, or OIDC credentials are unsafe.

## 4. Migrations

Run migrations against the **direct** Supabase connection before starting the
new application version:

```bash
DATABASE_URL="$MIGRATION_DATABASE_URL" python -m scripts.run_migrations
```

Roll back the most recent migration with:

```bash
DATABASE_URL="$MIGRATION_DATABASE_URL" python -m scripts.run_migrations --rollback
```

Create the BFF tables once with the explicit bootstrap command (production
startup keeps `AUTO_CREATE_SCHEMA=false`):

```bash
docker compose -f deploy/compose.prod.yaml run --rm bff \
  flask --app backend:create_app init-schema
```

Create the first operator account with the BFF CLI (use the direct URL or the
pooler, whichever your environment permits):

```bash
docker compose -f deploy/compose.prod.yaml run --rm bff \
  flask --app backend:create_app create-user
```

## 5. Start and verify

```bash
docker compose -f deploy/compose.prod.yaml up -d --build
docker compose -f deploy/compose.prod.yaml ps
curl -fsS https://zerotrace.example.com/api/v1/health
curl -fsS https://zerotrace.example.com/api/v1/ready
```

The engine is reachable only from the BFF's shared network namespace at
`127.0.0.1:8765`. Caddy proxies to the BFF at `engine:3000`; it does not expose
the engine port.

## 6. Backups and restore

- Enable Supabase point-in-time recovery if your plan provides it.
- Run `scripts/backup_database.py` on a schedule against the direct URL, encrypt
  the output, and copy it off-host.
- Store the encryption key outside the backup host.
- Restore into a clean database and run the restore verification before trusting
  the backup. See `docs/LAB-RUNBOOK.md` and `docs/PRODUCTION-READINESS.md`.

## 7. AI slots

Guard and Intel are provider-agnostic. Set the three slots independently:

- `GUARD_DETECTOR_*`: prompt-injection/jailbreak detector.
- `GUARD_UPSTREAM_*`: OpenAI-compatible upstream chat model.
- `INTEL_MODEL_*`: optional Intel enrichment model.

The Guard upstream base URL is allowlisted. The provider key stays in the Guard
process. Do not give the provider key to the browser, the BFF, or the engine.
NVIDIA's free API is trial/best-effort capacity and has no production SLA; use a
paid or local endpoint for production guarantees.

## 8. Rollback

1. Keep the previous image tag and the previous migration state.
2. Stop the stack.
3. Restore the previous image tag and, if the new release included a migration,
   run the down migration against the direct URL.
4. Start the stack and verify `/api/v1/health` and `/api/v1/ready`.
5. Record the rollback in the release evidence.

Never roll back by deleting data or by pointing the app at a stale SQLite file.
The durable database is authoritative.
