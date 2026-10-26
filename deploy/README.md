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

The Caddy service builds from `deploy/Dockerfile.caddy`; it is not the stock
image because edge rate limiting uses a pinned `caddy-ratelimit` module. The
Caddyfile limits `/api/v1/auth/*` to 10 requests/minute and the rest of
`/api/v1/*` to 300 requests/minute per direct peer. If Cloudflare proxying is
enabled, configure trusted proxies; otherwise every request is keyed on a
Cloudflare address and the limit is much less useful.

## 3. Configuration

Copy `.env.example` to `.env.production` on the server and set at least:

```dotenv
ZEROTRACE_ENV=production
FLASK_SECRET_KEY=<64+ random characters>
DATABASE_URL=postgresql://...@...pooler.supabase.com:6543/postgres
ZEROTRACE_COOKIE_SECURE=true
ZEROTRACE_IDLE_TIMEOUT_SECONDS=1800
# Set true to require TOTP enrollment and verification for every tenant user.
ZEROTRACE_MFA_REQUIRED=false
AUTO_CREATE_SCHEMA=false
DEMO_MODE=false
ZEROTRACE_MFA_ENCRYPTION_KEY=<Fernet key>
ZEROTRACE_ENGINE_API_KEY=<long random value>
ZEROTRACE_ENGINE_URL=http://127.0.0.1:8765
ZEROTRACE_TRUST_PROXY=true
# Pin released digests in production; leave the local tags for a source build.
ZEROTRACE_BFF_IMAGE=ghcr.io/<owner>/<repo>/zerotrace-bff@sha256:<digest>
ZEROTRACE_ENGINE_IMAGE=ghcr.io/<owner>/<repo>/zerotrace-engine@sha256:<digest>
ZEROTRACE_CADDY_IMAGE=ghcr.io/<owner>/<repo>/zerotrace-caddy@sha256:<digest>
ZEROTRACE_GUARD_BFF_API_KEY=<generated BFF-to-Guard key>
```

Guard provider secrets live in a separate `.env.guard` file copied from
`deploy/guard.env.example`. The BFF and engine do not receive that file.

Guard uses the built-in deterministic detector by default. Set
`ZEROTRACE_GUARD_DETECTOR_URL` to an HTTPS classifier that accepts
`{"text": "..."}` and returns `{"blocked": true|false, "reason": "..."}` to use
an external detector; failures are fail-closed. Run
`python -m scripts.evaluate_guard --mode live --model <model>` only after a
provider is configured and the Guard key is available in
`ZEROTRACE_GUARD_BFF_API_KEY`. See `deploy/GUARD-EGRESS.md` for the egress
boundary.

### Secret files

For a managed secret store or Docker secret, mount the value as a file and use
the `_FILE` suffix instead of putting the value in the environment:

```dotenv
FLASK_SECRET_KEY_FILE=/run/secrets/flask_secret_key
DATABASE_URL_FILE=/run/secrets/database_url
ZEROTRACE_ENGINE_API_KEY_FILE=/run/secrets/engine_api_key
ZEROTRACE_ENGINE_AUTH_SECRET_FILE=/run/secrets/engine_auth_secret
ZEROTRACE_MFA_ENCRYPTION_KEY_FILE=/run/secrets/mfa_key
ZEROTRACE_GUARD_BFF_API_KEY_FILE=/run/secrets/guard_bff_key
```

The process rejects a secret when both `NAME` and `NAME_FILE` are set, and
fails startup when the file cannot be read. Keep the files root-owned and
mode `0400` or `0600`, and mount them read-only into the container.

Generate the MFA key with:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Do not commit `.env.production`. The production startup check fails closed if
the secret key, PostgreSQL URL, secure cookies, schema auto-creation, demo mode,
MFA key, or OIDC credentials are unsafe.

The BFF runs with `AUTO_CREATE_SCHEMA=false`; migration `0010_bff_operational`
creates its operational tables. Sessions are bounded by both
`ZEROTRACE_SESSION_TTL_SECONDS` and `ZEROTRACE_IDLE_TIMEOUT_SECONDS` (minimum
60 seconds). With `ZEROTRACE_MFA_REQUIRED=true`, a user without MFA is signed
in to the enrollment screen only and cannot reach the console until TOTP
activation succeeds.

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

## 7. Guard and AI slots

Guard is deployed as a loopback sidecar in the production Compose stack. It
authenticates the BFF, inspects the prompt, and only then calls the allowlisted
OpenAI-compatible upstream. The provider key lives only in `.env.guard`, not in
`.env.production` and never in the browser or BFF.

The working upstream slot uses:

- `ZEROTRACE_GUARD_PROVIDER_API_KEY`
- `ZEROTRACE_GUARD_UPSTREAM_ALLOWLIST`
- `ZEROTRACE_GUARD_ALLOWED_MODELS`
- `ZEROTRACE_GUARD_PII_ACTION`

The built-in detector is deterministic regex/PII inspection. The
`GUARD_DETECTOR_*` and `INTEL_MODEL_*` names in `.env.example` are reserved for
the separate detector and Intel enrichment slots; they are **not wired to a
model in this release**. Do not describe either as active.

To generate the BFF-to-Guard credential:

```bash
export ZEROTRACE_GUARD_API_KEY_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
python -m scripts.generate_guard_credentials
```

Put `apiKey` in `.env.production` as `ZEROTRACE_GUARD_BFF_API_KEY` and
`apiKeyDigest` plus the same `ZEROTRACE_GUARD_API_KEY_SECRET` in `.env.guard`.
Copy `deploy/guard.env.example` to `.env.guard`, fill the provider values, and
keep the file mode `0600`.

The BFF exposes `POST /api/v1/guard/chat` for an authenticated operator. It
accepts only `model`, `messages`, `temperature`, `top_p`, and `max_tokens`;
streaming is not supported. The browser never receives the Guard or provider
key. Point an OpenAI-compatible application at this route, not directly at the
provider. See `docs/GUARD-EVALUATION.md`.

NVIDIA's free API is trial/best-effort capacity and has no production SLA; use a
paid or local endpoint for production guarantees.

## 8. Observability

The optional overlay starts Prometheus, Alertmanager, and Grafana on loopback:

```bash
cp deploy/observability/metrics-token.example deploy/observability/metrics-token
# Set ZEROTRACE_METRICS_TOKEN to the same value in .env.production.
export ZEROTRACE_METRICS_TOKEN_FILE="$PWD/deploy/observability/metrics-token"
export ZEROTRACE_GRAFANA_ADMIN_PASSWORD='a long unique password'
docker compose \
  -f deploy/compose.prod.yaml \
  -f deploy/compose.observability.yaml up -d
```

Validate the configuration before starting it:

```bash
docker compose \
  -f deploy/compose.prod.yaml \
  -f deploy/compose.observability.yaml config --quiet
docker run --rm \
  -v "$PWD/deploy/observability/prometheus.yml:/etc/prometheus/prometheus.yml:ro" \
  -v "$PWD/deploy/observability/alerts.yml:/etc/prometheus/alerts.yml:ro" \
  -v "$PWD/deploy/observability/metrics-token.example:/etc/prometheus/metrics-token:ro" \
  --entrypoint promtool prom/prometheus:v3.1.0 \
  check config /etc/prometheus/prometheus.yml
docker run --rm \
  -v "$PWD/deploy/observability/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro" \
  --entrypoint amtool prom/alertmanager:v0.28.1 \
  check-config /etc/alertmanager/alertmanager.yml
```

Prometheus, Alertmanager, and Grafana bind to `127.0.0.1`. Reach them through an
SSH tunnel. Set `ZEROTRACE_GRAFANA_COOKIE_SECURE=true` only when Grafana is
served over HTTPS. The shipped Alertmanager receiver is deliberately null; set
a real pager/webhook receiver before relying on alerts.

See `docs/SLO.md` and `docs/RUNBOOK-OPERATIONS.md`.

## 9. Backups

Use the encrypted backup CLI. Keep `ZEROTRACE_BACKUP_KEY` outside the backup
host, verify every backup, and record restore drills:

```bash
export ZEROTRACE_BACKUP_KEY='...'
python -m scripts.backup_database backup-postgres \
  --container zerotrace-postgres-1 --database zerotrace --user zerotrace \
  --output backups/postgres.ztb --offhost-dir /mnt/offhost/zerotrace
python -m scripts.backup_database verify --backup backups/postgres.ztb
```

See `docs/BACKUP-RESTORE.md` for RPO/RTO, key rotation, restore, and retention.

## 10. Rollback

1. Keep the previous image digest and the previous migration state.
2. Stop the stack.
3. Restore the previous image digest and, if the new release included a
   migration, run the down migration against the direct URL.
4. Start the stack and verify `/api/v1/health` and `/api/v1/ready`.
5. Record the rollback in the release evidence.

Never roll back by deleting data or by pointing the app at a stale SQLite file.
The durable database is authoritative. See `docs/RELEASE-PROCESS.md`.
