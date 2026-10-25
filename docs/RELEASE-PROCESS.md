# Release, staged rollout, and rollback

## Release gate

A release candidate must have:

- all required CI checks green;
- a passing root and BFF test run;
- a passing `scripts/security_smoke.py` and `scripts/load_test.py`;
- a current Guard evaluation evidence file;
- a successful encrypted backup restore drill within the last quarter;
- a reviewed `docs/PRODUCTION-READINESS.md` scorecard;
- a human signoff recorded in the release issue.

The Phase 18 gate is not complete until those items are true for the exact
commit being released.

## Versioning

- Use semantic versioning for the application and image tags.
- A migration that removes or renames a column is a breaking change.
- A change to the Guard request/response contract is a breaking change.
- Do not publish a tag from a dirty worktree.

## Staged rollout

1. Build immutable images and record their digests.
2. Deploy to a staging host with a copy of production configuration and a
   disposable database.
3. Run migrations with the direct database connection, not the transaction
   pooler.
4. Start the BFF and engine, then verify `/health`, `/ready`, `/api/v1/metrics`,
   and a synthetic Normal scan.
5. Deploy to production during a change window.
6. Keep the previous image digests and a verified pre-change database backup.
7. Watch the SLO dashboard for at least 30 minutes.
8. Increase traffic or enable scheduled scans only after the smoke window.

## Database changes

Use expand/contract:

1. Add the new column/table and deploy code that can read both shapes.
2. Backfill in bounded batches.
3. Switch reads and writes.
4. Remove the old shape in a later release.

Every migration needs a tested down migration. The migration rollback test runs
against PostgreSQL in CI.

## Rollback

Application rollback:

```bash
# Pin the previous immutable digests in .env.production:
#   ZEROTRACE_BFF_IMAGE=ghcr.io/<owner>/<repo>/zerotrace-bff@sha256:...
#   ZEROTRACE_ENGINE_IMAGE=ghcr.io/<owner>/<repo>/zerotrace-engine@sha256:...
#   ZEROTRACE_CADDY_IMAGE=ghcr.io/<owner>/<repo>/zerotrace-caddy@sha256:...
docker compose -f deploy/compose.prod.yaml pull bff engine guard caddy
docker compose -f deploy/compose.prod.yaml up -d --no-deps bff engine guard caddy
```

Database rollback:

1. Stop the BFF and engine so no writes occur.
2. Take a fresh backup.
3. Apply the down migration only if the schema change is reversible and the
   data loss is understood.
4. If the down migration is destructive, restore the pre-change encrypted
   backup instead.
5. Start the previous application version and verify readiness.

Never run a destructive down migration while the current application is still
writing.

## What is proven

- Migration apply and rollback are covered by tests.
- Encrypted PostgreSQL backup and destructive restore were exercised locally.
- The Compose production configuration validates.
- Images build in CI.

## What is not proven

- No production VPS or Supabase deployment has been performed.
- No canary traffic split or blue-green environment exists.
- No signed release has been published.
- No rollback has been exercised against a live production database.
- No load test has been run against the production Gunicorn/TLS topology.

Do not describe the project as production-proven until those gaps are closed.
