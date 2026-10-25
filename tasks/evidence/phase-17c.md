# Phase 17C evidence - scanner safety, schedules, and retention

Date: 2026-10-25

## Implemented

- Four scan levels for Nmap and Subfinder, with level-specific profiles and
  adapter mapping. Normal is the default for both.
- Server-side target allow/deny policy in `app/target_policy.py`, wired into
  scope creation and scan queueing. The policy is not trusted from the browser.
- Runtime scanner version gates in `app/scanner_versions.py`, wired into
  `/ready` and `/api/v1/engine/status`.
- Engine image pins Nmap `7.95+dfsg-3` and Subfinder `2.6.7`.
- Container hardening: `read_only`, `init`, `pids_limit`, `tmpfs`,
  `cap_drop: ALL`, and `no-new-privileges` for the engine, Guard, BFF, and
  Caddy services. Guard and BFF share the engine network namespace and are not
  published. Caddy edge rate limits are configured with a pinned custom image.
- Scheduled scans in `app/scan_schedule.py`:
  - bounded interval (300-604800 seconds);
  - revalidation of scope, target policy, profile, and DNS authorization on
    every run;
  - fail-closed disable on authorization or scope failure;
  - queue-pressure deferral instead of queue growth;
  - owner-scoped list/run/disable routes; the BFF forwards the authenticated
    subject and role to the loopback engine so owner checks are per user;
  - SQLite and PostgreSQL persistence through `live_scan_schedules`;
  - migration `0009_scan_schedules` and its down migration.
- Retention job `scripts/prune_runtime_data.py` for terminal scans, Guard
  counters, readiness snapshots, and old disabled schedules. It defaults to a
  dry run and requires `--apply`.

## Verification

```text
py -3.13 -m pytest tests/test_target_policy.py tests/test_scanner_versions.py \
  tests/test_scan_schedule.py tests/test_retention.py -q
```

The schedule suite covers interval bounds, authorization failure, persistence,
owner scoping, and API behavior. The retention suite proves that old operational
rows are pruned while recent rows remain.

```text
py -3.13 -m scripts.prune_runtime_data --sqlite-path <demo.sqlite3>
# dry run; no rows deleted
py -3.13 -m scripts.prune_runtime_data --sqlite-path <demo.sqlite3> --apply
```

```text
scripts/verify_container_hardening.py
# tasks/evidence/container-hardening.json: ok=true
```

```text
$env:ZEROTRACE_TEST_DATABASE_URL='postgresql://...'
py -3.13 -m pytest -q
265 passed
```

The full root suite includes the disposable PostgreSQL migration tests. The
PostgreSQL migration apply/rollback drill is recorded in
`tasks/evidence/migration-rollback.json`.

## Scheduled-scope behavior

See `docs/SCHEDULES.md`. The key invariant is that a schedule stores a
pre-approved intent, not a permanent authorization. A run that cannot re-prove
its scope, target policy, profile, and DNS authorization is disabled rather than
executed.

## Known gaps

- The operator console has no schedule editor yet; the API is implemented.
- The retention job has not run against a real production PostgreSQL database.
- Scanner sandboxing is container-level. There is no separate network namespace
  or per-scan filesystem jail beyond the container controls.
- Caddy edge rate limiting is configured and locally validated, but has not
  been load-tested in production.
- No production VPS or Supabase deployment has been performed.
