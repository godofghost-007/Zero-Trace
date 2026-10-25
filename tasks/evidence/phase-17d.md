# Phase 17D evidence - observability, backups, and operations

Date: 2026-10-25

## Implemented

- Dependency-free in-process metrics with counters, gauges, and histograms.
- JSON logging, request IDs, W3C `traceparent` parsing, and BFF-to-engine trace
  propagation.
- Engine `/metrics` and BFF `/api/v1/metrics`; optional bearer-token
  authorization for scrapers.
- BFF `/api/v1/engine/metrics` proxy so one authenticated scrape covers both
  processes.
- Prometheus scrape config, 8 alert rules, Alertmanager config, Grafana
  datasource/dashboard provisioning, and an optional observability Compose
  overlay.
- Encrypted backup primitives using Fernet with an inner
  `zerotrace-backup-v1` manifest and outer `zerotrace-backup-v2` envelope.
- Backup/restore/verify/prune CLI with SQLite and PostgreSQL paths, off-host
  copy, and retention that always keeps the newest copies.
- SLOs, operations runbook, backup/restore runbook, and alert-to-runbook links.

## Verification

### Configuration

```text
docker compose -f deploy/compose.prod.yaml \
  -f deploy/compose.observability.yaml config --quiet
# exit 0

promtool check config /etc/prometheus/prometheus.yml
# SUCCESS: 1 rule files found
# SUCCESS: valid prometheus config file syntax
# SUCCESS: 8 rules found

amtool check-config /etc/alertmanager/alertmanager.yml
# SUCCESS
```

Evidence: `tasks/evidence/observability-config.json`.

### Backup and restore drill

The drill applied migrations 0001-0009 to a disposable PostgreSQL 16 container,
seeded one scope, one scan, and one schedule, created an encrypted backup,
verified the outer and inner checksums, dropped the scan and schedule tables,
restored with `pg_restore --clean --if-exists`, and confirmed the rows returned.

```text
restore_seconds=8.81
scopes=1
scans=1
schedules=1
```

Evidence: `tasks/evidence/postgres-backup-restore.json`.

### Observability and runtime smoke

```text
frontend\.venv\Scripts\python.exe -m scripts.security_smoke
# passed=true

frontend\.venv\Scripts\python.exe -m scripts.load_test \
  --requests 100 --concurrency 10 --fail
# 200/200 200s, p95 92.69 ms, 163.36 req/s, passed=true
```

Evidence: `tasks/evidence/security-smoke.json`,
`tasks/evidence/load-test.json`.

### Tests

```text
py -3.13 -m pytest -q
265 passed

frontend\.venv\Scripts\python.exe -m pytest backend/tests -q
61 passed
```

The backup suite covers encrypted round-trip, restore, wrong-key/tamper
rejection, and retention pruning.

## SLO and RPO/RTO

- BFF availability: 99.5% over 30 days.
- BFF p95 latency: below 1.0 s.
- Intel feed freshness: no older than 26 hours.
- Backup RPO: 24 hours.
- Backup RTO: 2 hours, including operator decision time.
- Observed local restore: 8.81 seconds for a small synthetic database.

The local restore is not a production VPS or Supabase RTO. It excludes DNS,
TLS, image pulls, provider recovery, and the time to retrieve the off-host key.

## Known gaps

- The observability overlay has not been run against a real production stack.
- Alertmanager ships with a null receiver; no pager or email integration exists.
- No WAL archiving or point-in-time recovery was tested.
- Off-host copy used a local directory; rclone/S3 transfer was not exercised.
- Metrics are in-process and disappear on restart. There is no long-term
  metrics store beyond the 15-day Prometheus retention.
- The load test uses an embedded Flask/SQLite app, not Gunicorn/PostgreSQL/TLS.
