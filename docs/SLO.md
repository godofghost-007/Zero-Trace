# ZeroTrace service objectives

These are the objectives for a single-tenant, self-hosted deployment. They are
deliberately modest and are not a claim that every deployment has met them.
Measure them from the BFF and engine metrics exposed at `/api/v1/metrics` and
`/api/v1/engine/metrics`.

## Objectives

| Objective | Target | Measurement | Window |
|---|---|---|---|
| BFF availability | 99.5% of successful requests | `1 - 5xx / all requests` from `zerotrace_http_requests_total` | 30 days |
| BFF latency | p95 below 1.0 s | `zerotrace_http_request_duration_seconds` histogram | 5 minutes |
| Engine scrape availability | 99.5% | Prometheus `up{job="zerotrace-engine"}` | 30 days |
| Scan completion | 90% of started scans reach `completed` or `partial` | `zerotrace_scans_completed_total` | 7 days |
| Scheduled scan dispatch | 99% of due schedules are queued within 60 s | `zerotrace_scheduled_scans_total` and schedule timestamps | 7 days |
| Intel feed freshness | NVD/EPSS/KEV no older than 26 hours | `zerotrace_intel_feed_age_seconds` | continuous |
| Backup RPO | 24 hours | latest verified encrypted backup age | continuous |
| Backup RTO | 2 hours | last restore drill, including operator decision time | per drill |
| Guard availability | 99.5% of inspected requests | BFF Guard route metrics | 30 days |

## What is intentionally not promised

- No 99.99% objective. A single VPS, a single PostgreSQL instance, and a
  single Guard process cannot honestly provide it.
- No zero-data-loss objective. The RPO is 24 hours unless the operator adds
  WAL archiving or a managed PostgreSQL PITR feature.
- No objective for scanner accuracy. Nmap and Subfinder results depend on the
  target, network path, and profile.
- No objective for hosted model quality or provider uptime. Guard can only
  protect traffic that is routed through it.

## Alert routing

Prometheus rules live in `deploy/observability/alerts.yml`. Alertmanager ships
with a null receiver so the deployment does not pretend an on-call integration
exists. Set a real receiver before production use.

## Review cadence

Review the objectives after the first 30 days of real traffic and after every
incident. Lowering an objective requires a written reason in the change record;
it is not a way to make a failing deployment look healthy.
