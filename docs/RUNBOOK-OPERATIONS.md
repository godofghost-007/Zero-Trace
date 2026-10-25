# Operations runbook

This runbook maps the shipped alerts to the first diagnostic steps. It assumes
the production Compose stack from `deploy/README.md` and the observability
overlay in `deploy/compose.observability.yaml`.

## Start and verify the observability overlay

```bash
export ZEROTRACE_GRAFANA_ADMIN_PASSWORD='replace-with-a-long-password'
cp deploy/observability/metrics-token.example deploy/observability/metrics-token
# Put the same value in ZEROTRACE_METRICS_TOKEN in .env.production.
docker compose -f deploy/compose.prod.yaml -f deploy/compose.observability.yaml up -d
```

Grafana and Prometheus bind to `127.0.0.1` only. Reach them through an SSH
tunnel or a separately authenticated reverse proxy. Do not publish them on the
public interface.

Check:

```bash
curl -fsS -H "Authorization: Bearer $ZEROTRACE_METRICS_TOKEN" \
  https://$ZEROTRACE_DOMAIN/api/v1/metrics | head
curl -fsS -H "Authorization: Bearer $ZEROTRACE_METRICS_TOKEN" \
  https://$ZEROTRACE_DOMAIN/api/v1/engine/metrics | head
```

## BFF or engine unavailable

1. `docker compose -f deploy/compose.prod.yaml ps` and check health.
2. Read `docker compose logs --since=15m bff` and `engine`.
3. Check `GET /api/v1/ready` and the engine `/ready` output through the BFF
   status route.
4. If the database is the cause, verify the Supabase pooler and direct
   connection separately. Do not point migrations at the transaction pooler.
5. If the engine is healthy but the BFF is not, verify
   `ZEROTRACE_ENGINE_URL` is a loopback URL and that the BFF shares the engine
   network namespace.
6. If the Guard sidecar is unhealthy, the BFF health endpoint can still be
   healthy but `POST /api/v1/guard/chat` returns `503 guard_unavailable`.
   Check `docker compose logs guard` and the Guard credential in `.env.guard`.
7. Do not restart the engine while a scan is running unless you accept losing
   the in-flight result. The queue is durable, but the running subprocess is
   not.

## High error rate

1. Split `zerotrace_http_requests_total` by route and status.
2. Check whether the errors are authentication failures, Guard blocks, or
   upstream 5xx responses.
3. If Guard is returning `pii_detected`, confirm whether the deployment is in
   `block` or `redact` mode. Do not switch to `redact` just to silence an alert;
   record the privacy decision.
4. If the engine returns `upstream is not allowlisted`, check the provider base
   URL and the Guard allowlist. Prefer exact hosts; add a `https://*.example.com`
   entry only when every subdomain is intentionally trusted.
5. Capture the request ID from the response and search the JSON logs.

## High latency

1. Compare BFF p95 with engine request duration.
2. Check PostgreSQL connection saturation and pool waits.
3. Check whether a scan is saturating CPU. Nmap and Subfinder are bounded by
   the queue, but a high profile can still consume the CPU budget.
4. Check the provider latency for Guard. A slow model provider is not a
   ZeroTrace infrastructure incident, but it still counts against the BFF SLO.

## Scan failures

1. Inspect the scan state and warnings in the UI or the engine scan result.
2. `failed` and `timed_out` are different: a timeout usually means a network
   path or a profile that is too broad; a failure usually means a missing
   adapter or a scanner error.
3. Verify scanner inventory: Nmap and Subfinder must be present and meet the
   configured minimum version. Check `/api/v1/engine/status`.
4. Verify the target is still inside an approved, unexpired scope.
5. Do not retry a public target without checking authorization. High and Deep
   scans require a fresh DNS TXT verification.

## Scheduled scan blocked

A scheduled scan is disabled when the scope expires, the target policy changes,
or DNS authorization is no longer valid. This is fail-closed behavior.

1. Open the schedule list and read `lastError`.
2. Recreate the scope and re-verify DNS TXT if needed.
3. Create a new schedule. Do not re-enable a stale authorization.
4. Confirm the schedule interval is at least 300 seconds and at most 7 days.

## Guard block spike

1. Compare `blocked="true"` with the total inspection rate.
2. Review the reason distribution. A spike in `prompt_injection` may be an
   attack or a new application prompt that trips a regex.
3. Do not disable Guard. If a benign prompt is blocked, add a regression case
   to `app/guard_eval.py`, adjust the detector, and re-run
   `python -m scripts.evaluate_guard`.
4. If the cause is PII, decide whether the response policy should block or
   redact, and record the decision.

## Intel feed stale

1. Check the Intel scheduler status and the last error for each feed.
2. Verify outbound access to the allowlisted NVD, EPSS, and KEV endpoints.
3. A failed feed keeps the previous snapshot. Do not delete the snapshot just
   because it is stale; stale data is safer than no data.
4. If the provider is down, record the incident and keep the last-known-good
   snapshot until the feed recovers.

## Backup and restore

See `docs/BACKUP-RESTORE.md`. A restore is a destructive operation and requires
`--yes`. Always verify the encrypted backup before restoring.

## Incident closeout

Record:

- start and end time;
- affected objective;
- user-visible impact;
- root cause;
- the change that prevents recurrence;
- whether the SLO or alert threshold needs revision.
