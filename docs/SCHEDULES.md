# Scheduled scans

Scheduled scans are pre-approved, bounded runs. A schedule is not a way to
bypass scope authorization; it revalidates the same controls on every run.

## Contract

| Field | Constraint |
|---|---|
| `scopeId` | Must reference an approved, unexpired scope owned by the caller. |
| `target` | Must be in the scope's target list and pass the server-side target policy. |
| `profileId` | Must be one of the fixed profiles. |
| `intervalSeconds` | 300 seconds to 7 days (604800 seconds). |
| `authorized` | The BFF requires an explicit operator acknowledgement on create. |

High and Deep profiles still require the scope to be `isolated_lab` and a
verified DNS TXT challenge. The schedule cannot change the scope environment.

## API

Engine routes (server-side, engine key required):

- `GET /api/v1/recon/schedules` - list schedules for the current owner.
- `POST /api/v1/recon/schedules` - create a schedule.
- `POST /api/v1/recon/schedules/{schedule_id}/run` - run once now, with the
  same validation as a due run.
- `DELETE /api/v1/recon/schedules/{schedule_id}` - disable a schedule.

BFF routes (session + CSRF + acknowledgement):

- `GET /api/v1/engine/schedules`
- `POST /api/v1/engine/schedules`
- `POST /api/v1/engine/schedules/{schedule_id}/run`
- `DELETE /api/v1/engine/schedules/{schedule_id}`

The BFF strips unknown fields and rejects an interval outside the allowed range
before forwarding. The engine repeats the validation; the BFF is not the
authorization boundary.

## Failure behavior

- Queue pressure defers the run for 60 seconds. It does not create a second
  queue or exceed the configured depth.
- An expired scope, a target policy denial, a profile mismatch, or a missing
  DNS authorization **disables the schedule** and records the error.
- A failed scanner run does not silently retry forever. The operator sees the
  failure and must decide whether to create a new schedule.
- The schedule list is owner-scoped. An operator cannot inspect another owner's
  schedule. The BFF forwards the authenticated subject and role to the
  loopback engine with the engine API key, so the engine does not treat every
  BFF user as the same `local-operator`.

## Persistence

Schedules are stored in `live_scan_schedules` in both SQLite and PostgreSQL.
Migration `0009_scan_schedules` creates the PostgreSQL table; the down migration
drops it. The table is intentionally separate from the BFF auth tables.

## Retention

Disabled schedules whose last run is older than the retention window are
removed by `python -m scripts.prune_runtime_data --apply`. Active schedules are
never removed by the retention job.

## UI status

The schedule API and persistence are implemented. The operator console does not
yet expose a schedule editor; use the API or a reviewed script. Do not describe
scheduling as a finished UI feature until that screen exists.
