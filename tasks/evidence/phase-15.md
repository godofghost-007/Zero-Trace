# Phase 15 Evidence — Resource and Reliability Measurement

## Decision

Phase 15 measurement is **implemented and reproducible** on the target laptop
with synthetic Recon, Intel, Guard, and SQLite work. The raw report is
[phase-15-measurements.json](phase-15-measurements.json).

The measured core profile remains comfortably inside its declared RAM budget.
The full profile's 9 GB target remains **unproven** because it requires the
optional model stack and a larger workload than this evaluation ran.

## Environment

| Item | Value |
|---|---|
| OS | Windows 11 `10.0.26300` |
| Python | `3.13.5` |
| Logical CPUs | 4 |
| Total RAM | `20,247.33 MB` |
| Available RAM during run | `3,995.18 MB` |
| Swap total / used | `6,034.39 MB` / `862.67 MB` |

## Date

2026-10-21

## Measured results

| Measurement | Result | Budget | Status |
|---|---|---|---|
| Cold start (3 samples) | median `1.4883 s`, max `2.2705 s` | < 30 s | PASS |
| Peak process RAM | `60.69 MB` | < 4096 MB (core) | PASS |
| Per-service import footprint | recon `23.79`, intel `21.09`, guard `40.55`, readiness `19.42`, security `21.14`, events `19.62` MB | informational | PASS |
| CPU utilization (1 s sample) | `36.9%` | < 80% | PASS |
| Guard latency (5 samples) | median `0.0119 s`, max `0.1205 s` | < 2 s | PASS |
| SQLite query latency (5 samples) | median `0.0074 s`, max `0.0100 s` | < 5 s | PASS |
| SQLite live-store size | `0.25 MB` | informational | PASS |
| Swap used | `862.67 MB` | informational | PASS |
| Host RAM headroom | `3,874.90 MB` | > 512 MB | PASS |
| Host CPU headroom | `84.0%` | informational | PASS |
| Concurrent synthetic load | `0.1143 s`, peak RSS `60.8 MB` | bounded | PASS |
| Concurrent Recon | 3/3 `completed` | no failures | PASS |
| Concurrent Guard | 5/5 HTTP `200` | no failures | PASS |
| Concurrent Intel | 3/3 HTTP `202` | no failures | PASS |
| Optional model runtime | unavailable; degraded | explicit degraded state | PASS (degraded) |

## Deployment profiles

| Profile | Optional Ollama | Max RAM | Max CPU |
|---|---|---|---|
| `core` | no | `4096 MB` | `50%` |
| `full` | yes | `9216 MB` | `80%` |
| `dev` | no | `3072 MB` | `40%` |

The `core` profile is the supported laptop default. Ollama is absent on this
host, so the core profile's deterministic detectors are the tested path and
the optional model is reported as degraded rather than assumed available.

## Verification commands

```powershell
frontend\.venv\Scripts\python.exe -m scripts.performance_report
frontend\.venv\Scripts\python.exe -m pytest -q tests\test_performance.py
```

The report regenerated `tasks/evidence/phase-15-measurements.json` with
`overall: passed`.

## Exceptions and limits

- The full profile's `9216 MB` budget is a design target, not a measured
  workload result. No Ollama model stack was started.
- PostgreSQL latency/size was not measured because PostgreSQL was not running;
  the result above is the SQLite live-store path used by the local demo.
- Per-service memory is a fresh-process module import footprint, not isolated
  container memory, because ZeroTrace runs as one Python process.
- Measurements are synthetic and do not represent production load.

## Human signoff

**Human signoff:** Pending operator review of this Phase 15 evidence record.
Implementation was authorized on 2026-10-21.
