# ZeroTrace Measured Baseline

This file contains measurements from the Phase 0 environment inspection.

| Measurement | Result |
|---|---|
| Repository root | `E:\zerotrace-demo` |
| Operating system | Windows 11 Home Single Language, 64-bit |
| Windows version | `10.0.26300` |
| Git | `2.49.0.windows.1` |
| Docker CLI | `29.4.3` |
| Docker Desktop server | `29.4.3`, Linux engine |
| Docker Compose | `v5.1.3` |
| WSL | `2.7.14.0` |
| Python launcher | `py.exe`, Python `3.13.5` |
| Node.js | `v22.14.0` |
| npm | `10.9.2` |
| VS Code | `1.142.0` |
| Visible memory | Approximately 19.77 GiB |
| Free memory during inspection | Approximately 2.25 GiB |
| E: drive free space | Approximately 96.9 GiB |

## Phase 0 inspection notes

- Docker CLI is installed, but the Docker Desktop Linux daemon was not
  reachable during the first inspection; Docker Desktop was started and the
  Linux engine was verified afterward.
- At the time of the Phase 0 inspection, no application source or application
  test suite existed. Later Phase 2 verification recorded the runnable
  foundation checks in `tasks/evidence/phase-02.md`.

Environment values should be rechecked before Phase 0 signoff if the machine
or Docker state changes.

## Phase 15 resource measurements

Measured on 2026-10-21 with `python -m scripts.performance_report`; see
[tasks/evidence/phase-15.md](tasks/evidence/phase-15.md) and
[tasks/evidence/phase-15-measurements.json](tasks/evidence/phase-15-measurements.json)
for the full report.

| Measurement | Result |
|---|---|
| Cold start | median `1.4883 s`, max `2.2705 s` |
| Peak process RAM | `60.69 MB` |
| CPU utilization | `36.9%` |
| Guard latency | median `0.0119 s`, max `0.1205 s` |
| SQLite query latency | median `0.0074 s`, max `0.0100 s` |
| SQLite live-store size | `0.25 MB` |
| Host RAM available | `3,874.90 MB` |
| Swap used | `862.67 MB` |
| Concurrent synthetic load | `0.1143 s`, peak RSS `60.8 MB` |
| Optional Ollama model | unavailable, reported degraded |

The full profile's `9216 MB` target remains unproven until the optional model
stack is measured.

## Phase 16 gap-closure measurements

Measured on 2026-10-22; see
[tasks/evidence/phase-16.md](tasks/evidence/phase-16.md) for commands and
evidence files.

| Measurement | Result |
|---|---|
| Local password verification | `0.22 s` (Werkzeug hash check) |
| BFF demo-state request | `307.73 ms` |
| KEV real feed run | `6.26 s`, `1,754` records |
| EPSS real feed run | `38.39 s`, `394,415` records (full paged API) |
| NVD bounded first page | `5` facts, `0` quarantined |
| SQLite live store after full EPSS | `27,705,344` bytes |
| SQLite BFF backup | `143,360` bytes |
| SQLite Guard audit backup | `16,384` bytes |
| PostgreSQL BFF dump | `20,995` bytes |
| Root Python suite | `210 passed` in `24.89 s` |
| BFF suite | `24 passed` in `32.18 s` |
| Frontend bundle | `453.22 kB` JS, `135.63 kB` CSS |

The `27.7 MB` SQLite store reflects the full EPSS snapshot. PostgreSQL remains
the production persistence path; the local SQLite store is demo infrastructure.
The full live NVD sync was not measured end to end.
