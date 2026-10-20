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
