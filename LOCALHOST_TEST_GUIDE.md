# Isolated Lab Setup

This guide covers the bounded lab path for Recon evaluation. It replaces the
earlier localhost/Nmap scratch instructions, which assumed binaries that are not
installed and used a target name that the current domain validator rejects.

## What the lab provides

`compose.lab.yaml` publishes three loopback-only services:

| Service | Host port | Purpose |
|---|---|---|
| `lab-web` (nginx) | `127.0.0.1:8080` | HTTP inventory target |
| `lab-web-alt` (httpd) | `127.0.0.1:8081` | Second HTTP target |
| `lab-tls` (nginx TLS) | `127.0.0.1:8443` | TLS metadata target |

Only loopback addresses are published. Do not change these mappings to
`0.0.0.0`.

## Start the lab

```powershell
docker compose -f compose.lab.yaml up -d
docker compose -f compose.lab.yaml ps
```

Add the lab names to your hosts file only if you are running a real scanner:

```text
127.0.0.1 lab-web.zerotrace.local
127.0.0.1 lab-web-alt.zerotrace.local
127.0.0.1 lab-tls.zerotrace.local
```

Editing the hosts file requires Administrator access. Remove the entries when
you are finished.

## Run the authorized demo flow

1. Start the dashboard and live engine with `.\run-live-demo.ps1`.
2. Open <http://127.0.0.1:3000/targets>.
3. Create a scope for a lab name with an explicit authorization
   acknowledgement. The default profile is `tls_metadata_v1`; use
   `synthetic_inventory_v1` when no scanner binary is installed.
4. Run the scan and inspect the normalized result and readiness panel.
5. Run the CISA KEV sync from the Intel/console flow, then run the Guard
   jailbreak inspection.
6. Stop the lab:

```powershell
docker compose -f compose.lab.yaml down
```

## Current practical limit

The host does not have `nmap` or `subfinder` installed. The live demo therefore
uses the synthetic inventory adapter for deterministic evidence. The TLS
profile performs a single bounded certificate read when the target resolves and
trusts the lab certificate; a self-signed lab certificate is reported as
unreachable rather than silently trusted.

## Verification

```powershell
frontend\.venv\Scripts\python.exe -m pytest -q
frontend\.venv\Scripts\python.exe -m pytest -q frontend\backend\tests
Set-Location frontend; pnpm exec tsc --noEmit; pnpm test; pnpm build
```

See [docs/LAB-RUNBOOK.md](docs/LAB-RUNBOOK.md) for the full lab runbook and
[docs/decisions](docs/decisions) for recorded design decisions.
