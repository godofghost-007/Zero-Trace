# ZeroTrace P6-LAB — Isolated Lab Runbook

This document describes how to run and use the isolated Docker lab environment
for P6-LAB Recon scanner testing (Subfinder, Nmap, TLS).

## Lab Overview

The lab (`compose.lab.yaml`) runs three isolated services on localhost-only
ports:

| Service | Container | Host Port (127.0.0.1) | Container Port | Purpose |
|---------|-----------|----------------------|----------------|---------|
| Web (nginx) | `zerotrace-lab-web` | 8080 | 80 | Subdomain discovery via Subfinder |
| Web Alt (httpd) | `zerotrace-lab-web-alt` | 8081 | 80 | Second web target for Nmap |
| TLS (nginx + self-signed cert) | `zerotrace-lab-tls` | 8443 | 443 | TLS certificate/handshake inspection |

All ports are bound to `127.0.0.1` only — not reachable from the external
network.

## Prerequisites

- Docker Desktop running with Linux engine (verified in Phase 0)
- `docker compose` available
- `subfinder` and `nmap` binaries installed on the host (for real scanner execution)

No hosts-file edit or Administrator access is required. The recorded Phase 16
run uses the public `nip.io` wildcard so the lab names resolve to loopback:

- `lab-tls.127.0.0.1.nip.io` → `127.0.0.1`
- `lab-web.127.0.0.1.nip.io` → `127.0.0.1`
- `lab-web-alt.127.0.0.1.nip.io` → `127.0.0.1`

The optional traditional names (`lab-web.zerotrace.local`, and so on) still
require hosts-file entries if you prefer them.

## Step 1: Verify loopback resolution

```powershell
Resolve-DnsName lab-tls.127.0.0.1.nip.io
```

## Step 2: Start the Lab

```powershell
docker compose -f compose.lab.yaml up -d
```

Verify containers are running:

```powershell
docker compose -f compose.lab.yaml ps
```

Verify services are reachable from the host:

```powershell
# Web service
Invoke-WebRequest -Uri http://127.0.0.1:8080/ -UseBasicParsing

# Alt web service
Invoke-WebRequest -Uri http://127.0.0.1:8081/ -UseBasicParsing

# TLS service (self-signed certificate)
curl.exe -k https://127.0.0.1:8443/
```

The `lab-tls` container generates a short-lived self-signed certificate at
startup. It is not a production certificate.

## Step 3: Run ZeroTrace Recon Against the Lab

Start the live engine with the lab ports and a lab-only database:

```powershell
$env:PATH = "$env:LOCALAPPDATA\ZeroTrace\bin;C:\Program Files (x86)\Nmap;$env:PATH"
$env:ZEROTRACE_TLS_PORT = "8443"
$env:ZEROTRACE_TLS_VERIFY = "false"
$env:ZEROTRACE_NMAP_PORTS = "8080,8081,8443"
$env:ZEROTRACE_INTEL_SCHEDULE_ENABLED = "false"
$env:ZEROTRACE_LIVE_DB = "data/lab-live-engine.sqlite3"
.\.venv\Scripts\python.exe -m scripts.live_engine
```

`ZEROTRACE_TLS_VERIFY=false` is lab-only; the engine records the certificate as
`status: "unverified"` and never as `valid`.

In a second terminal, run the bounded evidence driver:

```powershell
.\.venv\Scripts\python.exe -m scripts.lab_scan
```

The scope it creates is explicit, expires in one hour, and contains only
`lab-tls.127.0.0.1.nip.io` and `lab.zerotrace.local`. It uses the `synthetic`
environment label because `isolated_lab` requires a public DNS TXT challenge.

Profiles used:

- `passive_subdomain_v1` — Subfinder passive discovery
- `service_inventory_v1` — Nmap TCP connect over ports `8080,8081,8443`
- `tls_metadata_v1` — one TLS metadata read on port `8443`

## Step 4: Verify Scanner Execution

The P6-LAB evidence must record:

| Evidence Item | How to Capture |
|---------------|----------------|
| Tool path and version | `subfinder --version`, `nmap --version` |
| Process group and timeout | ZeroTrace Recon run state and warnings |
| Cancellation behavior | Cancel a running scan via API |
| Parser output | Normalized assets/services from scan results |
| Partial failure | Scan with one service down, observe partial state |

The recorded Phase 16 run is in
[`tasks/evidence/phase-16-lab-scan.json`](../tasks/evidence/phase-16-lab-scan.json).
It found open loopback ports `8080`, `8081`, and `8443`, read the lab
self-signed certificate as `unverified`, and completed the passive profile
without inventing subdomain assets.

## Step 5: Stop and Clean Up

```powershell
docker compose -f compose.lab.yaml down
docker compose -f compose.lab.yaml down -v   # Also remove volumes
```

## Safety Boundaries

- **Do not** publish ports to `0.0.0.0` — only `127.0.0.1`.
- **Do not** add public domains or IP addresses to the lab scope.
- **Do not** run scanners against any target other than the lab domains above.
- **Do not** commit scan results containing credentials or sensitive data.
- Remove the optional hosts-file entries if you added them.

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Container fails to start | Check `docker compose -f compose.lab.yaml logs` |
| Port already in use | Change host port mapping in `compose.lab.yaml` |
| DNS resolution fails | Verify hosts file entries are correct |
| Scanner can't connect | Ensure container is healthy and port is bound to 127.0.0.1 |
| TLS certificate error | Expected — self-signed cert; use `curl.exe -k` or the engine's lab-only `ZEROTRACE_TLS_VERIFY=false` |