# ZeroTrace P6-LAB — Isolated Lab Runbook

This document describes how to run and use the isolated Docker lab environment
for P6-LAB Recon scanner testing (Subfinder, Nmap, TLS).

## Lab Overview

The lab (`compose.lab.yaml`) runs three isolated services on localhost-only
ports:

| Service | Container | Host Port (127.0.0.1) | Container Port | Purpose |
|---------|-----------|----------------------|----------------|---------|
| Web (nginx) | `zerotrace-lab-web` | 8080 | 80 | Subdomain discovery via Subfinder |
| Web Alt (httpd) | `zerotrace-lab-web-alt` | 8081 | 8080 | Second web target for Nmap |
| TLS (nginx + self-signed cert) | `zerotrace-lab-tls` | 8443 | 443 | TLS certificate/handshake inspection |

All ports are bound to `127.0.0.1` only — not reachable from the external
network.

## Prerequisites

- Docker Desktop running with Linux engine (verified in Phase 0)
- `docker compose` available
- `subfinder` and `nmap` binaries installed on the host (for real scanner execution)
- Administrator access to edit the hosts file

## Step 1: Add Hosts File Entries

ZeroTrace Recon resolves targets via DNS before scanning. Add these entries
to your hosts file so lab domains resolve to localhost:

**Windows (PowerShell, Administrator):**

```powershell
# Open hosts file in Notepad as Administrator
notepad C:\Windows\System32\drivers\etc\hosts
```

Add these lines:

```
127.0.0.1 lab-web.zerotrace.local
127.0.0.1 lab-web-alt.zerotrace.local
127.0.0.1 lab-tls.zerotrace.local
```

Verify resolution:

```powershell
Resolve-DnsName lab-web.zerotrace.local
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

# TLS service (self-signed cert, will warn)
Invoke-WebRequest -Uri https://127.0.0.1:8443/ -UseBasicParsing -SkipCertificateCheck
```

## Step 3: Run ZeroTrace Recon Against the Lab

Configure a ZeroTrace Recon scope targeting the lab domain:

```powershell
$env:ZEROTRACE_ENV = "development"
$env:DATABASE_URL = "postgresql://zerotrace:zerotrace-dev-only@127.0.0.1:5432/zerotrace"

# Create scope for lab-web.zerotrace.local using the test authorization harness
# (admin principal, test-only code, synthetic test domain)
```

Then create a scan run with one of the fixed profiles:

- `passive_subdomain_v1` — Subfinder passive discovery
- `service_inventory_v1` — Nmap top-100 TCP connect
- `tls_metadata_v1` — TLS certificate inspection

## Current host limitation

The default live-engine TLS adapter performs its single read on port **443**,
while this Compose file publishes the TLS container on host port **8443**. The
host also does not currently have `nmap` or `subfinder` installed. For the
recorded 2026-10-21 demo evaluation, the live console used the deterministic
`synthetic_inventory_v1` profile and did not claim a real scanner run. Use the
synthetic profile for a reproducible evaluation, or remap the lab and install
the scanner binaries before claiming real scanner evidence.

## Step 4: Verify Scanner Execution

The P6-LAB evidence must record:

| Evidence Item | How to Capture |
|---------------|----------------|
| Tool path and version | `subfinder --version`, `nmap --version` |
| Process group and timeout | ZeroTrace Recon run state and warnings |
| Cancellation behavior | Cancel a running scan via API |
| Parser output | Normalized assets/services from scan results |
| Partial failure | Scan with one service down, observe partial state |

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
- Remove the hosts file entries when the lab is no longer needed.

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Container fails to start | Check `docker compose -f compose.lab.yaml logs` |
| Port already in use | Change host port mapping in `compose.lab.yaml` |
| DNS resolution fails | Verify hosts file entries are correct |
| Scanner can't connect | Ensure container is healthy and port is bound to 127.0.0.1 |
| TLS certificate error | Expected — self-signed cert; use `-SkipCertificateCheck` or equivalent |