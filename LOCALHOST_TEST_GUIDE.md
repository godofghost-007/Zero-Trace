# ZeroTrace Localhost Test Setup — Recon with Nmap/Subfinder

This guide helps you install nmap and subfinder on Windows, then test ZeroTrace Recon against **localhost only** (your own machine).

---

## Step 1: Install Nmap (Manual)

1. Download: https://nmap.org/dist/nmap-7.80-setup.exe
2. Run the installer as Administrator
3. During installation, check **"Add to PATH"** if available
4. Verify: `nmap --version` should show version 7.80

**Alternative:** Download directly from https://nmap.org/download.html

---

## Step 2: Install Subfinder (Manual)

Subfinder is not available via winget. Install manually:

1. Go to: https://github.com/projectdiscovery/subfinder/releases
2. Download the Windows ZIP (e.g., `subfinder-windows-amd64.zip`)
3. Extract to a folder (e.g., `C:\tools\subfinder\`)
4. Add that folder to your Windows PATH
5. Verify: `subfinder --version` should show the version

**Alternative:** Use Go:
```powershell
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

---

## Step 3: Add Localhost Hosts Entry

Run PowerShell as Administrator:

```powershell
notepad C:\Windows\System32\drivers\etc\hosts
```

Add this line:
```
127.0.0.1 localhost
127.0.0.1 lab-web.zerotrace.local
```

Save and close.

Verify:
```powershell
Resolve-DnsName localhost
Resolve-DnsName lab-web.zerotrace.local
```

---

## Step 4: Start a Local Service for Nmap to Scan

Nmap needs something to scan. Start a simple local web server:

```powershell
# Option A: Python HTTP server
python -m http.server 8080

# Option B: If you have the Docker lab running
docker compose -f compose.lab.yaml up -d
```

The lab provides:
- `lab-web.zerotrace.local` → port 8080 (nginx)
- `lab-tls.zerotrace.local` → port 8443 (TLS)

---

## Step 5: Create Authorization and Run Recon Against Localhost

ZeroTrace's test authorization harness accepts `localhost` and `host.docker.internal` domains. Here's the complete test script:

```python
"""
Test Recon against localhost using ZeroTrace test authorization.
Run from: E:\zerotrace-demo
"""

from datetime import datetime, timedelta, timezone
from app.security import Principal
from app.test_authorization import TestOnlyAuthorizationRegistry
from app.recon import (
    ReconEngine, ReconRunState, Scope, Target,
    ReconProfile, PROFILES, SyntheticAdapter, AdapterResult,
    InMemoryReconRepository
)
from app.recon_pg import PostgresReconRepository


# --- Step 1: Create test authorization for localhost ---

auth = TestOnlyAuthorizationRegistry(environment="test").authorize(
    Principal("student-admin", "admin"),
    code="ZEROTRACE-TEST-ONLY",
    target="localhost",                          # Your own machine
    profile_id="service_inventory_v1",           # Nmap profile
)

print(f"Authorization: {auth.target} -> {auth.profile_ids}")
print(f"Expires: {auth.expires_at}")

# --- Step 2: Create a scope for localhost ---

scope = Scope(
    scope_id="scope-localhost",
    owner_id="student-admin",
    targets=("localhost",),
    environment="synthetic",                     # Synthetic = no DNS TXT needed
    approved=True,
    expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    profiles=("service_inventory_v1",),
)

# --- Step 3: Set up Recon engine with a synthetic adapter ---

# Use SyntheticAdapter for testing without real nmap
# (Replace with real NmapAdapter when nmap is installed)
adapter = SyntheticAdapter(
    AdapterResult(
        assets=("localhost",),
        services=(("localhost", "tcp", 8080, "http"),),
        warnings=(),
    )
)

repository = InMemoryReconRepository()
engine = ReconEngine(
    repository,
    {"service_inventory_v1": adapter},
)

# --- Step 4: Run the scan ---

target = Target(value="localhost", kind="domain")

run = engine.create_run(
    scope,
    target,
    profile_id="service_inventory_v1",
)

print(f"\nScan Result:")
print(f"  State:       {run.state}")
print(f"  Target:      {run.target.value}")
print(f"  Profile:     {run.profile_id}")
print(f"  Warnings:    {run.warnings}")

# --- Step 5: Check results ---

result = repository.results.get(run.run_id)
if result:
    print(f"\nDiscovered Assets: {result.assets}")
    print(f"Discovered Services:")
    for svc in result.services:
        print(f"  - {svc.asset}:{svc.port}/{svc.protocol} ({svc.product})")

print("\n✓ Localhost Recon test complete!")
```

Save this as `test_localhost_recon.py` and run:

```powershell
cd E:\zerotrace-demo
$env:ZEROTRACE_ENV = "test"
py test_localhost_recon.py
```

---

## Step 6: Run with Real Nmap (After Installation)

Once nmap is installed, replace the SyntheticAdapter with NmapAdapter:

```python
from app.recon import NmapAdapter, SubprocessRunner

# Real nmap adapter (only after nmap is installed and in PATH)
adapter = NmapAdapter(
    executable="nmap",
    runner=SubprocessRunner(),
)
```

**Important:** NmapAdapter scans the target's IP. For localhost, it will scan your own machine's open ports.

---

## Step 7: Run Full Test Suite

To verify the entire ZeroTrace pipeline (Recon → Intel → Patch) works:

```powershell
cd E:\zerotrace-demo
$env:ZEROTRACE_ENV = "development"
py -m unittest discover -s tests -v
```

This runs **145 tests** covering all phases including Recon, Intel, correlation, prioritization, and remediation proposals.

---

## Security Boundaries (Still Enforced)

Even for localhost testing:

| Rule | Status |
|------|--------|
| Only localhost/127.0.0.1 targets | ✅ Enforced |
| Approved scope required | ✅ Enforced |
| Profile allowlisting | ✅ Enforced |
| Rate limiting | ✅ Enforced |
| No external targets | ✅ Enforced |
| No automatic remediation execution | ✅ Enforced |

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `nmap` not found | Install from https://nmap.org/download.html |
| `subfinder` not found | Install from https://github.com/projectdiscovery/subfinder/releases |
| Authorization fails | Use `environment="test"` and code `"ZEROTRACE-TEST-ONLY"` |
| Target outside scope | Ensure target matches scope targets exactly |
| Profile not allowlisted | Use one of: `service_inventory_v1`, `passive_subdomain_v1`, `tls_metadata_v1`, `s3_read_only_v1` |

---

## Files Created

| File | Purpose |
|------|---------|
| `test_localhost_recon.py` | Localhost Recon test script |
| `compose.lab.yaml` | Docker lab environment (already created) |
| `docs/LAB-RUNBOOK.md` | Full lab runbook |

---

You now have everything to test Recon against localhost. Start with the test script using SyntheticAdapter, then install nmap/subfinder for real scanning against your own machine.