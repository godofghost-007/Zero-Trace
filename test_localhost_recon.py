"""
Test Recon against localhost using ZeroTrace test authorization.

This script demonstrates the complete Recon pipeline against your own machine
(localhost). No external targets are scanned.

Run from: E:\zerotrace-demo
    $env:ZEROTRACE_ENV = "test"
    py test_localhost_recon.py
"""

from datetime import datetime, timedelta, timezone

from app.security import Principal
from app.test_authorization import TestOnlyAuthorizationRegistry
from app.recon import (
    ReconEngine,
    ReconRunState,
    Scope,
    Target,
    ReconProfile,
    PROFILES,
    SyntheticAdapter,
    AdapterResult,
    InMemoryReconRepository,
)


def main():
    print("=" * 60)
    print("ZERO TRACE — Localhost Recon Test")
    print("=" * 60)

    # ------------------------------------------------------------------
    # Step 1: Create test authorization for localhost
    # ------------------------------------------------------------------
    print("\n[1/5] Creating test authorization for localhost...")

    # Use "localhost.test" - passes domain validation (has a dot)
    # and test authorization (ends with .test TLD)
    test_domain = "localhost.test"

    auth = TestOnlyAuthorizationRegistry(environment="test").authorize(
        Principal("student-admin", "admin"),
        code="ZEROTRACE-TEST-ONLY",
        target=test_domain,                          # Your own machine (.test domain)
        profile_id="service_inventory_v1",           # Nmap profile
    )

    print(f"  Authorization ID: authorized")
    print(f"  Target:           {auth.target}")
    print(f"  Profile:          {auth.profile_id}")
    print(f"  Expires:          {auth.expires_at}")
    print("  [OK] Authorization created")

    # ------------------------------------------------------------------
    # Step 2: Create a scope for localhost.test
    # ------------------------------------------------------------------
    print("\n[2/5] Creating scope for localhost.test...")

    scope = Scope(
        scope_id="scope-localhost",
        owner_id="student-admin",
        targets=(test_domain,),
        environment="synthetic",          # Synthetic = no DNS TXT needed
        approved=True,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        profiles=("service_inventory_v1",),
    )

    print(f"  Scope ID:   {scope.scope_id}")
    print(f"  Owner:      {scope.owner_id}")
    print(f"  Targets:    {scope.targets}")
    print(f"  Environment:{scope.environment}")
    print(f"  Approved:   {scope.approved}")
    print("  [OK] Scope created")

    # ------------------------------------------------------------------
    # Step 3: Set up Recon engine with synthetic adapter
    # ------------------------------------------------------------------
    print("\n[3/5] Setting up Recon engine...")

    # SyntheticAdapter simulates nmap results without needing nmap installed
    # Replace with NmapAdapter when nmap is installed on your system
    adapter = SyntheticAdapter(
        AdapterResult(
            assets=(test_domain,),
            services=((test_domain, "tcp", 8080, "http"),),
            warnings=(),
        )
    )

    repository = InMemoryReconRepository()

    # DNS resolver for localhost testing - returns 127.0.0.1 for any domain
    def localhost_dns_resolver(domain: str) -> tuple[str, ...]:
        return ("127.0.0.1",)

    engine = ReconEngine(
        repository,
        {"service_inventory_v1": adapter},
        dns_resolver=localhost_dns_resolver,
    )

    print("  Adapter:    SyntheticAdapter (simulates nmap)")
    print("  Repository: InMemoryReconRepository")
    print("  [OK] Engine ready")

    # ------------------------------------------------------------------
    # Step 4: Run the scan
    # ------------------------------------------------------------------
    print("\n[4/5] Running scan against localhost...")

    target = Target(value=test_domain, kind="domain")

    run = engine.create_run(
        scope,
        target,
        profile_id="service_inventory_v1",
    )

    print(f"  Run ID:     {run.run_id[:8]}...")
    print(f"  State:      {run.state}")
    print(f"  Target:     {run.target.value}")
    print(f"  Profile:    {run.profile_id}")
    print(f"  Warnings:   {run.warnings}")
    print("  [OK] Scan completed")

    # ------------------------------------------------------------------
    # Step 5: Show results
    # ------------------------------------------------------------------
    print("\n[5/5] Scan results:")

    result = repository.results.get(run.run_id)
    if result:
        print(f"\n  Discovered Assets ({len(result.assets)}):")
        for asset in result.assets:
            print(f"    - {asset}")

        print(f"\n  Discovered Services ({len(result.services)}):")
        for svc in result.services:
            print(f"    - {svc.asset}:{svc.port}/{svc.protocol} -> {svc.product}")

        if result.inventory_delta:
            print(f"\n  Inventory Delta:")
            print(f"    Added assets:   {result.inventory_delta.added_assets}")
            print(f"    Added services: {result.inventory_delta.added_services}")

    print("\n" + "=" * 60)
    print("[OK] Localhost Recon test complete!")
    print("=" * 60)
    print()
    print("Next steps:")
    print("  1. Install nmap: https://nmap.org/download.html")
    print("  2. Install subfinder: https://github.com/projectdiscovery/subfinder/releases")
    print("  3. Replace SyntheticAdapter with NmapAdapter for real scanning")
    print("  4. Run: py -m unittest discover -s tests -v  (full test suite)")


if __name__ == "__main__":
    main()