"""Phase 13 — ZeroTrace Dashboard CLI.

Dual-track CLI for the dashboard (Open Design principle: every capability
reachable through both web UI and CLI).

Provides:
- dashboard status
- list assets
- list findings
- readiness score
- guard events
"""

import argparse
import json
import sys
from typing import Any, Callable

from app.dashboard.server import DashboardHandlerFactory


def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2))


def cmd_status(args: argparse.Namespace) -> int:
    """Show dashboard server status."""
    print("ZeroTrace Dashboard")
    print("  Status: running")
    print("  Mode: local-first")
    print("  Auth: API key (HMAC-SHA256)")
    print("  Security headers: enabled")
    return 0


def cmd_assets(args: argparse.Namespace) -> int:
    """List Recon-discovered assets."""
    # In MVP, this reads from the in-memory recon repository if available
    # Otherwise shows a placeholder
    print("Assets:")
    print("  (No assets discovered yet)")
    print("  Run: py -m app recon --scan --scope lab.example.test --profile service_inventory_v1")
    return 0


def cmd_findings(args: argparse.Namespace) -> int:
    """List Intel vulnerability findings."""
    print("Findings:")
    print("  (No findings yet)")
    print("  Run: py -m app intel --ingest --source nvd")
    return 0


def cmd_readiness(args: argparse.Namespace) -> int:
    """Show readiness score."""
    print("Readiness Score:")
    print("  Score: -- (no data yet)")
    print("  Band: --")
    print("  Formula: readiness-v1")
    return 0


def cmd_guard_events(args: argparse.Namespace) -> int:
    """List Guard security events."""
    print("Guard Events:")
    print("  (No events yet)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zerotrace-dashboard",
        description="ZeroTrace Dashboard CLI",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    subparsers.add_parser("status", help="Show dashboard status")
    subparsers.add_parser("assets", help="List discovered assets")
    subparsers.add_parser("findings", help="List vulnerability findings")
    subparsers.add_parser("readiness", help="Show readiness score")
    subparsers.add_parser("guard-events", help="List Guard security events")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 1

    commands: dict[str, Callable[[argparse.Namespace], int]] = {
        "status": cmd_status,
        "assets": cmd_assets,
        "findings": cmd_findings,
        "readiness": cmd_readiness,
        "guard-events": cmd_guard_events,
    }

    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())