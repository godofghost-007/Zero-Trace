"""Generate a CycloneDX SBOM for the installed Python environment.

This is intentionally dependency-free so it works in CI before any extra tool
is installed. It lists installed distributions with their version and PyPI
package URL. Use Syft or the container SBOM action for image-layer SBOMs.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from importlib import metadata
from pathlib import Path
import re
import sys
from uuid import uuid4

_REQUIREMENT_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:==\s*([^\s;#]+))?"
)


def _requirements(path: Path) -> dict[str, str]:
    selected: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        match = _REQUIREMENT_RE.match(line)
        if match:
            selected[match.group(1).lower()] = match.group(2) or ""
    return selected


def _component(name: str, version: str) -> dict[str, object]:
    normalized = name.lower().replace("_", "-")
    return {
        "type": "library",
        "name": name,
        "version": version or "unknown",
        "purl": f"pkg:pypi/{normalized}@{version or 'unknown'}",
    }


def build_sbom(requirements: Path | None = None) -> dict[str, object]:
    selected = _requirements(requirements) if requirements else None
    components: list[dict[str, object]] = []
    for distribution in metadata.distributions():
        name = distribution.metadata.get("Name") or ""
        if not name:
            continue
        if selected is not None and name.lower() not in selected:
            continue
        components.append(_component(name, distribution.version))
    components.sort(key=lambda item: str(item["name"]).lower())
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "zerotrace-sbom",
                        "version": "1",
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": "zerotrace",
                "version": "0.1.0.dev0",
            },
        },
        "components": components,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("sbom-python.json"))
    parser.add_argument("--requirements", type=Path)
    parser.add_argument("--fail-on-empty", action="store_true")
    args = parser.parse_args()
    sbom = build_sbom(args.requirements)
    if args.fail_on_empty and not sbom["components"]:
        print("SBOM contains no components", file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(sbom, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {len(sbom['components'])} components to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
