"""Phase 15 resource/reliability report.

Runs synthetic measurements and prints a JSON report. No external target,
scanner, feed, or model call is used.

Run with::

    python -m scripts.performance_report
"""

from __future__ import annotations

import json
import platform
import statistics
from pathlib import Path
import sys
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import psutil

from app.performance import (
    get_profile_config,
    measure_cold_start,
    measure_concurrent_load,
    measure_cpu_utilization,
    measure_database_size,
    measure_db_query_latency,
    measure_guard_latency,
    measure_host_headroom,
    measure_optional_model_load,
    measure_peak_ram,
    measure_per_service_memory,
    measure_swap_usage,
)


def _samples(call: Callable[[], float], count: int = 3) -> dict[str, float]:
    values = [call() for _ in range(count)]
    return {
        "samples": values,
        "min": round(min(values), 4),
        "median": round(statistics.median(values), 4),
        "max": round(max(values), 4),
    }


def collect_report() -> dict[str, object]:
    memory = psutil.virtual_memory()
    swap = psutil.swap_memory()
    cold_start = _samples(measure_cold_start, 3)
    guard_latency = _samples(measure_guard_latency, 5)
    db_latency = _samples(measure_db_query_latency, 5)

    profiles = {
        name: get_profile_config(name) for name in ("core", "full", "dev")
    }
    model = measure_optional_model_load()

    checks = {
        "cold_start_under_30s": cold_start["max"] < 30.0,
        "guard_latency_under_2s": guard_latency["max"] < 2.0,
        "db_latency_under_5s": db_latency["max"] < 5.0,
        "peak_ram_under_core_4gb": measure_peak_ram() < profiles["core"]["max_ram_mb"],
        "host_headroom_above_512mb": measure_host_headroom()["ram_available_mb"] > 512.0,
    }

    return {
        "phase": 15,
        "host": {
            "operating_system": f"{platform.system()} {platform.release()}",
            "platform": platform.platform(),
            "python": platform.python_version(),
            "cpu_count": psutil.cpu_count(logical=True),
            "ram_total_mb": round(memory.total / (1024 * 1024), 2),
            "ram_available_mb": round(memory.available / (1024 * 1024), 2),
            "swap_total_mb": round(swap.total / (1024 * 1024), 2),
            "swap_used_mb": measure_swap_usage(),
        },
        "profiles": profiles,
        "measurements": {
            "cold_start_seconds": cold_start,
            "peak_process_ram_mb": measure_peak_ram(),
            "per_service_import_ram_mb": measure_per_service_memory(),
            "cpu_utilization_percent": measure_cpu_utilization(1.0),
            "guard_latency_seconds": guard_latency,
            "db_query_latency_seconds": db_latency,
            "db_size_mb": measure_database_size(),
            "swap_usage_mb": measure_swap_usage(),
            "host_headroom": measure_host_headroom(),
            "optional_model": model,
            "concurrent_load": measure_concurrent_load(),
        },
        "checks": checks,
        "optional_model": "degraded" if model["degraded"] else "available",
        "overall": "passed" if all(checks.values()) else "failed",
    }


def main() -> int:
    report = collect_report()
    print(json.dumps(report, indent=2, default=str))
    return 0 if report["overall"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
