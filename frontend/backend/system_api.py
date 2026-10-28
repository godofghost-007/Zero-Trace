"""Read-only host information for the local Admin > Architecture view."""

from __future__ import annotations

import platform
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil
from flask import Blueprint, jsonify

system_api = Blueprint("system_api", __name__)


def _battery() -> dict[str, object] | None:
    try:
        battery = psutil.sensors_battery()
    except (AttributeError, NotImplementedError):
        return None
    if battery is None:
        return None
    return {
        "percent": round(float(battery.percent), 1),
        "plugged": bool(battery.power_plugged),
    }


def _gigabytes(value: int | float) -> float:
    return round(float(value) / (1024**3), 1)


@system_api.get("/system/info")
def system_info():
    battery = _battery()
    disk_root = Path.home().anchor or "/"
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage(disk_root)
    frequency = psutil.cpu_freq()
    boot = psutil.boot_time()
    processor = platform.processor() or platform.uname().processor or "Unknown"

    return jsonify(
        {
            "deviceType": "Laptop" if battery else "Desktop / workstation",
            "hostname": socket.gethostname(),
            "platform": platform.system(),
            "os": platform.platform(),
            "release": platform.release(),
            "machine": platform.machine(),
            "processor": processor,
            "pythonVersion": platform.python_version(),
            "cpu": {
                "logical": psutil.cpu_count(logical=True) or 0,
                "physical": psutil.cpu_count(logical=False) or 0,
                "frequencyMhz": round(frequency.max, 0) if frequency else None,
            },
            "memory": {
                "totalGb": _gigabytes(memory.total),
                "availableGb": _gigabytes(memory.available),
            },
            "disk": {
                "path": disk_root,
                "totalGb": _gigabytes(disk.total),
                "freeGb": _gigabytes(disk.free),
            },
            "battery": battery,
            "bootTime": datetime.fromtimestamp(boot, tz=timezone.utc).isoformat(),
            "uptimeSeconds": int(max(0, time.time() - boot)),
        }
    )
