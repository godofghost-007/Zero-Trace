"""Environment or secret-file lookup for the BFF container."""

from __future__ import annotations

import os
from pathlib import Path


def env_or_file(name: str, default: str = "") -> str:
    """Read ``NAME`` or ``NAME_FILE`` and reject ambiguous configuration."""

    raw = os.environ.get(name)
    file_name = f"{name}_FILE"
    file_path = os.environ.get(file_name, "").strip()
    if raw is not None and raw.strip():
        if file_path:
            raise ValueError(f"{name} and {file_name} cannot both be set")
        return raw.strip()
    if file_path:
        try:
            return Path(file_path).expanduser().read_text(encoding="utf-8").strip()
        except OSError as error:
            raise ValueError(f"{file_name} could not be read") from error
    return default
