from dataclasses import dataclass
import os
from pathlib import Path

from .errors import ConfigurationError


def env_or_file(name: str, default: str = "") -> str:
    """Read a value from ``NAME`` or a ``NAME_FILE`` secret file.

    Environment values take precedence only when non-empty. Setting both a
    non-empty value and a file is rejected so a deployment cannot silently use
    a stale environment value after moving a secret to a file.
    """

    raw = os.environ.get(name)
    file_name = f"{name}_FILE"
    file_path = os.environ.get(file_name, "").strip()
    if raw is not None and raw.strip():
        if file_path:
            raise ConfigurationError(
                f"{name} and {file_name} cannot both be set"
            )
        return raw.strip()
    if file_path:
        try:
            return Path(file_path).expanduser().read_text(encoding="utf-8").strip()
        except OSError as error:
            raise ConfigurationError(f"{file_name} could not be read") from error
    return default


@dataclass(frozen=True, repr=False)
class Settings:
    environment: str
    database_url: str
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> "Settings":
        environment = os.environ.get("ZEROTRACE_ENV", "").strip()
        database_url = os.environ.get("DATABASE_URL", "").strip()
        if not environment:
            raise ConfigurationError("ZEROTRACE_ENV is required")
        if not database_url:
            raise ConfigurationError("DATABASE_URL is required")
        return cls(
            environment=environment,
            database_url=database_url,
            log_level=os.environ.get("ZEROTRACE_LOG_LEVEL", "INFO").upper(),
        )

    def __repr__(self) -> str:
        return (
            f"Settings(environment={self.environment!r}, "
            f"database_url=<redacted>, log_level={self.log_level!r})"
        )
