from dataclasses import dataclass
import os

from .errors import ConfigurationError


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
