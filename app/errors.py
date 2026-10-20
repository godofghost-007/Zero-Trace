class ConfigurationError(ValueError):
    """Raised when required application configuration is missing or invalid."""


class DependencyUnavailableError(RuntimeError):
    """Raised when a required runtime dependency cannot be reached."""
