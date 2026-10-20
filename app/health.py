from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class HealthReport:
    status: str
    checks: Mapping[str, str]

    @classmethod
    def liveness(cls) -> "HealthReport":
        return cls(status="healthy", checks={})


def dependency_status(dependencies: Mapping[str, bool]) -> HealthReport:
    checks = {
        name: "available" if available else "unavailable"
        for name, available in dependencies.items()
    }
    status = "healthy" if all(dependencies.values()) else "degraded"
    return HealthReport(status=status, checks=checks)
