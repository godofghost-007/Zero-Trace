"""Runtime scanner version gates for the bounded Recon adapters.

The container image pins Subfinder and installs Nmap from the pinned base
image. That is a build-time guarantee only. This module checks the binaries that
are actually present at runtime and turns a missing or unexpected version into
a degraded readiness result instead of a silent success.
"""

from __future__ import annotations

from dataclasses import dataclass
import re


class ScannerVersionError(ValueError):
    """Raised when a scanner version requirement is malformed."""


_VERSION_RE = re.compile(r"(?<!\d)(\d+)\.(\d+)(?:\.(\d+))?(?!\d)")
_SUPPORTED_STATUSES = {
    "ok",
    "missing",
    "below_minimum",
    "above_maximum",
    "unexpected_version",
    "unparseable",
}


def parse_version(value: str | None) -> tuple[int, int, int] | None:
    """Extract the first semantic version from scanner output.

    Nmap prints ``Nmap version 7.94 ( https://nmap.org )`` and Subfinder prints
    either ``subfinder version v2.6.7`` or a ``Current Version`` line. Both are
    covered by taking the first three-part version number.
    """

    if not value:
        return None
    match = _VERSION_RE.search(value)
    if match is None:
        return None
    major, minor, patch = match.groups()
    return (int(major), int(minor), int(patch or 0))


def _format(version: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version)


@dataclass(frozen=True)
class ScannerRequirement:
    """A minimum and optional exact version for one scanner binary."""

    name: str
    minimum: str
    expected: str | None = None
    maximum: str | None = None

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ScannerVersionError("scanner name is required")
        minimum = parse_version(self.minimum)
        if minimum is None:
            raise ScannerVersionError(f"{self.name} minimum version is invalid")
        if self.expected is not None and parse_version(self.expected) is None:
            raise ScannerVersionError(f"{self.name} expected version is invalid")
        if self.maximum is not None and parse_version(self.maximum) is None:
            raise ScannerVersionError(f"{self.name} maximum version is invalid")
        if self.maximum is not None and minimum > parse_version(self.maximum):  # type: ignore[operator]
            raise ScannerVersionError(
                f"{self.name} minimum version is above its maximum"
            )

    @property
    def minimum_tuple(self) -> tuple[int, int, int]:
        return parse_version(self.minimum)  # type: ignore[return-value]

    @property
    def expected_tuple(self) -> tuple[int, int, int] | None:
        return parse_version(self.expected) if self.expected else None

    @property
    def maximum_tuple(self) -> tuple[int, int, int] | None:
        return parse_version(self.maximum) if self.maximum else None

    def evaluate(
        self, *, available: bool, version_output: str | None
    ) -> dict[str, object]:
        detected = parse_version(version_output)
        if not available:
            status = "missing"
        elif detected is None:
            status = "unparseable"
        elif self.expected_tuple is not None and detected != self.expected_tuple:
            status = "unexpected_version"
        elif detected < self.minimum_tuple:
            status = "below_minimum"
        elif self.maximum_tuple is not None and detected > self.maximum_tuple:
            status = "above_maximum"
        else:
            status = "ok"
        return {
            "name": self.name,
            "available": available,
            "version": version_output,
            "detectedVersion": _format(detected) if detected else None,
            "requiredMinimum": _format(self.minimum_tuple),
            "requiredExact": (
                _format(self.expected_tuple) if self.expected_tuple else None
            ),
            "requiredMaximum": (
                _format(self.maximum_tuple) if self.maximum_tuple else None
            ),
            "status": status,
            "compatible": status == "ok",
        }


DEFAULT_REQUIREMENTS: dict[str, ScannerRequirement] = {
    "nmap": ScannerRequirement(name="nmap", minimum="7.80"),
    "subfinder": ScannerRequirement(name="subfinder", minimum="2.6.0"),
}


def default_requirements(
    *,
    nmap_minimum: str = "7.80",
    nmap_expected: str | None = None,
    subfinder_minimum: str = "2.6.0",
    subfinder_expected: str | None = None,
) -> dict[str, ScannerRequirement]:
    return {
        "nmap": ScannerRequirement(
            name="nmap", minimum=nmap_minimum, expected=nmap_expected
        ),
        "subfinder": ScannerRequirement(
            name="subfinder",
            minimum=subfinder_minimum,
            expected=subfinder_expected,
        ),
    }
