"""Server-side target allow/deny policy for Recon scopes and scans.

The policy is deliberately evaluated in the engine, not only in the browser or
the BFF. A caller that talks to the engine directly still has to pass the same
gate. Entries are exact hostnames; an entry also covers its subdomains, so
``example.com`` allows ``www.example.com`` but not ``example.com.evil.test``.

Configuration is read from comma/newline separated environment variables:

* ``ZEROTRACE_TARGET_ALLOWLIST`` - when non-empty, every target must match.
* ``ZEROTRACE_TARGET_DENYLIST`` - matching targets are always rejected.

Deny always wins over allow. An empty policy is permissive for the local demo;
production deployments should configure at least a denylist and preferably an
allowlist. The policy never resolves DNS and never scans anything itself.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import os
from typing import Iterable


class TargetPolicyError(ValueError):
    """Raised when a target is rejected by the configured policy."""


def normalize_target(value: str) -> str:
    """Normalize a domain target without performing network resolution."""

    if not isinstance(value, str) or not value.strip():
        raise TargetPolicyError("target is required")
    candidate = value.strip().lower().rstrip(".")
    if "://" in candidate or "/" in candidate or "@" in candidate:
        raise TargetPolicyError("target must be a hostname, not a URL")
    if ":" in candidate or "*" in candidate:
        raise TargetPolicyError("target must be a literal hostname")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        raise TargetPolicyError("target must be a domain name, not an IP address")
    labels = candidate.split(".")
    if len(labels) < 2 or len(candidate) > 253:
        raise TargetPolicyError("target must be a valid hostname")
    for label in labels:
        if not label or len(label) > 63:
            raise TargetPolicyError("target must be a valid hostname")
        if label.startswith("-") or label.endswith("-"):
            raise TargetPolicyError("target must be a valid hostname")
        if not label.replace("-", "").isalnum():
            raise TargetPolicyError("target must be a valid hostname")
    return candidate


def _parse_entries(values: Iterable[str] | str | None) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, str):
        raw = values.replace("\n", ",").split(",")
    else:
        raw = []
        for value in values:
            raw.extend(str(value).replace("\n", ",").split(","))
    entries: list[str] = []
    for value in raw:
        candidate = value.strip()
        if not candidate:
            continue
        entries.append(normalize_target(candidate))
    return tuple(dict.fromkeys(entries))


def _matches(target: str, entry: str) -> bool:
    return target == entry or target.endswith("." + entry)


@dataclass(frozen=True)
class TargetPolicy:
    """Immutable target policy shared by scope creation and scan queueing."""

    allowlist: tuple[str, ...] = ()
    denylist: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "allowlist", _parse_entries(self.allowlist))
        object.__setattr__(self, "denylist", _parse_entries(self.denylist))

    @classmethod
    def from_env(cls) -> "TargetPolicy":
        return cls(
            allowlist=_parse_entries(os.environ.get("ZEROTRACE_TARGET_ALLOWLIST", "")),
            denylist=_parse_entries(os.environ.get("ZEROTRACE_TARGET_DENYLIST", "")),
        )

    @property
    def allowlist_configured(self) -> bool:
        return bool(self.allowlist)

    @property
    def denylist_configured(self) -> bool:
        return bool(self.denylist)

    def check(self, value: str) -> str:
        """Return the normalized target or raise :class:`TargetPolicyError`."""

        target = normalize_target(value)
        if any(_matches(target, entry) for entry in self.denylist):
            raise TargetPolicyError("target is blocked by the denylist")
        if self.allowlist and not any(
            _matches(target, entry) for entry in self.allowlist
        ):
            raise TargetPolicyError("target is not in the allowlist")
        return target

    def summary(self) -> dict[str, object]:
        """Return a non-sensitive policy summary for status endpoints."""

        return {
            "allowlistConfigured": self.allowlist_configured,
            "denylistConfigured": self.denylist_configured,
            "allowlistEntries": len(self.allowlist),
            "denylistEntries": len(self.denylist),
        }
