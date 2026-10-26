from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
import hashlib
import re
from collections.abc import Iterable
from typing import Mapping


FORMULA_VERSION = "intel-priority-v1"
_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_CPE_PATTERN = re.compile(r"^cpe:2\.3:[aho]:[^:]+:[^:]+:[^:]+:")


class IntelError(ValueError):
    """Raised when an Intel fact or correlation violates its contract."""


@dataclass(frozen=True)
class VulnerabilityFact:
    cve_id: str
    source: str
    source_record_id: str
    source_revision: str
    summary: str
    cpe_names: tuple[str, ...]
    cvss_score: float | None
    epss_score: float | None
    kev: bool | None
    published_at: datetime | None
    modified_at: datetime | None
    retrieved_at: datetime
    schema_version: int
    payload_digest: str
    epss_score_date: date | None = None
    kev_due_date: date | None = None
    cpe_ranges: tuple[
        tuple[str, str | None, str | None, str | None, str | None], ...
    ] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "cve_id", normalize_cve(self.cve_id))
        if not self.source or not self.source_record_id or not self.source_revision:
            raise IntelError("source provenance is required")
        if not 1 <= len(self.summary) <= 16_384:
            raise IntelError("summary length is invalid")
        object.__setattr__(
            self, "cpe_names", tuple(normalize_cpe(cpe) for cpe in self.cpe_names)
        )
        normalized_ranges: list[
            tuple[str, str | None, str | None, str | None, str | None]
        ] = []
        for item in self.cpe_ranges:
            if len(item) != 5:
                raise IntelError("CPE range shape is invalid")
            criteria = normalize_cpe(item[0])
            bounds = tuple(
                None if value is None or str(value).strip() == "" else str(value)
                for value in item[1:]
            )
            normalized_ranges.append((criteria, *bounds))
        object.__setattr__(self, "cpe_ranges", tuple(normalized_ranges))
        if self.cvss_score is not None and not 0.0 <= self.cvss_score <= 10.0:
            raise IntelError("CVSS score is out of range")
        if self.epss_score is not None and not 0.0 <= self.epss_score <= 1.0:
            raise IntelError("EPSS score is out of range")
        if self.schema_version < 1 or len(self.payload_digest) != 64:
            raise IntelError("fact provenance is invalid")
        _require_aware(self.retrieved_at)


@dataclass(frozen=True)
class ServiceDescriptor:
    service_id: str
    asset_id: str
    product: str
    vendor: str
    version: str | None
    cpe: str | None
    exposed: bool

    def __post_init__(self) -> None:
        if not self.service_id or not self.asset_id or not self.product:
            raise IntelError("service identity is required")
        if self.cpe is not None:
            object.__setattr__(self, "cpe", normalize_cpe(self.cpe))


@dataclass(frozen=True)
class PriorityResult:
    formula_version: str
    score: float
    inputs: Mapping[str, float]
    missing: tuple[str, ...]
    confidence: float


@dataclass(frozen=True)
class ServiceFinding:
    service_id: str
    asset_id: str
    cve_id: str
    match_method: str
    confidence: float
    evidence: tuple[str, ...]
    freshness: str
    priority: PriorityResult


@dataclass(frozen=True)
class UncertainMatch:
    service_id: str
    asset_id: str
    cve_id: str
    reason: str
    evidence: tuple[str, ...]
    freshness: str
    source_revision: str


@dataclass(frozen=True)
class CorrelationOutcome:
    finding: ServiceFinding | None
    uncertain: UncertainMatch | None

    def __post_init__(self) -> None:
        if (self.finding is None) == (self.uncertain is None):
            raise IntelError("correlation outcome must have one result")


@dataclass(frozen=True)
class CorrelationBatch:
    findings: tuple[ServiceFinding, ...]
    uncertain_matches: tuple[UncertainMatch, ...]


def normalize_cve(value: str) -> str:
    normalized = value.strip().upper()
    if not _CVE_PATTERN.fullmatch(normalized):
        raise IntelError("CVE identifier is invalid")
    return normalized


def normalize_cpe(value: str) -> str:
    normalized = value.strip().lower()
    if not _CPE_PATTERN.match(normalized) or normalized.count(":") < 12:
        raise IntelError("CPE identifier is invalid")
    return normalized


def calculate_priority(
    *,
    cvss_score: float | None,
    epss_score: float | None,
    kev: bool | None,
    exposed: bool,
    confidence: float,
) -> PriorityResult:
    if not 0.0 <= confidence <= 1.0:
        raise IntelError("confidence is out of range")
    values: dict[str, float] = {}
    missing: list[str] = []
    if cvss_score is None:
        missing.append("cvss")
    else:
        if not 0.0 <= cvss_score <= 10.0:
            raise IntelError("CVSS score is out of range")
        values["cvss"] = cvss_score / 10.0
    if epss_score is None:
        missing.append("epss")
    else:
        if not 0.0 <= epss_score <= 1.0:
            raise IntelError("EPSS score is out of range")
        values["epss"] = epss_score
    if kev is None:
        missing.append("kev")
    else:
        values["kev"] = 1.0 if kev else 0.0
    values["exposure"] = 1.0 if exposed else 0.0
    weights = {"cvss": 0.35, "epss": 0.30, "kev": 0.25, "exposure": 0.10}
    available_weight = sum(weights[name] for name in values)
    weighted = sum(weights[name] * values[name] for name in values)
    score = 0.0 if available_weight == 0.0 else 100.0 * confidence * weighted / available_weight
    return PriorityResult(
        FORMULA_VERSION,
        round(max(0.0, min(100.0, score)), 6),
        values,
        tuple(missing),
        confidence,
    )


def freshness_state(
    retrieved_at: datetime,
    *,
    now: datetime,
    max_age: timedelta,
) -> str:
    _require_aware(retrieved_at)
    _require_aware(now)
    if max_age <= timedelta(0):
        raise IntelError("freshness window must be positive")
    age = now.astimezone(timezone.utc) - retrieved_at.astimezone(timezone.utc)
    if age < timedelta(0):
        return "unknown"
    return "fresh" if age <= max_age else "stale"


def match_service(
    service: ServiceDescriptor,
    fact: VulnerabilityFact,
    *,
    now: datetime | None = None,
    freshness_window: timedelta = timedelta(days=7),
) -> ServiceFinding | None:
    outcome = correlate_service(
        service,
        fact,
        now=now,
        freshness_window=freshness_window,
    )
    return outcome.finding


def _cpe_parts(value: str) -> list[str]:
    return value.split(":")


def _cpe_matches(service_cpe: str, fact_cpe: str) -> bool:
    """Match an exact service CPE against NVD wildcard CPE fields."""

    service_parts = _cpe_parts(service_cpe)
    fact_parts = _cpe_parts(fact_cpe)
    if len(service_parts) != 13 or len(fact_parts) != 13:
        return False
    return all(
        fact_parts[index] in {"*", "-"}
        or service_parts[index] == fact_parts[index]
        for index in range(2, 13)
    )


def _version_key(value: str) -> tuple[tuple[int, int | str], ...]:
    parts = re.findall(r"\d+|[a-z]+", value.lower())
    while parts and parts[-1] == "0":
        parts.pop()
    return tuple(
        (0, int(part)) if part.isdigit() else (1, part)
        for part in parts
    )


def _compare_versions(left: str, right: str) -> int:
    from itertools import zip_longest

    left_key = _version_key(left)
    right_key = _version_key(right)
    for a, b in zip_longest(left_key, right_key, fillvalue=(0, 0)):
        if a == b:
            continue
        return -1 if a < b else 1
    return 0


def _range_matches(
    service: ServiceDescriptor,
    item: tuple[str, str | None, str | None, str | None, str | None],
) -> bool:
    criteria, start_including, start_excluding, end_including, end_excluding = item
    parts = _cpe_parts(criteria)
    if len(parts) != 13:
        return False
    if parts[3] != service.vendor.lower() or parts[4] != service.product.lower():
        return False
    if service.version is None:
        return False
    version = service.version.lower()
    if start_including is not None and _compare_versions(version, start_including) < 0:
        return False
    if start_excluding is not None and _compare_versions(version, start_excluding) <= 0:
        return False
    if end_including is not None and _compare_versions(version, end_including) > 0:
        return False
    if end_excluding is not None and _compare_versions(version, end_excluding) >= 0:
        return False
    if not any(
        (start_including, start_excluding, end_including, end_excluding)
    ) and parts[5] not in {"*", "-"}:
        return version == parts[5]
    return True


def _range_evidence(
    item: tuple[str, str | None, str | None, str | None, str | None],
) -> str:
    criteria, start_including, start_excluding, end_including, end_excluding = item
    bounds = [
        label
        for label, value in (
            (f">={start_including}" if start_including else "", start_including),
            (f">{start_excluding}" if start_excluding else "", start_excluding),
            (f"<={end_including}" if end_including else "", end_including),
            (f"<{end_excluding}" if end_excluding else "", end_excluding),
        )
        if value is not None
    ]
    return f"{criteria} ({', '.join(bounds)})" if bounds else criteria


def _match_evidence(
    service: ServiceDescriptor,
    fact: VulnerabilityFact,
) -> (
    tuple[str, float, tuple[str, ...]]
    | str
    | tuple[str, tuple[str, ...]]
):
    if service.cpe is not None and service.cpe in fact.cpe_names:
        return "exact_cpe", 1.0, (service.cpe,)
    if service.cpe is not None:
        wildcard_candidates = tuple(
            sorted(
                cpe for cpe in fact.cpe_names if _cpe_matches(service.cpe, cpe)
            )
        )
        if len(wildcard_candidates) == 1:
            return "cpe_wildcard", 0.95, wildcard_candidates
        if len(wildcard_candidates) > 1:
            return "ambiguous_candidates", wildcard_candidates
        range_candidates = tuple(
            sorted(
                _range_evidence(item)
                for item in fact.cpe_ranges
                if _range_matches(service, item)
            )
        )
        if len(range_candidates) == 1:
            return "cpe_version_range", 0.9, range_candidates
        if len(range_candidates) > 1:
            return "ambiguous_candidates", range_candidates
    if service.version is None:
        return "missing_service_version"
    vendor = service.vendor.lower()
    product = service.product.lower()
    version = service.version.lower()
    candidates = tuple(
        sorted(
            cpe
            for cpe in fact.cpe_names
            if (
                len(_cpe_parts(cpe)) == 13
                and _cpe_parts(cpe)[3] == vendor
                and _cpe_parts(cpe)[4] == product
                and (
                    _cpe_parts(cpe)[5] in {"*", "-"}
                    or _cpe_parts(cpe)[5] == version
                )
            )
        )
    )
    if len(candidates) == 1:
        return "vendor_product_version", 0.8, candidates
    if len(candidates) > 1:
        return "ambiguous_candidates", candidates
    return "no_candidate"


def correlate_service(
    service: ServiceDescriptor,
    fact: VulnerabilityFact,
    *,
    now: datetime | None = None,
    freshness_window: timedelta = timedelta(days=7),
) -> CorrelationOutcome:
    retrieved = now or datetime.now(timezone.utc)
    freshness = freshness_state(
        fact.retrieved_at,
        now=retrieved,
        max_age=freshness_window,
    )
    matched = _match_evidence(service, fact)
    if isinstance(matched, str):
        return CorrelationOutcome(
            None,
            UncertainMatch(
                service.service_id,
                service.asset_id,
                fact.cve_id,
                matched,
                (),
                freshness,
                fact.source_revision,
            ),
        )
    if isinstance(matched, tuple) and len(matched) == 2:
        reason, candidates = matched
        return CorrelationOutcome(
            None,
            UncertainMatch(
                service.service_id,
                service.asset_id,
                fact.cve_id,
                reason,
                tuple(candidates),
                freshness,
                fact.source_revision,
            ),
        )
    method, confidence, evidence = matched
    if freshness != "fresh":
        return CorrelationOutcome(
            None,
            UncertainMatch(
                service.service_id,
                service.asset_id,
                fact.cve_id,
                "stale_fact" if freshness == "stale" else "unknown_freshness",
                evidence,
                freshness,
                fact.source_revision,
            ),
        )
    priority = calculate_priority(
        cvss_score=fact.cvss_score,
        epss_score=fact.epss_score,
        kev=fact.kev,
        exposed=service.exposed,
        confidence=confidence,
    )
    return CorrelationOutcome(
        ServiceFinding(
            service.service_id,
            service.asset_id,
            fact.cve_id,
            method,
            confidence,
            evidence,
            freshness,
            priority,
        ),
        None,
    )


def correlate_scope(
    services: Iterable[ServiceDescriptor],
    facts: Iterable[VulnerabilityFact],
    *,
    now: datetime | None = None,
    freshness_window: timedelta = timedelta(days=7),
) -> CorrelationBatch:
    """Correlate every service against every fact deterministically.

    Each service/fact pair produces exactly one result: either a confirmed
    finding or an uncertain match. Ordering is deterministic regardless of
    input order.
    """
    service_list = tuple(sorted(services, key=lambda s: s.service_id))
    fact_list = tuple(sorted(facts, key=lambda f: f.cve_id))
    findings: list[ServiceFinding] = []
    uncertain: list[UncertainMatch] = []
    for service in service_list:
        for fact in fact_list:
            outcome = correlate_service(
                service,
                fact,
                now=now,
                freshness_window=freshness_window,
            )
            if outcome.finding is not None:
                findings.append(outcome.finding)
            else:
                uncertain.append(outcome.uncertain)
    findings.sort(key=lambda item: (item.service_id, item.cve_id))
    uncertain.sort(key=lambda item: (item.service_id, item.cve_id))
    return CorrelationBatch(
        tuple(findings),
        tuple(uncertain),
    )


def payload_digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _require_aware(value: datetime) -> None:
    if value.tzinfo is None:
        raise IntelError("timestamp must include timezone")
