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

    def __post_init__(self) -> None:
        object.__setattr__(self, "cve_id", normalize_cve(self.cve_id))
        if not self.source or not self.source_record_id or not self.source_revision:
            raise IntelError("source provenance is required")
        if not 1 <= len(self.summary) <= 16_384:
            raise IntelError("summary length is invalid")
        object.__setattr__(
            self, "cpe_names", tuple(normalize_cpe(cpe) for cpe in self.cpe_names)
        )
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
    if service.cpe is not None and service.cpe in fact.cpe_names:
        method = "exact_cpe"
        confidence = 1.0
        evidence = (service.cpe,)
    else:
        product = service.product.lower()
        vendor = service.vendor.lower()
        if service.version is None:
            return CorrelationOutcome(
                None,
                UncertainMatch(
                    service.service_id,
                    service.asset_id,
                    fact.cve_id,
                    "missing_service_version",
                    (),
                    freshness,
                    fact.source_revision,
                ),
            )
        candidates = [
            cpe
            for cpe in fact.cpe_names
            if f":{vendor}:{product}:" in cpe
            and f":{service.version.lower()}:" in cpe
        ]
        candidates = tuple(sorted(candidates))
        if len(candidates) != 1:
            reason = "ambiguous_candidates" if len(candidates) > 1 else "no_candidate"
            return CorrelationOutcome(
                None,
                UncertainMatch(
                    service.service_id,
                    service.asset_id,
                    fact.cve_id,
                    reason,
                    candidates,
                    freshness,
                    fact.source_revision,
                ),
            )
        method = "vendor_product_version"
        confidence = 0.8
        evidence = (candidates[0],)
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
