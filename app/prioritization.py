"""Phase 9 — Vulnerability Prioritization.

Extends the deterministic ``intel-priority-v1`` formula with business
criticality, enhanced exposure features, model/pipeline versioning, and a
48-hour remediation queue SLA. XGBoost remains an optional integration point
that may replace or augment this deterministic baseline only when it
demonstrably improves ranking quality.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Mapping


class BusinessCriticality(Enum):
    """Business criticality of an asset, used as a prioritization input."""

    LOW = 0.0
    MEDIUM = 0.25
    HIGH = 0.50
    CRITICAL = 1.0


@dataclass(frozen=True)
class AssetCriticality:
    """Registry mapping asset IDs to business criticality levels.

    Unknown assets default to MEDIUM criticality.
    """

    _mapping: dict[str, BusinessCriticality]

    def __init__(self) -> None:
        object.__setattr__(self, "_mapping", {})

    def set_criticality(
        self, asset_id: str, criticality: BusinessCriticality
    ) -> None:
        if not asset_id:
            raise ValueError("asset ID is required")
        self._mapping[asset_id] = criticality

    def criticality_for(self, asset_id: str) -> BusinessCriticality:
        if not asset_id:
            raise ValueError("asset ID is required")
        return self._mapping.get(asset_id, BusinessCriticality.MEDIUM)


@dataclass(frozen=True)
class PrioritizationInput:
    """Single weighted input to the prioritization formula."""

    name: str
    weight: float
    value: float
    missing: bool


@dataclass(frozen=True)
class PriorityResultV2:
    """Explainable prioritization result with versioned inputs."""

    formula_version: str
    score: float
    inputs: tuple[PrioritizationInput, ...]
    missing: tuple[str, ...]
    confidence: float
    model_version: str | None = None
    feature_pipeline_version: str | None = None

    def input_value(self, name: str) -> float | None:
        for inp in self.inputs:
            if inp.name == name:
                return None if inp.missing else inp.value
        return None


@dataclass(frozen=True)
class ModelVersion:
    """Versioned model artifact with checksum and feature pipeline reference."""

    name: str
    version: str
    artifact_checksum: str
    feature_pipeline_version: str

    def __post_init__(self) -> None:
        if len(self.artifact_checksum) != 64:
            raise ValueError("artifact checksum must be a 64-character hex digest")
        if not self.name or not self.version:
            raise ValueError("model name and version are required")
        if not self.feature_pipeline_version:
            raise ValueError("feature pipeline version is required")


@dataclass(frozen=True)
class QueueItem:
    """A remediation queue entry with a 48-hour SLA."""

    finding_id: str
    priority_score: float
    discovered_at: datetime
    sla_hours: int = 48

    @property
    def sla_deadline(self) -> datetime:
        return self.discovered_at + timedelta(hours=self.sla_hours)

    @property
    def sla_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.sla_deadline


class RemediationQueue:
    """Priority-ordered remediation queue with 48-hour SLA tracking."""

    def __init__(self) -> None:
        self._items: dict[str, QueueItem] = {}

    def add_item(
        self,
        finding_id: str,
        priority_score: float,
        discovered_at: datetime,
    ) -> None:
        if not finding_id:
            raise ValueError("finding ID is required")
        if not 0.0 <= priority_score <= 100.0:
            raise ValueError("priority score must be between 0 and 100")
        self._items[finding_id] = QueueItem(
            finding_id=finding_id,
            priority_score=priority_score,
            discovered_at=discovered_at,
        )

    def get_item(self, finding_id: str) -> QueueItem | None:
        return self._items.get(finding_id)

    def next_items(self, limit: int = 10) -> list[QueueItem]:
        if limit < 1:
            raise ValueError("limit must be positive")
        return sorted(
            self._items.values(),
            key=lambda item: item.priority_score,
            reverse=True,
        )[:limit]


FORMULA_VERSION_V2 = "intel-priority-v2"

_WEIGHTS: dict[str, float] = {
    "cvss": 0.30,
    "epss": 0.25,
    "kev": 0.20,
    "exposure": 0.15,
    "business_criticality": 0.10,
}

_CRITICALITY_VALUE: dict[BusinessCriticality, float] = {
    BusinessCriticality.LOW: 0.0,
    BusinessCriticality.MEDIUM: 0.25,
    BusinessCriticality.HIGH: 0.50,
    BusinessCriticality.CRITICAL: 1.0,
}


def _validate_range(value: float, name: str) -> None:
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be between 0 and 1")


class PrioritizationV2:
    """Deterministic vulnerability prioritization scorer (intel-priority-v2)."""

    def __init__(
        self,
        criticality_registry: AssetCriticality,
        model_version: ModelVersion | None = None,
    ) -> None:
        self._criticality_registry = criticality_registry
        self._model_version = model_version

    def score(
        self,
        *,
        service: object,
        fact: object,
        now: datetime | None = None,
        freshness_window: timedelta = timedelta(days=7),
    ) -> PriorityResultV2 | None:
        from .intel import IntelError

        try:
            from .intel import freshness_state

            freshness = freshness_state(
                fact.retrieved_at,
                now=now or datetime.now(timezone.utc),
                max_age=freshness_window,
            )
        except IntelError:
            freshness = "unknown"

        if freshness != "fresh":
            return None

        return calculate_priority_v2(
            cvss_score=fact.cvss_score,
            epss_score=fact.epss_score,
            kev=fact.kev,
            exposed=service.exposed,
            business_criticality=self._criticality_registry.criticality_for(
                service.asset_id
            ),
            confidence=1.0,
            model_version=self._model_version,
        )


def calculate_priority_v2(
    *,
    cvss_score: float | None,
    epss_score: float | None,
    kev: bool | None,
    exposed: bool,
    business_criticality: BusinessCriticality,
    confidence: float,
    model_version: ModelVersion | None = None,
) -> PriorityResultV2:
    """Calculate vulnerability priority using intel-priority-v2.

    Formula: 100 * confidence * sum(weight * value) / sum(available weights)
    Missing components are omitted and their weights are renormalized.
    """
    if not 0.0 <= confidence <= 1.0:
        raise ValueError("confidence is out of range")

    inputs: list[PrioritizationInput] = []
    missing: list[str] = []

    if cvss_score is None:
        missing.append("cvss")
    else:
        _validate_range(cvss_score / 10.0, "cvss")
        inputs.append(
            PrioritizationInput("cvss", _WEIGHTS["cvss"], cvss_score / 10.0, False)
        )

    if epss_score is None:
        missing.append("epss")
    else:
        _validate_range(epss_score, "epss")
        inputs.append(
            PrioritizationInput("epss", _WEIGHTS["epss"], epss_score, False)
        )

    if kev is None:
        missing.append("kev")
    else:
        inputs.append(
            PrioritizationInput("kev", _WEIGHTS["kev"], 1.0 if kev else 0.0, False)
        )

    inputs.append(
        PrioritizationInput(
            "exposure", _WEIGHTS["exposure"], 1.0 if exposed else 0.0, False
        )
    )

    crit_value = _CRITICALITY_VALUE[business_criticality]
    inputs.append(
        PrioritizationInput(
            "business_criticality",
            _WEIGHTS["business_criticality"],
            crit_value,
            False,
        )
    )

    available_weight = sum(inp.weight for inp in inputs)
    weighted = sum(inp.weight * inp.value for inp in inputs)
    score = 0.0 if available_weight == 0.0 else 100.0 * confidence * weighted / available_weight

    return PriorityResultV2(
        formula_version=FORMULA_VERSION_V2,
        score=round(max(0.0, min(100.0, score)), 6),
        inputs=tuple(inputs),
        missing=tuple(missing),
        confidence=confidence,
        model_version=model_version.version if model_version else None,
        feature_pipeline_version=(
            model_version.feature_pipeline_version if model_version else None
        ),
    )


def explain_priority(result: PriorityResultV2) -> dict[str, str]:
    """Return a human-readable explanation of each prioritization input."""
    explanations: dict[str, str] = {}
    for inp in result.inputs:
        if inp.missing:
            explanations[inp.name] = f"missing (weight {inp.weight})"
        else:
            explanations[inp.name] = (
                f"value={inp.value:.2f}, weight={inp.weight}, "
                f"contribution={inp.weight * inp.value:.2f}"
            )
    explanations["confidence"] = f"{result.confidence:.2f}"
    explanations["formula"] = result.formula_version
    return explanations