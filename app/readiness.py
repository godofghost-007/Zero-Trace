from dataclasses import dataclass
from typing import Sequence


FORMULA_VERSION = "readiness-v1"
_COMPONENT_NAMES = ("AEI", "VUI", "AIET")


@dataclass(frozen=True)
class AssetRisk:
    exploit_probability: float
    cvss_score: float


@dataclass(frozen=True)
class ScoreComponent:
    name: str
    value: float | None
    numerator: float
    denominator: int
    status: str


@dataclass(frozen=True)
class ReadinessResult:
    formula_version: str
    components: tuple[ScoreComponent, ...]
    values: dict[str, float | None]
    unknown_components: tuple[str, ...]
    coverage: float
    score: float | None
    band: str | None


def calculate_aei(exposed_services: int, total_services: int) -> ScoreComponent:
    return _ratio_component("AEI", exposed_services, total_services)


def calculate_vui(
    asset_risks: Sequence[AssetRisk], total_assets: int
) -> ScoreComponent:
    _validate_non_negative_integer("total_assets", total_assets)
    if len(asset_risks) > total_assets:
        raise ValueError("asset_risks cannot exceed total_assets")

    risk_total = 0.0
    for risk in asset_risks:
        if not 0.0 <= risk.exploit_probability <= 1.0:
            raise ValueError("exploit_probability must be between 0 and 1")
        if not 0.0 <= risk.cvss_score <= 10.0:
            raise ValueError("cvss_score must be between 0 and 10")
        risk_total += risk.exploit_probability * (risk.cvss_score / 10.0)

    if total_assets == 0:
        return ScoreComponent("VUI", None, 0.0, 0, "unknown")

    return ScoreComponent(
        "VUI",
        round(risk_total / total_assets * 100.0, 6),
        round(risk_total, 6),
        total_assets,
        "known",
    )


def calculate_aiet(unblocked_attacks: int, total_requests: int) -> ScoreComponent:
    return _ratio_component("AIET", unblocked_attacks, total_requests)


def calculate_readiness(
    exposed_services: int,
    total_services: int,
    asset_risks: Sequence[AssetRisk],
    total_assets: int,
    unblocked_attacks: int,
    total_requests: int,
) -> ReadinessResult:
    components = (
        calculate_aei(exposed_services, total_services),
        calculate_vui(asset_risks, total_assets),
        calculate_aiet(unblocked_attacks, total_requests),
    )
    unknown_components = tuple(
        component.name for component in components if component.value is None
    )
    values = {component.name: component.value for component in components}
    coverage = round(
        (len(components) - len(unknown_components)) / len(components) * 100.0,
        6,
    )

    if unknown_components:
        score = None
        band = None
    else:
        score = round(
            max(
                0.0,
                min(
                    100.0,
                    100.0
                    - (
                        0.40 * values["AEI"]
                        + 0.40 * values["VUI"]
                        + 0.20 * values["AIET"]
                    ),
                ),
            ),
            6,
        )
        band = _score_band(score)

    return ReadinessResult(
        formula_version=FORMULA_VERSION,
        components=components,
        values=values,
        unknown_components=unknown_components,
        coverage=coverage,
        score=score,
        band=band,
    )


def _ratio_component(name: str, numerator: int, denominator: int) -> ScoreComponent:
    _validate_non_negative_integer(f"{name} numerator", numerator)
    _validate_non_negative_integer(f"{name} denominator", denominator)
    if numerator > denominator:
        raise ValueError(f"{name} numerator cannot exceed denominator")
    if denominator == 0:
        if numerator != 0:
            raise ValueError(f"{name} numerator must be zero with zero denominator")
        return ScoreComponent(name, None, 0.0, 0, "unknown")

    return ScoreComponent(
        name,
        round(numerator / denominator * 100.0, 6),
        float(numerator),
        denominator,
        "known",
    )


def _validate_non_negative_integer(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")


def _score_band(score: float) -> str:
    if score >= 90.0:
        return "Secure"
    if score >= 70.0:
        return "Moderate"
    if score >= 50.0:
        return "Elevated"
    return "Critical"
