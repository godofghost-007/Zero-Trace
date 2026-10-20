from dataclasses import dataclass, field
from typing import Iterable

from app.intel import ServiceFinding
from app.prioritization import PrioritizationInput
from app.readiness import AssetRisk, ReadinessResult, calculate_readiness


@dataclass
class IntegratedReadinessState:
    total_services: int = 0
    exposed_services: int = 0
    total_assets: int = 0
    findings: list[ServiceFinding] = field(default_factory=list)
    intel_complete: bool = True
    total_requests: int = 0
    unblocked_attacks: int = 0

    def record_recon(
        self, *, assets: Iterable[str], total_services: int, exposed_services: int
    ) -> None:
        self.total_assets = len(set(assets))
        self.exposed_services = exposed_services
        self.total_services = total_services

    def record_findings(self, findings: Iterable[ServiceFinding]) -> None:
        self.findings = list(findings)
        self.intel_complete = all(
            not finding.priority.missing for finding in self.findings
        )

    def record_guard_request(self, *, blocked: bool) -> None:
        self.total_requests += 1
        if not blocked:
            self.unblocked_attacks += 1

    def _input_value(self, inputs: tuple[PrioritizationInput, ...], name: str) -> float:
        for inp in inputs:
            if inp.name == name and not inp.missing:
                return inp.value
        return 0.0

    def calculate(self) -> ReadinessResult:
        risks_by_asset: dict[str, AssetRisk] = {}
        for finding in self.findings:
            inputs = finding.priority.inputs
            risk = AssetRisk(
                self._input_value(inputs, "epss"),
                self._input_value(inputs, "cvss") * 10.0,
            )
            existing = risks_by_asset.get(finding.asset_id)
            if existing is None or (
                risk.exploit_probability * risk.cvss_score
                > existing.exploit_probability * existing.cvss_score
            ):
                risks_by_asset[finding.asset_id] = risk
        return calculate_readiness(
            self.exposed_services,
            self.total_services,
            tuple(risks_by_asset.values()),
            self.total_assets if self.intel_complete else 0,
            self.unblocked_attacks,
            self.total_requests,
        )
