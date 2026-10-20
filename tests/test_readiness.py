import unittest

from app.readiness import (
    FORMULA_VERSION,
    AssetRisk,
    calculate_readiness,
    calculate_vui,
)


class ReadinessScoreTests(unittest.TestCase):
    def test_combined_scenario_uses_governing_equation(self) -> None:
        result = calculate_readiness(
            exposed_services=20,
            total_services=100,
            asset_risks=[
                AssetRisk(exploit_probability=0.7, cvss_score=5.0),
                AssetRisk(exploit_probability=0.7, cvss_score=5.0),
                AssetRisk(exploit_probability=0.7, cvss_score=5.0),
                AssetRisk(exploit_probability=0.7, cvss_score=5.0),
                AssetRisk(exploit_probability=0.7, cvss_score=5.0),
                AssetRisk(exploit_probability=0.7, cvss_score=5.0),
                AssetRisk(exploit_probability=0.7, cvss_score=5.0),
                AssetRisk(exploit_probability=0.7, cvss_score=5.0),
                AssetRisk(exploit_probability=0.7, cvss_score=5.0),
                AssetRisk(exploit_probability=0.7, cvss_score=5.0),
            ],
            total_assets=10,
            unblocked_attacks=25,
            total_requests=100,
        )

        self.assertEqual(result.formula_version, FORMULA_VERSION)
        self.assertEqual(result.values, {"AEI": 20.0, "VUI": 35.0, "AIET": 25.0})
        self.assertEqual(result.score, 73.0)
        self.assertEqual(result.band, "Moderate")

    def test_zero_denominator_returns_unknown_without_precise_score(self) -> None:
        result = calculate_readiness(
            exposed_services=0,
            total_services=0,
            asset_risks=[],
            total_assets=0,
            unblocked_attacks=0,
            total_requests=0,
        )

        self.assertIsNone(result.score)
        self.assertIsNone(result.band)
        self.assertEqual(result.unknown_components, ("AEI", "VUI", "AIET"))
        self.assertEqual(result.coverage, 0.0)

    def test_more_adverse_exposure_lowers_score(self) -> None:
        safer = calculate_readiness(0, 100, [], 100, 0, 100)
        riskier = calculate_readiness(50, 100, [], 100, 25, 100)

        self.assertGreater(safer.score, riskier.score)
        self.assertGreaterEqual(riskier.score, 0.0)
        self.assertLessEqual(riskier.score, 100.0)

    def test_recovery_improves_score(self) -> None:
        before = calculate_readiness(40, 100, [], 100, 20, 100)
        after = calculate_readiness(10, 100, [], 100, 5, 100)

        self.assertGreater(after.score, before.score)

    def test_calculation_is_reproducible(self) -> None:
        inputs = (20, 100, [AssetRisk(0.5, 8.0)], 10, 25, 100)

        self.assertEqual(calculate_readiness(*inputs), calculate_readiness(*inputs))

    def test_vui_normalizes_cvss_and_stays_bounded(self) -> None:
        result = calculate_vui(
            [AssetRisk(exploit_probability=1.0, cvss_score=10.0)],
            total_assets=1,
        )

        self.assertEqual(result.value, 100.0)
        self.assertGreaterEqual(result.value, 0.0)
        self.assertLessEqual(result.value, 100.0)

    def test_invalid_component_inputs_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            calculate_readiness(101, 100, [], 100, 0, 100)

        with self.assertRaises(ValueError):
            calculate_readiness(
                0,
                100,
                [AssetRisk(exploit_probability=1.1, cvss_score=5.0)],
                1,
                0,
                100,
            )
