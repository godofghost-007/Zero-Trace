import unittest

from app.integration import IntegratedReadinessState


class IntegrationTests(unittest.TestCase):
    def test_recon_intel_guard_state_recomputes_readiness(self) -> None:
        state = IntegratedReadinessState()
        state.record_recon(
            assets=("asset-1", "asset-2"),
            total_services=2,
            exposed_services=1,
        )
        state.record_guard_request(blocked=True)
        state.record_guard_request(blocked=False)

        result = state.calculate()

        self.assertEqual(result.formula_version, "readiness-v1")
        self.assertEqual(result.values["AEI"], 50.0)
        self.assertEqual(result.values["AIET"], 50.0)
