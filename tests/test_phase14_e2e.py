"""Phase 14 end-to-end integration gate tests."""

import unittest

from scripts.phase14_e2e import run_e2e


class Phase14EndToEndTests(unittest.TestCase):
    def test_synthetic_pipeline_and_failure_modes(self) -> None:
        result = run_e2e()

        pipeline = result["pipeline"]
        self.assertEqual(pipeline["recon"]["state"], "completed")
        self.assertEqual(pipeline["intel"]["match_method"], "exact_cpe")
        self.assertEqual(pipeline["guard"]["normal_status"], 200)
        self.assertEqual(pipeline["guard"]["blocked_status"], 400)
        self.assertIsNotNone(pipeline["readiness"]["score"])
        self.assertEqual(pipeline["remediation"]["validation_errors"], [])
        self.assertEqual(pipeline["remediation"]["status"], "approved")

        self.assertEqual(result["duplicate_scan"]["adapter_calls"], 1)
        self.assertEqual(result["retry"]["state"], "completed")
        self.assertEqual(result["retry"]["adapter_calls"], 2)
        self.assertEqual(result["restart"]["scopes_after_restart"], 1)
        self.assertIsNone(result["optional_input_degraded"]["score"])
        self.assertIn("VUI", result["optional_input_degraded"]["unknown_components"])
        self.assertEqual(result["guard_outage"]["status"], 502)
        self.assertEqual(result["partial_recon"]["state"], "partial")
        self.assertTrue(result["partial_recon"]["warnings"])
        self.assertTrue(
            any(
                "digest" in error.lower()
                for error in result["tampered_proposal"]["validation_errors"]
            )
        )


if __name__ == "__main__":
    unittest.main()
