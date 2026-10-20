import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock

from app.intel import ServiceFinding, UncertainMatch, VulnerabilityFact, calculate_priority
from app.intel_pg import PostgresIntelRepository


class IntelPersistenceTests(unittest.TestCase):
    def test_fact_and_finding_writes_are_parameterized_and_committed(self) -> None:
        connection = MagicMock()
        connection.__enter__.return_value = connection
        repository = PostgresIntelRepository(lambda: connection)
        fact = VulnerabilityFact(
            "CVE-2024-1234", "nvd", "CVE-2024-1234", "rev-1", "Example",
            (), 7.5, None, None, None, None,
            datetime(2024, 1, 1, tzinfo=timezone.utc), 1, "a" * 64,
        )

        repository.save_fact(fact)

        connection.commit.assert_called_once()
        statements = [
            call.args[0]
            for call in connection.cursor.return_value.__enter__.return_value.execute.call_args_list
        ]
        self.assertTrue(any("INSERT INTO intel_vulnerability_facts" in item for item in statements))
        self.assertTrue(all("%s" in item or "UPDATE" in item for item in statements))

    def test_uncertain_matches_preserve_reason_evidence_and_revision(self) -> None:
        connection = MagicMock()
        connection.__enter__.return_value = connection
        repository = PostgresIntelRepository(lambda: connection)
        repository.save_uncertain_matches(
            "scope-1",
            (
                UncertainMatch(
                    "service-1",
                    "asset-1",
                    "CVE-2024-1234",
                    "ambiguous_candidates",
                    ("cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*",),
                    "fresh",
                    "rev-1",
                ),
            ),
        )

        connection.commit.assert_called_once()
        statements = [
            call.args[0]
            for call in connection.cursor.return_value.__enter__.return_value.execute.call_args_list
        ]
        self.assertTrue(any("intel_uncertain_matches" in item for item in statements))
        self.assertTrue(all("%s" in item or "UPDATE" in item for item in statements))

    def test_correlation_persistence_commits_findings_and_uncertainty_together(self) -> None:
        connection = MagicMock()
        connection.__enter__.return_value = connection
        repository = PostgresIntelRepository(lambda: connection)
        finding = ServiceFinding(
            "service-1", "asset-1", "CVE-2024-1234", "exact_cpe", 1.0,
            ("cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*",), "fresh",
            calculate_priority(
                cvss_score=8.0, epss_score=0.7, kev=True,
                exposed=True, confidence=1.0,
            ),
        )
        uncertain = UncertainMatch(
            "service-2", "asset-2", "CVE-2024-1234", "missing_service_version",
            (), "fresh", "rev-1",
        )

        repository.save_correlation("scope-1", (finding,), (uncertain,))

        self.assertEqual(connection.commit.call_count, 1)
        statements = [
            call.args[0]
            for call in connection.cursor.return_value.__enter__.return_value.execute.call_args_list
        ]
        self.assertTrue(any("intel_findings" in item for item in statements))
        self.assertTrue(any("intel_uncertain_matches" in item for item in statements))
