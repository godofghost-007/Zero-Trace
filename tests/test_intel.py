import unittest
from datetime import datetime, timedelta, timezone

from app.intel import (
    CorrelationBatch,
    CorrelationOutcome,
    IntelError,
    ServiceDescriptor,
    VulnerabilityFact,
    calculate_priority,
    correlate_service,
    correlate_scope,
    freshness_state,
    match_service,
)


class IntelModelTests(unittest.TestCase):
    def _fact(self, **changes: object) -> VulnerabilityFact:
        values = {
            "cve_id": "CVE-2024-1234",
            "source": "nvd",
            "source_record_id": "CVE-2024-1234",
            "source_revision": "2024-01-02T00:00:00Z",
            "summary": "Example vulnerability",
            "cpe_names": ("cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*",),
            "cvss_score": 8.0,
            "epss_score": 0.7,
            "kev": True,
            "published_at": datetime(2024, 1, 1, tzinfo=timezone.utc),
            "modified_at": datetime(2024, 1, 2, tzinfo=timezone.utc),
            "retrieved_at": datetime(2024, 1, 3, tzinfo=timezone.utc),
            "schema_version": 1,
            "payload_digest": "a" * 64,
        }
        values.update(changes)
        return VulnerabilityFact(**values)

    def test_cve_and_cpe_are_normalized_and_invalid_values_rejected(self) -> None:
        fact = self._fact(cve_id="cve-2024-1234", cpe_names=(
            "CPE:2.3:A:Acme:Widget:1.2.3:*:*:*:*:*:*:*",
        ))
        self.assertEqual(fact.cve_id, "CVE-2024-1234")
        self.assertEqual(fact.cpe_names[0], "cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*")
        with self.assertRaises(IntelError):
            self._fact(cve_id="CVE-2024-1234;DROP")

    def test_priority_is_bounded_explainable_and_monotonic(self) -> None:
        high = calculate_priority(
            cvss_score=10.0,
            epss_score=1.0,
            kev=True,
            exposed=True,
            confidence=1.0,
        )
        low = calculate_priority(
            cvss_score=4.0,
            epss_score=0.1,
            kev=False,
            exposed=False,
            confidence=0.5,
        )
        self.assertGreater(high.score, low.score)
        self.assertLessEqual(high.score, 100.0)
        self.assertEqual(high.formula_version, "intel-priority-v1")
        self.assertIn("cvss", high.inputs)

    def test_missing_priority_inputs_remain_visible(self) -> None:
        result = calculate_priority(
            cvss_score=None,
            epss_score=None,
            kev=None,
            exposed=True,
            confidence=0.8,
        )
        self.assertEqual(result.missing, ("cvss", "epss", "kev"))
        self.assertGreater(result.score, 0.0)

    def test_freshness_transitions(self) -> None:
        retrieved = datetime(2026, 10, 17, tzinfo=timezone.utc)
        self.assertEqual(
            freshness_state(
                retrieved,
                now=retrieved + timedelta(hours=1),
                max_age=timedelta(days=1),
            ),
            "fresh",
        )
        self.assertEqual(
            freshness_state(
                retrieved,
                now=retrieved + timedelta(days=2),
                max_age=timedelta(days=1),
            ),
            "stale",
        )

    def test_matching_requires_exact_evidence_and_rejects_ambiguity(self) -> None:
        service = ServiceDescriptor(
            service_id="service-1",
            asset_id="asset-1",
            product="widget",
            vendor="acme",
            version="1.2.3",
            cpe="cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*",
            exposed=True,
        )
        finding = match_service(
            service,
            self._fact(),
            now=datetime(2024, 1, 4, tzinfo=timezone.utc),
        )
        self.assertIsNotNone(finding)
        self.assertEqual(finding.match_method, "exact_cpe")
        self.assertEqual(finding.freshness, "fresh")

        ambiguous = self._fact(cpe_names=(), summary="same product")
        self.assertIsNone(match_service(service, ambiguous))

    def test_unique_fallback_match_is_confirmed(self) -> None:
        service = ServiceDescriptor(
            "service-1", "asset-1", "widget", "acme", "1.2.3", None, True
        )
        outcome = correlate_service(
            service, self._fact(),
            now=datetime(2024, 1, 4, tzinfo=timezone.utc),
        )

        self.assertIsInstance(outcome, CorrelationOutcome)
        self.assertIsNotNone(outcome.finding)
        self.assertIsNone(outcome.uncertain)
        self.assertEqual(outcome.finding.match_method, "vendor_product_version")

    def test_ambiguous_match_is_reviewable_uncertain_evidence(self) -> None:
        service = ServiceDescriptor(
            "service-1", "asset-1", "widget", "acme", "1.2.3", None, True
        )
        fact = self._fact(cpe_names=(
            "cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*",
            "cpe:2.3:o:acme:widget:1.2.3:*:*:*:*:*:*:*",
        ))

        outcome = correlate_service(
            service, fact, now=datetime(2024, 1, 4, tzinfo=timezone.utc)
        )

        self.assertIsNone(outcome.finding)
        self.assertEqual(outcome.uncertain.reason, "ambiguous_candidates")
        self.assertEqual(outcome.uncertain.source_revision, fact.source_revision)

    def test_missing_service_version_is_uncertain_not_confirmed(self) -> None:
        service = ServiceDescriptor(
            "service-1", "asset-1", "widget", "acme", None, None, True
        )

        outcome = correlate_service(
            service, self._fact(), now=datetime(2024, 1, 4, tzinfo=timezone.utc)
        )

        self.assertIsNone(outcome.finding)
        self.assertEqual(outcome.uncertain.reason, "missing_service_version")

    def test_stale_exact_match_is_uncertain_not_confirmed(self) -> None:
        service = ServiceDescriptor(
            "service-1",
            "asset-1",
            "widget",
            "acme",
            "1.2.3",
            "cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*",
            True,
        )

        outcome = correlate_service(
            service,
            self._fact(retrieved_at=datetime(2024, 1, 1, tzinfo=timezone.utc)),
            now=datetime(2024, 1, 10, tzinfo=timezone.utc),
        )

        self.assertIsNone(outcome.finding)
        self.assertEqual(outcome.uncertain.reason, "stale_fact")
        self.assertEqual(outcome.uncertain.freshness, "stale")

    def test_scope_correlation_is_deterministic_and_separates_results(self) -> None:
        confirmed_service = ServiceDescriptor(
            "service-1", "asset-1", "widget", "acme", "1.2.3",
            "cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*", True,
        )
        uncertain_service = ServiceDescriptor(
            "service-2", "asset-2", "widget", "acme", None, None, True,
        )

        result = correlate_scope(
            (uncertain_service, confirmed_service),
            (self._fact(),),
            now=datetime(2024, 1, 4, tzinfo=timezone.utc),
        )

        self.assertIsInstance(result, CorrelationBatch)
        self.assertEqual([item.service_id for item in result.findings], ["service-1"])
        self.assertEqual(
            [item.service_id for item in result.uncertain_matches], ["service-2"]
        )
        self.assertEqual(
            result,
            correlate_scope(
                (confirmed_service, uncertain_service),
                (self._fact(),),
                now=datetime(2024, 1, 4, tzinfo=timezone.utc),
            ),
        )
