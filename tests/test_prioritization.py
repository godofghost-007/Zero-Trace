import unittest
from datetime import datetime, timedelta, timezone

from app.prioritization import (
    BusinessCriticality,
    AssetCriticality,
    PrioritizationV2,
    ModelVersion,
    RemediationQueue,
    calculate_priority_v2,
    explain_priority,
)


class BusinessCriticalityTests(unittest.TestCase):
    def test_criticality_levels_are_ordered(self) -> None:
        self.assertLess(
            BusinessCriticality.LOW.value, BusinessCriticality.MEDIUM.value
        )
        self.assertLess(
            BusinessCriticality.MEDIUM.value, BusinessCriticality.HIGH.value
        )
        self.assertLess(
            BusinessCriticality.HIGH.value, BusinessCriticality.CRITICAL.value
        )

    def test_asset_criticality_defaults_to_medium(self) -> None:
        registry = AssetCriticality()
        self.assertEqual(
            registry.criticality_for("asset-1"), BusinessCriticality.MEDIUM
        )

    def test_asset_criticality_can_be_overridden(self) -> None:
        registry = AssetCriticality()
        registry.set_criticality("asset-1", BusinessCriticality.CRITICAL)
        self.assertEqual(
            registry.criticality_for("asset-1"), BusinessCriticality.CRITICAL
        )

    def test_unknown_asset_returns_medium_by_default(self) -> None:
        registry = AssetCriticality()
        self.assertEqual(
            registry.criticality_for("nonexistent"), BusinessCriticality.MEDIUM
        )


class PrioritizationV2Tests(unittest.TestCase):
    def _fact(self, **changes: object) -> object:
        from app.intel import VulnerabilityFact

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

    def _service(self, **changes: object) -> object:
        from app.intel import ServiceDescriptor

        values = {
            "service_id": "service-1",
            "asset_id": "asset-1",
            "product": "widget",
            "vendor": "acme",
            "version": "1.2.3",
            "cpe": "cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*",
            "exposed": True,
        }
        values.update(changes)
        return ServiceDescriptor(**values)

    def test_v2_includes_business_criticality(self) -> None:
        from app.prioritization import PrioritizationV2

        crit_registry = AssetCriticality()
        crit_registry.set_criticality("asset-1", BusinessCriticality.CRITICAL)

        scorer = PrioritizationV2(criticality_registry=crit_registry)
        result = scorer.score(
            service=self._service(),
            fact=self._fact(),
            now=datetime(2024, 1, 4, tzinfo=timezone.utc),
        )

        self.assertIsNotNone(result)
        input_names = {inp.name for inp in result.inputs}
        self.assertIn("business_criticality", input_names)
        crit_input = next(
            inp for inp in result.inputs if inp.name == "business_criticality"
        )
        self.assertGreater(crit_input.value, 0.0)

    def test_v2_is_monotonic_with_criticality(self) -> None:
        from app.prioritization import PrioritizationV2

        low_crit = AssetCriticality()
        low_crit.set_criticality("asset-1", BusinessCriticality.LOW)

        high_crit = AssetCriticality()
        high_crit.set_criticality("asset-1", BusinessCriticality.CRITICAL)

        service = self._service()
        fact = self._fact()
        now = datetime(2024, 1, 4, tzinfo=timezone.utc)

        low_result = PrioritizationV2(
            criticality_registry=low_crit
        ).score(service=service, fact=fact, now=now)
        high_result = PrioritizationV2(
            criticality_registry=high_crit
        ).score(service=service, fact=fact, now=now)

        self.assertIsNotNone(low_result)
        self.assertIsNotNone(high_result)
        self.assertGreater(high_result.score, low_result.score)

    def test_v2_preserves_missingness_explicitly(self) -> None:
        from app.prioritization import PrioritizationV2

        scorer = PrioritizationV2(criticality_registry=AssetCriticality())
        result = scorer.score(
            service=self._service(),
            fact=self._fact(cvss_score=None, epss_score=None, kev=None),
            now=datetime(2024, 1, 4, tzinfo=timezone.utc),
        )

        self.assertIsNotNone(result)
        self.assertIn("cvss", result.missing)
        self.assertIn("epss", result.missing)
        self.assertIn("kev", result.missing)


class ModelVersionTests(unittest.TestCase):
    def test_model_version_has_checksum(self) -> None:
        version = ModelVersion(
            name="intel-priority-v2",
            version="1.0.0",
            artifact_checksum="a" * 64,
            feature_pipeline_version="features-v1",
        )
        self.assertEqual(version.name, "intel-priority-v2")
        self.assertEqual(len(version.artifact_checksum), 64)

    def test_model_version_rejects_invalid_checksum(self) -> None:
        with self.assertRaises(ValueError):
            ModelVersion(
                name="intel-priority-v2",
                version="1.0.0",
                artifact_checksum="short",
                feature_pipeline_version="features-v1",
            )


class RemediationQueueTests(unittest.TestCase):
    def test_queue_items_have_48_hour_sla(self) -> None:
        queue = RemediationQueue()
        now = datetime(2024, 1, 1, tzinfo=timezone.utc)
        queue.add_item(
            finding_id="finding-1",
            priority_score=85.0,
            discovered_at=now,
        )
        item = queue.get_item("finding-1")
        self.assertIsNotNone(item)
        self.assertEqual(item.sla_hours, 48)
        self.assertEqual(
            item.sla_deadline, now + timedelta(hours=48)
        )

    def test_queue_orders_by_priority(self) -> None:
        queue = RemediationQueue()
        now = datetime(2024, 1, 1, tzinfo=timezone.utc)
        queue.add_item("finding-low", 30.0, now)
        queue.add_item("finding-high", 90.0, now)
        queue.add_item("finding-med", 60.0, now)

        ordered = queue.next_items(limit=3)
        self.assertEqual(
            [item.finding_id for item in ordered],
            ["finding-high", "finding-med", "finding-low"],
        )

    def test_expired_sla_items_are_flagged(self) -> None:
        queue = RemediationQueue()
        past = datetime(2024, 1, 1, tzinfo=timezone.utc) - timedelta(hours=50)
        queue.add_item("finding-stale", 90.0, past)

        item = queue.get_item("finding-stale")
        self.assertIsNotNone(item)
        self.assertTrue(item.sla_expired)


class ExplainPriorityTests(unittest.TestCase):
    def _fact(self, **changes: object) -> object:
        from app.intel import VulnerabilityFact

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

    def _service(self, **changes: object) -> object:
        from app.intel import ServiceDescriptor

        values = {
            "service_id": "service-1",
            "asset_id": "asset-1",
            "product": "widget",
            "vendor": "acme",
            "version": "1.2.3",
            "cpe": "cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*",
            "exposed": True,
        }
        values.update(changes)
        return ServiceDescriptor(**values)

    def test_explanation_includes_all_inputs(self) -> None:
        from app.prioritization import PrioritizationV2

        scorer = PrioritizationV2(criticality_registry=AssetCriticality())
        result = scorer.score(
            service=self._service(),
            fact=self._fact(),
            now=datetime(2024, 1, 4, tzinfo=timezone.utc),
        )

        explanation = explain_priority(result)
        self.assertIn("cvss", explanation)
        self.assertIn("epss", explanation)
        self.assertIn("kev", explanation)
        self.assertIn("exposure", explanation)
        self.assertIn("business_criticality", explanation)


if __name__ == "__main__":
    unittest.main()