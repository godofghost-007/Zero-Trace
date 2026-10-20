import json
import unittest
from fastapi.testclient import TestClient

from app.intel_api import InMemoryIntelRepository, create_intel_app
from app.intel_feeds import NVD_ENDPOINT, SyntheticTransport
from app.security import Principal


class IntelApiTests(unittest.TestCase):
    def test_viewer_can_read_engine_status(self) -> None:
        app = create_intel_app(
            InMemoryIntelRepository(),
            lambda request: Principal("viewer-1", "viewer"),
            SyntheticTransport({}),
        )
        response = TestClient(app).get("/api/v1/intel/status")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["mode"], "live-engine")
        self.assertEqual(response.json()["facts"], 0)
        self.assertIn("nvd", response.json()["feeds"])

    def test_operator_can_ingest_fixed_source_and_viewer_can_read_status(self) -> None:
        def principal_provider(request):
            return Principal("operator-1", "operator")

        payload = json.dumps({"vulnerabilities": []}).encode()
        app = create_intel_app(
            InMemoryIntelRepository(),
            principal_provider,
            SyntheticTransport({NVD_ENDPOINT: payload}),
        )
        client = TestClient(app)
        response = client.post(
            "/api/v1/intel/ingestions",
            headers={"Idempotency-Key": "one"},
            json={"source": "nvd"},
        )
        self.assertEqual(response.status_code, 202)
        status = client.get(f"/api/v1/intel/ingestions/{response.json()['ingestionId']}")
        self.assertEqual(status.status_code, 200)
        self.assertEqual(status.json()["state"], "completed")

    def test_ingestion_requires_idempotency_and_rejects_unknown_source(self) -> None:
        app = create_intel_app(
            InMemoryIntelRepository(),
            lambda request: Principal("operator-1", "operator"),
            SyntheticTransport({NVD_ENDPOINT: b"{}"}),
        )
        client = TestClient(app)
        self.assertEqual(
            client.post("/api/v1/intel/ingestions", json={"source": "nvd"}).status_code,
            400,
        )
        self.assertEqual(
            client.post(
                "/api/v1/intel/ingestions",
                headers={"Idempotency-Key": "one"},
                json={"source": "arbitrary"},
            ).status_code,
            422,
        )

    def test_findings_are_paginated_and_have_a_detail_route(self) -> None:
        repository = InMemoryIntelRepository()
        repository.findings = {str(index): {"findingId": str(index)} for index in range(3)}
        app = create_intel_app(
            repository,
            lambda request: Principal("viewer-1", "viewer"),
            SyntheticTransport({}),
        )
        client = TestClient(app)
        response = client.get("/api/v1/findings?page=2&pageSize=1")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["items"], [{"findingId": "1"}])
        self.assertEqual(response.json()["pagination"]["totalItems"], 3)
        detail = client.get("/api/v1/findings/1")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["findingId"], "1")

    def test_uncertain_matches_are_paginated_and_separate_from_findings(self) -> None:
        repository = InMemoryIntelRepository()
        repository.uncertain_matches = [
            {"uncertainId": "u-1", "reason": "ambiguous_candidates"}
        ]
        app = create_intel_app(
            repository,
            lambda request: Principal("viewer-1", "viewer"),
            SyntheticTransport({}),
        )

        response = TestClient(app).get("/api/v1/uncertain-matches?page=1&pageSize=10")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["items"], repository.uncertain_matches)
        self.assertEqual(response.json()["pagination"]["totalItems"], 1)
