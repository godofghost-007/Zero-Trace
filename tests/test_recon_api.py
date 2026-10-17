import unittest
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.recon import (
    AdapterResult,
    InMemoryReconRepository,
    ReconEngine,
    Scope,
    SyntheticAdapter,
)
from app.recon_api import ReconQueue, create_recon_app
from app.security import Principal


class ReconApiTests(unittest.TestCase):
    def setUp(self) -> None:
        repository = InMemoryReconRepository()
        engine = ReconEngine(
            repository,
            {
                "synthetic_inventory_v1": SyntheticAdapter(
                    AdapterResult(("lab.example.test",), (), ())
                )
            },
        )
        self.queue = ReconQueue(engine, repository)
        self.scope = Scope(
            scope_id="scope-lab",
            owner_id="operator-1",
            targets=("lab.example.test", "other.example.test"),
            environment="synthetic",
            approved=True,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            profiles=("synthetic_inventory_v1",),
        )
        self.queue.add_scope(self.scope)
        self.client = TestClient(
            create_recon_app(
                self.queue,
                lambda request: Principal(
                    request.headers.get("X-Principal-ID", ""),
                    request.headers.get("X-Principal-Role", ""),
                ),
            )
        )

    def test_operator_can_queue_and_poll_scan(self) -> None:
        response = self.client.post(
            "/api/v1/recon/scans",
            headers={
                "X-Principal-ID": "operator-1",
                "X-Principal-Role": "operator",
                "Idempotency-Key": "scan-1",
            },
            json={
                "scopeId": "scope-lab",
                "target": "lab.example.test",
                "profileId": "synthetic_inventory_v1",
            },
        )
        self.assertEqual(response.status_code, 202)
        scan_id = response.json()["scanId"]
        self.assertEqual(response.json()["state"], "queued")

        self.queue.run_pending()
        status = self.client.get(
            f"/api/v1/recon/scans/{scan_id}",
            headers={"X-Principal-ID": "operator-1", "X-Principal-Role": "viewer"},
        )
        self.assertEqual(status.status_code, 200)
        self.assertEqual(status.json()["state"], "completed")
        asset = self.client.get(
            "/api/v1/assets/lab.example.test",
            headers={"X-Principal-ID": "operator-1", "X-Principal-Role": "viewer"},
        )
        self.assertEqual(asset.status_code, 200)
        self.assertEqual(asset.json(), {"assetId": "lab.example.test"})

    def test_missing_scan_is_not_found(self) -> None:
        response = self.client.get(
            "/api/v1/recon/scans/missing",
            headers={"X-Principal-ID": "operator-1", "X-Principal-Role": "viewer"},
        )
        self.assertEqual(response.status_code, 404)

    def test_operator_can_cancel_a_queued_scan(self) -> None:
        response = self.client.post(
            "/api/v1/recon/scans",
            headers={
                "X-Principal-ID": "operator-1",
                "X-Principal-Role": "operator",
            },
            json={
                "scopeId": "scope-lab",
                "target": "lab.example.test",
                "profileId": "synthetic_inventory_v1",
            },
        )
        scan_id = response.json()["scanId"]
        cancelled = self.client.post(
            f"/api/v1/recon/scans/{scan_id}/cancel",
            headers={
                "X-Principal-ID": "operator-1",
                "X-Principal-Role": "operator",
            },
        )
        self.assertEqual(cancelled.status_code, 200)
        self.assertEqual(cancelled.json()["state"], "cancelled")

    def test_viewer_cannot_create_scan_or_read_other_scope(self) -> None:
        response = self.client.post(
            "/api/v1/recon/scans",
            headers={"X-Principal-ID": "operator-1", "X-Principal-Role": "viewer"},
            json={
                "scopeId": "scope-lab",
                "target": "lab.example.test",
                "profileId": "synthetic_inventory_v1",
            },
        )
        self.assertEqual(response.status_code, 403)

        response = self.client.get(
            "/api/v1/assets",
            headers={"X-Principal-ID": "other-user", "X-Principal-Role": "viewer"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"assets": []})

    def test_changed_idempotency_request_is_a_conflict(self) -> None:
        headers = {
            "X-Principal-ID": "operator-1",
            "X-Principal-Role": "operator",
            "Idempotency-Key": "scan-2",
        }
        payload = {
            "scopeId": "scope-lab",
            "target": "lab.example.test",
            "profileId": "synthetic_inventory_v1",
        }
        self.assertEqual(
            self.client.post("/api/v1/recon/scans", headers=headers, json=payload).status_code,
            202,
        )
        payload["target"] = "other.example.test"
        response = self.client.post(
            "/api/v1/recon/scans", headers=headers, json=payload
        )
        self.assertEqual(response.status_code, 409)
