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
from app.recon_authorization import AuthorizationRegistry, DnsTxtResolver
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

    def test_operator_can_create_scope_and_read_scan_result(self) -> None:
        headers = {"X-Principal-ID": "operator-1", "X-Principal-Role": "operator"}
        created = self.client.post(
            "/api/v1/recon/scopes",
            headers=headers,
            json={
                "scopeId": "scope-created",
                "targets": ["lab.example.test"],
                "environment": "synthetic",
                "profiles": ["synthetic_inventory_v1"],
                "expiresInHours": 2,
            },
        )
        self.assertEqual(created.status_code, 201)
        self.assertEqual(created.json()["scopeId"], "scope-created")
        self.assertEqual(created.json()["targets"], ["lab.example.test"])

        listed = self.client.get(
            "/api/v1/recon/scopes",
            headers={"X-Principal-ID": "operator-1", "X-Principal-Role": "viewer"},
        )
        self.assertEqual(listed.status_code, 200)
        self.assertIn(
            "scope-created",
            [item["scopeId"] for item in listed.json()["items"]],
        )

        queued = self.client.post(
            "/api/v1/recon/scans",
            headers=headers,
            json={
                "scopeId": "scope-created",
                "target": "lab.example.test",
                "profileId": "synthetic_inventory_v1",
            },
        )
        self.assertEqual(queued.status_code, 202)
        scan_id = queued.json()["scanId"]
        self.queue.run_pending()

        result = self.client.get(
            f"/api/v1/recon/scans/{scan_id}/result",
            headers={"X-Principal-ID": "operator-1", "X-Principal-Role": "viewer"},
        )
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json()["state"], "completed")
        self.assertEqual(result.json()["assets"], ["lab.example.test"])

    def test_scope_creation_requires_operator_role(self) -> None:
        response = self.client.post(
            "/api/v1/recon/scopes",
            headers={"X-Principal-ID": "operator-1", "X-Principal-Role": "viewer"},
            json={
                "scopeId": "scope-viewer",
                "targets": ["lab.example.test"],
                "profiles": ["synthetic_inventory_v1"],
            },
        )
        self.assertEqual(response.status_code, 403)

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

    def test_isolated_lab_scope_requires_active_target_authorization(self) -> None:
        class EmptyResolver(DnsTxtResolver):
            def txt_records(self, name: str) -> tuple[str, ...]:
                return ()

        repository = InMemoryReconRepository()
        engine = ReconEngine(
            repository,
            {
                "synthetic_inventory_v1": SyntheticAdapter(
                    AdapterResult(("lab.example.test",), (), ())
                )
            },
        )
        queue = ReconQueue(engine, repository, AuthorizationRegistry(EmptyResolver()))
        isolated_scope = Scope(
            scope_id="scope-isolated",
            owner_id="operator-1",
            targets=("lab.example.test",),
            environment="isolated_lab",
            approved=True,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            profiles=("synthetic_inventory_v1",),
        )
        queue.add_scope(isolated_scope)
        client = TestClient(
            create_recon_app(
                queue,
                lambda request: Principal("operator-1", "operator"),
            )
        )
        response = client.post(
            "/api/v1/recon/scans",
            json={
                "scopeId": "scope-isolated",
                "target": "lab.example.test",
                "profileId": "synthetic_inventory_v1",
            },
        )
        self.assertEqual(response.status_code, 403)

    def test_operator_can_create_and_verify_domain_challenge(self) -> None:
        class Resolver(DnsTxtResolver):
            def __init__(self) -> None:
                self.records: dict[str, tuple[str, ...]] = {}

            def txt_records(self, name: str) -> tuple[str, ...]:
                return self.records.get(name, ())

        resolver = Resolver()
        registry = AuthorizationRegistry(resolver)
        queue = ReconQueue(InMemoryReconRepository(), InMemoryReconRepository(), registry)
        client = TestClient(
            create_recon_app(queue, lambda request: Principal("operator-1", "operator"))
        )
        challenge_response = client.post(
            "/api/v1/recon/authorizations/challenges",
            json={"domain": "example.com"},
        )
        self.assertEqual(challenge_response.status_code, 201)
        challenge = challenge_response.json()
        resolver.records[challenge["recordName"]] = (challenge["token"],)
        verification = client.post(
            "/api/v1/recon/authorizations",
            json={
                "challengeId": challenge["challengeId"],
                "profileIds": ["service_inventory_v1"],
            },
        )
        self.assertEqual(verification.status_code, 201)
        self.assertEqual(verification.json()["target"], "example.com")

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
