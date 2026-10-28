import unittest
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from app.recon import (
    AdapterResult,
    InMemoryReconRepository,
    ReconEngine,
    ReconError,
    Scope,
    SyntheticAdapter,
    Target,
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
            expires_at=datetime.now(UTC) + timedelta(hours=1),
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

    def test_operator_can_delete_a_scope(self) -> None:
        headers = {"X-Principal-ID": "operator-1", "X-Principal-Role": "operator"}
        deleted = self.client.delete("/api/v1/recon/scopes/scope-lab", headers=headers)
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(deleted.json(), {"scopeId": "scope-lab", "deleted": True})

        listed = self.client.get(
            "/api/v1/recon/scopes",
            headers={"X-Principal-ID": "operator-1", "X-Principal-Role": "viewer"},
        )
        self.assertEqual(listed.status_code, 200)
        self.assertNotIn(
            "scope-lab",
            [item["scopeId"] for item in listed.json()["items"]],
        )

    def test_scope_deletion_requires_operator_role(self) -> None:
        response = self.client.delete(
            "/api/v1/recon/scopes/scope-lab",
            headers={"X-Principal-ID": "operator-1", "X-Principal-Role": "viewer"},
        )
        self.assertEqual(response.status_code, 403)

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
            expires_at=datetime.now(UTC) + timedelta(hours=1),
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

    def test_verified_public_scope_can_queue_scan(self) -> None:
        class Resolver(DnsTxtResolver):
            def __init__(self) -> None:
                self.records: dict[str, tuple[str, ...]] = {}

            def txt_records(self, name: str) -> tuple[str, ...]:
                return self.records.get(name, ())

        resolver = Resolver()
        registry = AuthorizationRegistry(resolver)
        repository = InMemoryReconRepository()
        engine = ReconEngine(
            repository,
            {
                "synthetic_inventory_v1": SyntheticAdapter(
                    AdapterResult(("example.com",), (), ())
                )
            },
        )
        queue = ReconQueue(engine, repository, registry)
        client = TestClient(
            create_recon_app(queue, lambda request: Principal("operator-1", "operator"))
        )
        challenge = client.post(
            "/api/v1/recon/authorizations/challenges",
            json={"domain": "example.com"},
        ).json()
        resolver.records[challenge["recordName"]] = (challenge["token"],)
        verification = client.post(
            "/api/v1/recon/authorizations",
            json={
                "challengeId": challenge["challengeId"],
                "profileIds": ["synthetic_inventory_v1"],
            },
        )
        self.assertEqual(verification.status_code, 201)
        authorization_id = verification.json()["authorizationId"]

        created = client.post(
            "/api/v1/recon/scopes",
            json={
                "scopeId": "scope-public",
                "targets": ["example.com"],
                "environment": "isolated_lab",
                "profiles": ["synthetic_inventory_v1"],
                "authorizationId": authorization_id,
                "expiresInHours": 1,
            },
        )
        self.assertEqual(created.status_code, 201)
        queued = client.post(
            "/api/v1/recon/scans",
            json={
                "scopeId": "scope-public",
                "target": "example.com",
                "profileId": "synthetic_inventory_v1",
            },
        )
        self.assertEqual(queued.status_code, 202)
        queue.run_pending()
        status = client.get(f"/api/v1/recon/scans/{queued.json()['scanId']}")
        self.assertEqual(status.status_code, 200)
        self.assertEqual(status.json()["state"], "completed")

    def test_isolated_lab_scope_creation_requires_authorization(self) -> None:
        response = self.client.post(
            "/api/v1/recon/scopes",
            headers={"X-Principal-ID": "operator-1", "X-Principal-Role": "operator"},
            json={
                "scopeId": "scope-public-missing-auth",
                "targets": ["example.com"],
                "environment": "isolated_lab",
                "profiles": ["synthetic_inventory_v1"],
            },
        )
        self.assertEqual(response.status_code, 403)

    def test_normal_and_medium_scopes_do_not_require_authorization(self) -> None:
        response = self.client.post(
            "/api/v1/recon/scopes",
            headers={"X-Principal-ID": "operator-1", "X-Principal-Role": "operator"},
            json={
                "scopeId": "scope-bounded",
                "targets": ["example.com"],
                "environment": "synthetic",
                "profiles": [
                    "service_inventory_normal_v1",
                    "passive_subdomain_medium_v1",
                ],
            },
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(
            response.json()["profiles"],
            ["service_inventory_normal_v1", "passive_subdomain_medium_v1"],
        )

    def test_high_and_deep_profiles_require_dns_authorization(self) -> None:
        for profile_id in (
            "service_inventory_high_v1",
            "service_inventory_deep_v1",
            "passive_subdomain_high_v1",
            "passive_subdomain_deep_v1",
        ):
            response = self.client.post(
                "/api/v1/recon/scopes",
                headers={"X-Principal-ID": "operator-1", "X-Principal-Role": "operator"},
                json={
                    "scopeId": f"scope-{profile_id}",
                    "targets": ["example.com"],
                    "environment": "synthetic",
                    "profiles": [profile_id],
                },
            )
            self.assertEqual(response.status_code, 403, profile_id)

    def test_verified_high_profile_can_create_isolated_scope(self) -> None:
        class Resolver(DnsTxtResolver):
            def __init__(self) -> None:
                self.records: dict[str, tuple[str, ...]] = {}

            def txt_records(self, name: str) -> tuple[str, ...]:
                return self.records.get(name, ())

        resolver = Resolver()
        registry = AuthorizationRegistry(resolver)
        queue = ReconQueue(
            InMemoryReconRepository(),
            InMemoryReconRepository(),
            registry,
        )
        client = TestClient(
            create_recon_app(queue, lambda request: Principal("operator-1", "operator"))
        )
        challenge = client.post(
            "/api/v1/recon/authorizations/challenges",
            json={"domain": "example.com"},
        ).json()
        resolver.records[challenge["recordName"]] = (challenge["token"],)
        verification = client.post(
            "/api/v1/recon/authorizations",
            json={
                "challengeId": challenge["challengeId"],
                "profileIds": ["service_inventory_high_v1"],
            },
        )
        self.assertEqual(verification.status_code, 201)
        created = client.post(
            "/api/v1/recon/scopes",
            json={
                "scopeId": "scope-high-authorized",
                "targets": ["example.com"],
                "environment": "isolated_lab",
                "profiles": ["service_inventory_high_v1"],
                "authorizationId": verification.json()["authorizationId"],
                "expiresInHours": 1,
            },
        )
        self.assertEqual(created.status_code, 201)

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

    def test_queue_depth_and_target_cooldown_are_bounded(self) -> None:
        repository = InMemoryReconRepository()
        engine = ReconEngine(
            repository,
            {
                "synthetic_inventory_v1": SyntheticAdapter(
                    AdapterResult(("lab.example.test",), (), ())
                )
            },
        )
        queue = ReconQueue(
            engine,
            repository,
            max_queue_depth=1,
            target_cooldown_seconds=60,
        )
        queue.add_scope(self.scope)
        queue.enqueue(
            self.scope,
            Target("lab.example.test", "domain"),
            "synthetic_inventory_v1",
            None,
        )
        with self.assertRaises(ReconError):
            queue.enqueue(
                self.scope,
                Target("other.example.test", "domain"),
                "synthetic_inventory_v1",
                None,
            )
