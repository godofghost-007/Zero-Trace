import json
import unittest
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from app.intel_api import InMemoryIntelRepository, create_intel_app
from app.intel_feeds import NVD_ENDPOINT, SyntheticTransport
from app.recon import AdapterResult, InMemoryReconRepository, ReconEngine, SyntheticAdapter
from app.recon_api import ReconQueue, create_recon_app
from app.security import Principal
from app.runtime import create_postgres_repositories


class RuntimePersistenceHookTests(unittest.TestCase):
    def test_runtime_factory_mounts_recon_and_intel_routes(self) -> None:
        from app.runtime import create_runtime_app

        recon_repository = MagicMock()
        intel_repository = MagicMock()
        app = create_runtime_app(
            recon_queue=MagicMock(),
            recon_repository=recon_repository,
            intel_repository=intel_repository,
            principal_provider=lambda request: Principal("viewer-1", "viewer"),
            transport=SyntheticTransport({}),
        )

        def paths(routes):
            for route in routes:
                if hasattr(route, "path"):
                    yield route.path
                yield from paths(getattr(route, "routes", ()))

        routes = set(paths(app.routes))
        self.assertIn("/api/v1/assets", routes)
        self.assertIn("/api/v1/findings", routes)

    def test_postgres_recon_reads_are_scope_filtered(self) -> None:
        from app.recon_pg import PostgresReconRepository

        connection = MagicMock()
        connection.__enter__.return_value = connection
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchall.return_value = [("asset-1", "lab.example.test")]
        repository = PostgresReconRepository(lambda: connection)

        assets = repository.list_assets("owner-1")

        self.assertEqual(assets, [{"assetId": "asset-1", "identifier": "lab.example.test"}])
        statement = cursor.execute.call_args.args[0]
        self.assertIn("JOIN recon_scopes", statement)
        self.assertIn("owner_id = %s", statement)

    def test_postgres_intel_reads_are_scope_filtered_and_paginated(self) -> None:
        from app.intel_pg import PostgresIntelRepository

        connection = MagicMock()
        connection.__enter__.return_value = connection
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchone.side_effect = [(3,)]
        cursor.fetchall.return_value = [
            (
                "finding-1", "scope-1", "asset-1", "service-1", "CVE-2024-1234",
                "exact_cpe", 1.0, [], "fresh", 80.0, {}, "intel-priority-v1",
                "rev-1",
            )
        ]
        repository = PostgresIntelRepository(lambda: connection)

        result = repository.list_findings("owner-1", page=1, page_size=2)

        self.assertEqual(result["pagination"]["totalItems"], 3)
        self.assertEqual(result["items"][0]["findingId"], "finding-1")
        statement = cursor.execute.call_args_list[-1].args[0]
        self.assertIn("JOIN recon_scopes", statement)
        self.assertIn("owner_id = %s", statement)

    def test_postgres_intel_detail_read_is_scope_filtered(self) -> None:
        from app.intel_pg import PostgresIntelRepository

        connection = MagicMock()
        connection.__enter__.return_value = connection
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchone.return_value = (
            "finding-1", "scope-1", "asset-1", "service-1", "CVE-2024-1234",
            "exact_cpe", 1.0, [], "fresh", 80.0, {}, "intel-priority-v1", "rev-1",
        )
        repository = PostgresIntelRepository(lambda: connection)

        finding = repository.get_finding("owner-1", "finding-1")

        self.assertEqual(finding["findingId"], "finding-1")
        self.assertIn("owner_id = %s", cursor.execute.call_args.args[0])

    def test_runtime_factory_composes_postgres_repositories(self) -> None:
        recon, intel = create_postgres_repositories(
            "postgresql://zerotrace:password@localhost/zerotrace"
        )

        self.assertEqual(type(recon).__name__, "PostgresReconRepository")
        self.assertEqual(type(intel).__name__, "PostgresIntelRepository")

    def test_intel_ingestion_calls_persistence_hook(self) -> None:
        persistence = MagicMock()
        body = json.dumps(
            {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2024-1234",
                            "descriptions": [{"lang": "en", "value": "Example"}],
                            "published": "2024-01-01T00:00:00Z",
                            "lastModified": "2024-01-02T00:00:00Z",
                            "configurations": [],
                            "metrics": {},
                        }
                    }
                ]
            }
        ).encode()
        app = create_intel_app(
            InMemoryIntelRepository(),
            lambda request: Principal("operator-1", "operator"),
            SyntheticTransport({NVD_ENDPOINT: body}),
            persistence=persistence,
        )

        response = TestClient(app).post(
            "/api/v1/intel/ingestions",
            headers={"Idempotency-Key": "runtime-hook"},
            json={"source": "nvd"},
        )

        self.assertEqual(response.status_code, 202)
        persistence.save_fact.assert_called_once()

    def test_recon_queue_calls_postgres_persistence_hook(self) -> None:
        repository = InMemoryReconRepository()
        persistence = MagicMock()
        engine = ReconEngine(
            repository,
            {
                "synthetic_inventory_v1": SyntheticAdapter(
                    AdapterResult(
                        ("lab.example.test",),
                        (("lab.example.test", "tcp", 443, "https"),),
                        (),
                    )
                )
            },
        )
        queue = ReconQueue(engine, repository, persistence=persistence)
        from app.recon import Scope, Target
        from datetime import datetime, timedelta, timezone

        scope = Scope(
            "scope-hook",
            "operator-1",
            ("lab.example.test",),
            "synthetic",
            True,
            datetime.now(timezone.utc) + timedelta(minutes=5),
            ("synthetic_inventory_v1",),
        )
        queue.add_scope(scope)
        queue.enqueue(scope, Target("lab.example.test", "domain"), "synthetic_inventory_v1", None)
        queue.run_pending()

        persistence.save_scan.assert_called()
        self.assertEqual(
            persistence.save_scan.call_args.kwargs["state"],
            "completed",
        )
        self.assertEqual(
            persistence.save_scan.call_args.kwargs["assets"],
            ("lab.example.test",),
        )
