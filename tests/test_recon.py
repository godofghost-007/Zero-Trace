from datetime import datetime, timedelta, timezone
import unittest
from uuid import uuid4

from app.recon import (
    AdapterResult,
    InMemoryReconRepository,
    NmapAdapter,
    PROFILES,
    ReconEngine,
    ReconError,
    ReconCancelledError,
    ReconRunState,
    ReconTimeoutError,
    ReadOnlyS3Adapter,
    Scope,
    SubfinderAdapter,
    SyntheticAdapter,
    Target,
    TLSAdapter,
    ReconRateLimiter,
)


def scope(**overrides: object) -> Scope:
    values = {
        "scope_id": "scope-lab",
        "owner_id": "operator-1",
        "targets": ("lab.example.test",),
        "environment": "isolated_lab",
        "approved": True,
        "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
        "profiles": ("synthetic_inventory_v1",),
    }
    values.update(overrides)
    return Scope(**values)


def target(value: str = "lab.example.test") -> Target:
    return Target(value=value, kind="domain")


class ReconContractTests(unittest.TestCase):
    def test_active_profile_requires_dns_resolution_before_adapter(self) -> None:
        adapter = SyntheticAdapter(AdapterResult(("lab.example.test",), (), ()))
        engine = ReconEngine(
            InMemoryReconRepository(),
            {"service_inventory_v1": adapter},
            dns_resolver=lambda _: (),
        )
        active_scope = scope(profiles=("service_inventory_v1",))

        with self.assertRaisesRegex(ReconError, "DNS resolution"):
            engine.create_run(active_scope, target(), profile_id="service_inventory_v1")

        self.assertEqual(adapter.calls, 0)

    def test_inventory_delta_records_new_and_removed_services(self) -> None:
        repository = InMemoryReconRepository()
        results = [
            AdapterResult(
                ("lab.example.test", "old.lab.example.test"),
                (("lab.example.test", "tcp", 443, "https"),),
                (),
            ),
            AdapterResult(
                ("lab.example.test", "new.lab.example.test"),
                (("lab.example.test", "tcp", 8443, "https"),),
                (),
            ),
        ]

        class Adapter:
            def run(self, target: Target, profile: object) -> AdapterResult:
                return results.pop(0)

        engine = ReconEngine(repository, {"synthetic_inventory_v1": Adapter()})
        engine.create_run(scope(), target())
        second = engine.create_run(scope(), target())

        self.assertEqual(
            repository.results[second.run_id].inventory_delta.added_assets,
            ("new.lab.example.test",),
        )
        self.assertEqual(
            repository.results[second.run_id].inventory_delta.removed_assets,
            ("old.lab.example.test",),
        )
        self.assertEqual(
            repository.results[second.run_id].inventory_delta.added_services,
            (("lab.example.test", "tcp", 8443),),
        )
        self.assertEqual(
            repository.results[second.run_id].inventory_delta.removed_services,
            (("lab.example.test", "tcp", 443),),
        )
    def test_rate_limiter_enforces_profile_budget(self) -> None:
        limiter = ReconRateLimiter()
        limiter.acquire("scope-1", rate_per_minute=1, now=100.0)
        with self.assertRaises(ReconError):
            limiter.acquire("scope-1", rate_per_minute=1, now=100.1)

    def test_expired_scope_is_rejected_before_adapter_execution(self) -> None:
        adapter = SyntheticAdapter(
            AdapterResult(assets=(), services=(), warnings=())
        )
        engine = ReconEngine(InMemoryReconRepository(), {"synthetic_inventory_v1": adapter})
        expired = scope(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))

        with self.assertRaises(ReconError):
            engine.create_run(expired, target())

        self.assertEqual(adapter.calls, 0)

    def test_target_outside_scope_and_unknown_profile_are_rejected(self) -> None:
        repository = InMemoryReconRepository()
        adapter = SyntheticAdapter(AdapterResult(assets=(), services=(), warnings=()))
        engine = ReconEngine(repository, {"synthetic_inventory_v1": adapter})

        with self.assertRaises(ReconError):
            engine.create_run(scope(), target("attacker.example.test"))

        with self.assertRaises(ReconError):
            engine.create_run(
                scope(profiles=("unknown_profile",)),
                target(),
            )

        self.assertEqual(repository.runs, {})

    def test_successful_run_normalizes_results_and_publishes_after_commit(self) -> None:
        repository = InMemoryReconRepository()
        event_order: list[str] = []
        repository.on_event = lambda _: event_order.append(
            "event" if repository.results_committed else "early"
        )
        adapter = SyntheticAdapter(
            AdapterResult(
                assets=("lab.example.test",),
                services=(("lab.example.test", "tcp", 443, "https"),),
                warnings=(),
            )
        )
        engine = ReconEngine(
            repository,
            {"synthetic_inventory_v1": adapter},
            event_publisher=repository.publish_event,
        )

        run = engine.create_run(scope(), target())

        self.assertEqual(run.state, ReconRunState.COMPLETED)
        self.assertEqual(repository.results[run.run_id].services[0].port, 443)
        self.assertEqual(event_order, ["event"])
        self.assertEqual(repository.events[0]["eventType"], "scan_status_changed")

    def test_adapter_failure_is_visible_and_not_empty_success(self) -> None:
        repository = InMemoryReconRepository()
        adapter = SyntheticAdapter(
            AdapterResult(
                assets=(),
                services=(),
                warnings=("scanner failed",),
                state=ReconRunState.FAILED,
            )
        )
        engine = ReconEngine(
            repository,
            {"synthetic_inventory_v1": adapter},
            event_publisher=repository.publish_event,
        )

        run = engine.create_run(scope(), target())

        self.assertEqual(run.state, ReconRunState.FAILED)
        self.assertEqual(run.warnings, ("scanner failed",))
        self.assertNotEqual(run.state, ReconRunState.COMPLETED)

    def test_duplicate_idempotency_key_returns_existing_run(self) -> None:
        repository = InMemoryReconRepository()
        adapter = SyntheticAdapter(AdapterResult(assets=(), services=(), warnings=()))
        engine = ReconEngine(
            repository,
            {"synthetic_inventory_v1": adapter},
            event_publisher=repository.publish_event,
        )

        first = engine.create_run(scope(), target(), idempotency_key="request-1")
        second = engine.create_run(scope(), target(), idempotency_key="request-1")

        self.assertEqual(first.run_id, second.run_id)
        self.assertEqual(adapter.calls, 1)

    def test_reusing_idempotency_key_with_different_target_is_rejected(self) -> None:
        repository = InMemoryReconRepository()
        adapter = SyntheticAdapter(AdapterResult(assets=(), services=(), warnings=()))
        engine = ReconEngine(repository, {"synthetic_inventory_v1": adapter})

        engine.create_run(scope(), target(), idempotency_key="request-1")

        with self.assertRaises(ReconError):
            engine.create_run(
                scope(targets=("other.example.test",)),
                target("other.example.test"),
                idempotency_key="request-1",
            )

    def test_timeout_and_cancellation_are_explicit_states(self) -> None:
        class TimeoutAdapter:
            def run(self, target: Target, profile: object) -> AdapterResult:
                raise ReconTimeoutError("internal detail")

        class CancelledAdapter:
            def run(self, target: Target, profile: object) -> AdapterResult:
                raise ReconCancelledError("internal detail")

        timed_out = ReconEngine(
            InMemoryReconRepository(),
            {"synthetic_inventory_v1": TimeoutAdapter()},
        ).create_run(scope(), target())
        cancelled = ReconEngine(
            InMemoryReconRepository(),
            {"synthetic_inventory_v1": CancelledAdapter()},
        ).create_run(scope(), target())

        self.assertEqual(timed_out.state, ReconRunState.TIMED_OUT)
        self.assertEqual(cancelled.state, ReconRunState.CANCELLED)
        self.assertEqual(timed_out.warnings, ("recon execution timed out",))


class ReconAdapterTests(unittest.TestCase):
    def test_subfinder_uses_fixed_arguments_and_keeps_malformed_records_visible(self) -> None:
        calls: list[tuple[str, ...]] = []

        class Runner:
            def run(self, args: tuple[str, ...], timeout_seconds: int, max_output_bytes: int) -> bytes:
                calls.append(args)
                return (
                    b'{"host":"api.lab.example.test"}\n'
                    b'not-json\n'
                )

        result = SubfinderAdapter("subfinder", Runner()).run(
            target(), PROFILES["passive_subdomain_v1"]
        )

        self.assertEqual(calls[0], ("subfinder", "-d", "lab.example.test", "-silent", "-json"))
        self.assertEqual(result.assets, ("api.lab.example.test",))
        self.assertEqual(result.state, ReconRunState.PARTIAL)
        self.assertEqual(result.warnings, ("malformed passive-discovery record",))

    def test_nmap_parses_only_open_services_and_reports_zero_ports(self) -> None:
        class Runner:
            def run(self, args: tuple[str, ...], timeout_seconds: int, max_output_bytes: int) -> bytes:
                return (
                    b"<nmaprun><host><ports><port protocol='tcp' portid='443'>"
                    b"<state state='open'/><service name='https'/></port>"
                    b"<port protocol='tcp' portid='22'><state state='closed'/>"
                    b"</port></ports></host></nmaprun>"
                )

        result = NmapAdapter("nmap", Runner()).run(
            target(), PROFILES["service_inventory_v1"]
        )

        self.assertEqual(result.services, (("lab.example.test", "tcp", 443, "https"),))
        self.assertEqual(result.warnings, ())

    def test_read_only_s3_adapter_accepts_statuses_but_has_no_write_interface(self) -> None:
        adapter = ReadOnlyS3Adapter(lambda _: "public_listable")

        result = adapter.run(target(), PROFILES["s3_read_only_v1"])

        self.assertEqual(result.warnings, ("s3:public_listable",))
        self.assertFalse(hasattr(adapter, "upload"))
        self.assertFalse(hasattr(adapter, "delete"))

    def test_tls_adapter_preserves_certificate_metadata(self) -> None:
        adapter = TLSAdapter(
            lambda host, port, timeout: {
                "subject": "CN=lab.example.test",
                "issuer": "Synthetic CA",
                "expires_at": "2030-01-01T00:00:00+00:00",
                "status": "valid",
            }
        )

        result = adapter.run(target(), PROFILES["tls_metadata_v1"])

        self.assertEqual(result.tls_findings[0]["issuer"], "Synthetic CA")
        self.assertEqual(result.tls_findings[0]["status"], "valid")


if __name__ == "__main__":
    unittest.main()
