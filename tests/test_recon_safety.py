from datetime import datetime, timedelta, timezone
import threading
import time
import unittest
from uuid import uuid4

from app.recon import (
    AdapterResult,
    InMemoryReconRepository,
    ReconEngine,
    ReconError,
    ReconRunState,
    Scope,
    SyntheticAdapter,
    Target,
    ReconRateLimiter,
)


def safe_scope(**overrides: object) -> Scope:
    values = {
        "scope_id": "scope-safety",
        "owner_id": "operator-1",
        "targets": ("lab.example.test",),
        "environment": "isolated_lab",
        "approved": True,
        "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
        "profiles": ("synthetic_inventory_v1",),
    }
    values.update(overrides)
    return Scope(**values)


def safe_target(value: str = "lab.example.test") -> Target:
    return Target(value=value, kind="domain")


class CountingAdapter:
    """Adapter that tracks calls and can fail on the first N attempts."""

    def __init__(self, fail_count: int = 0, result: AdapterResult | None = None) -> None:
        self.fail_count = fail_count
        self.calls = 0
        self._result = result or AdapterResult(
            assets=("lab.example.test",),
            services=(("lab.example.test", "tcp", 443, "https"),),
            warnings=(),
        )

    def run(self, target: Target, profile: object) -> AdapterResult:
        self.calls += 1
        if self.calls <= self.fail_count:
            raise ReconError("transient adapter failure")
        return self._result


class AlwaysRejectLimiter:
    def acquire(self, scope_id: str, *, rate_per_minute: int, now: float | None = None) -> None:
        raise ReconError("rate limit exceeded")


class RateLimiterPlacementTests(unittest.TestCase):
    def test_rate_limit_failure_does_not_leave_orphaned_run(self) -> None:
        """Rate limiter must be checked before run creation so a rejected
        request never leaves a RUNNING run in the repository."""
        repository = InMemoryReconRepository()
        adapter = SyntheticAdapter(
            AdapterResult(assets=(), services=(), warnings=())
        )
        engine = ReconEngine(
            repository,
            {"synthetic_inventory_v1": adapter},
            rate_limiter=None,  # we'll inject a failing limiter below
        )
        # Replace with a limiter that always rejects
        engine.rate_limiter = AlwaysRejectLimiter()

        with self.assertRaises(ReconError):
            engine.create_run(safe_scope(), safe_target())

        # No run should exist in the repository
        self.assertEqual(repository.runs, {})


class ConcurrencyLimitTests(unittest.TestCase):
    def test_concurrency_limit_exceeded_marks_failed(self) -> None:
        """When max_concurrent_runs is reached, a new run must fail fast
        instead of blocking or leaving orphaned state."""
        repository = InMemoryReconRepository()

        class HoldingAdapter:
            def __init__(self) -> None:
                self.lock = threading.Lock()
                self.held = False

            def run(self, target: Target, profile: object) -> AdapterResult:
                with self.lock:
                    self.held = True
                # Simulate a long-running scan that holds the concurrency slot
                import time

                time.sleep(0.5)
                with self.lock:
                    self.held = False
                return AdapterResult(assets=(), services=(), warnings=())

        holding = HoldingAdapter()
        engine = ReconEngine(
            repository,
            {"synthetic_inventory_v1": holding},
            max_concurrent_runs=1,
        )

        result_holder = {}

        def run_scan() -> None:
            result_holder["run"] = engine.create_run(
                safe_scope(), safe_target(), profile_id="synthetic_inventory_v1"
            )

        t = threading.Thread(target=run_scan)
        t.start()
        # Give the first run time to acquire the semaphore
        time.sleep(0.1)

        # A second run should fail fast due to concurrency limit (returns FAILED run)
        second = engine.create_run(safe_scope(), safe_target(), profile_id="synthetic_inventory_v1")
        self.assertEqual(second.state, ReconRunState.FAILED)
        self.assertIn("recon concurrency limit exceeded", second.warnings)

        t.join()
        # The first run should complete successfully
        self.assertEqual(result_holder["run"].state, ReconRunState.COMPLETED)


class RetryLogicTests(unittest.TestCase):
    def test_transient_failures_are_retried_before_marking_failed(self) -> None:
        """A transient adapter failure should be retried up to the configured
        max_attempts before the run is marked FAILED."""
        repository = InMemoryReconRepository()
        adapter = CountingAdapter(fail_count=2)
        engine = ReconEngine(
            repository,
            {"synthetic_inventory_v1": adapter},
            max_retries=3,
            retry_delay_seconds=0.01,
        )

        run = engine.create_run(safe_scope(), safe_target())

        self.assertEqual(run.state, ReconRunState.COMPLETED)
        self.assertEqual(adapter.calls, 3)  # 2 failures + 1 success

    def test_exhausted_retries_mark_run_failed(self) -> None:
        """When all retries are exhausted, the run must be FAILED, not
        silently successful."""
        repository = InMemoryReconRepository()
        adapter = CountingAdapter(fail_count=5)
        engine = ReconEngine(
            repository,
            {"synthetic_inventory_v1": adapter},
            max_retries=3,
            retry_delay_seconds=0.01,
        )

        run = engine.create_run(safe_scope(), safe_target())

        self.assertEqual(run.state, ReconRunState.FAILED)
        self.assertEqual(adapter.calls, 4)  # 1 initial + 3 retries


if __name__ == "__main__":
    unittest.main()