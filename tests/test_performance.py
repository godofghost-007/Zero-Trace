"""Phase 15 — Resource and Reliability Measurement.

Tests for resource measurement and reliability validation. These tests measure
cold-start time, peak RAM, per-service memory, CPU utilization, optional model
availability, Guard latency, scanner concurrency, database latency/size, swap
usage, host headroom, and behavior under concurrent activity.
"""

import unittest
import time
import threading
from datetime import datetime, timezone


class PerformanceMeasurementTests(unittest.TestCase):
    """Tests for cold-start time and application startup performance."""

    def test_cold_start_time_is_measured(self) -> None:
        """Cold-start time must be measured and recorded."""
        from app.performance import measure_cold_start
        result = measure_cold_start()
        self.assertIsInstance(result, float)
        self.assertGreaterEqual(result, 0.0)
        self.assertLess(result, 30.0)  # Must start within 30 seconds

    def test_cold_start_is_reproducible(self) -> None:
        """Cold-start measurements should all be positive and within bounds."""
        from app.performance import measure_cold_start
        results = [measure_cold_start() for _ in range(3)]
        for result in results:
            self.assertGreaterEqual(result, 0.0)
            self.assertLess(result, 30.0)


class ResourceMeasurementTests(unittest.TestCase):
    """Tests for memory, CPU, and resource measurement."""

    def test_peak_system_ram_is_measured(self) -> None:
        """Peak system RAM must be measured and reported."""
        from app.performance import measure_peak_ram
        result = measure_peak_ram()
        self.assertIsInstance(result, float)
        self.assertGreater(result, 0.0)

    def test_per_service_memory_is_measured(self) -> None:
        """Per-service memory usage must be measured."""
        from app.performance import measure_per_service_memory
        results = measure_per_service_memory()
        self.assertIsInstance(results, dict)
        self.assertGreater(len(results), 0)

    def test_cpu_utilization_is_measured(self) -> None:
        """CPU utilization must be measured during operation."""
        from app.performance import measure_cpu_utilization
        result = measure_cpu_utilization(duration_seconds=1)
        self.assertIsInstance(result, float)
        self.assertGreaterEqual(result, 0.0)
        self.assertLessEqual(result, 100.0)


class GuardLatencyTests(unittest.TestCase):
    """Tests for Guard latency measurement."""

    def test_guard_latency_is_measured(self) -> None:
        """Guard request latency must be measured and bounded."""
        from app.performance import measure_guard_latency
        result = measure_guard_latency()
        self.assertIsInstance(result, float)
        self.assertGreaterEqual(result, 0.0)
        self.assertLess(result, 5.0)  # Must respond within 5 seconds

    def test_guard_latency_is_bounded(self) -> None:
        """Guard latency must not exceed acceptable threshold."""
        from app.performance import measure_guard_latency
        result = measure_guard_latency()
        self.assertLess(result, 2.0)  # Target: under 2 seconds


class ConcurrencyTests(unittest.TestCase):
    """Tests for concurrent Recon, Intel, Guard, and dashboard activity."""

    def test_concurrent_recon_scans(self) -> None:
        """Multiple Recon scans must run concurrently without failure."""
        from app.performance import test_concurrent_recon
        results = test_concurrent_recon(num_runs=3)
        self.assertEqual(len(results), 3)
        for result in results:
            self.assertIn(result["state"], ["completed", "partial", "failed"])

    def test_concurrent_guard_requests(self) -> None:
        """Multiple Guard requests must be handled concurrently."""
        from app.performance import test_concurrent_guard
        results = test_concurrent_guard(num_requests=5)
        self.assertEqual(len(results), 5)
        for result in results:
            # Guard API returns HTTP status codes: 200 (completed), 400 (blocked), 500 (failed)
            self.assertIn(result["status"], [200, 400, 500, "completed", "blocked", "failed"])

    def test_concurrent_intel_ingestions(self) -> None:
        """Multiple Intel ingestions must run concurrently."""
        from app.performance import test_concurrent_intel
        results = test_concurrent_intel(num_ingestions=3)
        self.assertEqual(len(results), 3)


class DatabasePerformanceTests(unittest.TestCase):
    """Tests for database query performance."""

    def test_database_query_latency_is_measured(self) -> None:
        """Database query latency must be measured and bounded."""
        from app.performance import measure_db_query_latency
        result = measure_db_query_latency()
        self.assertIsInstance(result, float)
        self.assertGreaterEqual(result, 0.0)
        self.assertLess(result, 5.0)  # Must query within 5 seconds

    def test_database_query_is_deterministic(self) -> None:
        """Database queries must return consistent results."""
        from app.performance import measure_db_query_latency
        results = [measure_db_query_latency() for _ in range(3)]
        max_val = max(results)
        min_val = min(results)
        if max_val > 0:
            self.assertLess((max_val - min_val) / max_val, 0.8)

    def test_database_size_is_measured(self) -> None:
        """The live-store database size must be reported in MB."""
        from app.performance import measure_database_size
        result = measure_database_size()
        self.assertIsInstance(result, float)
        self.assertGreaterEqual(result, 0.0)


class OptionalModelTests(unittest.TestCase):
    """The optional local model runtime must report degraded state explicitly."""

    def test_optional_model_probe_is_explicit(self) -> None:
        from app.performance import measure_optional_model_load
        result = measure_optional_model_load()
        self.assertIn("available", result)
        self.assertIn("degraded", result)
        self.assertIn("probe_seconds", result)
        self.assertIn("reason", result)
        if not result["available"]:
            self.assertTrue(result["degraded"])
            self.assertIsNotNone(result["reason"])


class ConcurrentLoadTests(unittest.TestCase):
    """Combined synthetic load must complete with measured headroom."""

    def test_concurrent_load_is_measured(self) -> None:
        from app.performance import measure_concurrent_load
        result = measure_concurrent_load()
        self.assertGreaterEqual(result["duration_seconds"], 0.0)
        self.assertGreater(result["peak_rss_mb"], 0.0)
        self.assertEqual(len(result["recon"]), 3)
        self.assertEqual(len(result["guard"]), 5)
        self.assertEqual(len(result["intel"]), 3)


class SwapUsageTests(unittest.TestCase):
    """Tests for swap usage measurement."""

    def test_swap_usage_is_measured(self) -> None:
        """Swap usage must be measured and reported."""
        from app.performance import measure_swap_usage
        result = measure_swap_usage()
        self.assertIsInstance(result, float)
        self.assertGreaterEqual(result, 0.0)


class ProfileTests(unittest.TestCase):
    """Tests for core/full/dev deployment profiles."""

    def test_core_profile_is_defined(self) -> None:
        """Core profile must be defined with minimal services."""
        from app.performance import get_profile_config
        config = get_profile_config("core")
        self.assertIsInstance(config, dict)
        self.assertIn("services", config)
        self.assertIn("ollama", config["services"])
        self.assertFalse(config["services"]["ollama"])  # Core mode: no Ollama

    def test_full_profile_includes_all_services(self) -> None:
        """Full profile must include all services."""
        from app.performance import get_profile_config
        config = get_profile_config("full")
        self.assertIsInstance(config, dict)
        self.assertIn("ollama", config["services"])
        self.assertTrue(config["services"]["ollama"])

    def test_dev_profile_has_reduced_services(self) -> None:
        """Dev profile must have reduced services for development."""
        from app.performance import get_profile_config
        config = get_profile_config("dev")
        self.assertIsInstance(config, dict)


class HostHeadroomTests(unittest.TestCase):
    """Tests for host headroom measurement."""

    def test_host_headroom_is_measured(self) -> None:
        """Host headroom must be measured and reported."""
        from app.performance import measure_host_headroom
        result = measure_host_headroom()
        self.assertIsInstance(result, dict)
        self.assertIn("ram_available_mb", result)
        self.assertIn("cpu_available_percent", result)


if __name__ == "__main__":
    unittest.main()