import json
import unittest
from datetime import datetime, timezone

from app.intel_api import InMemoryIntelRepository
from app.intel_feeds import (
    CISA_KEV_ENDPOINT,
    EPSS_ENDPOINT,
    NVD_ENDPOINT,
    SyntheticTransport,
)
from app.intel_scheduler import IntelScheduler


class IntelSchedulerTests(unittest.TestCase):
    def test_scheduled_ingestion_runs_all_allowlisted_feeds(self) -> None:
        transport = SyntheticTransport({
            NVD_ENDPOINT: json.dumps({"vulnerabilities": []}).encode(),
            EPSS_ENDPOINT: json.dumps({
                "data": [{
                    "cve": "CVE-2024-1234",
                    "epss": "0.75",
                    "date": "2024-01-03",
                }]
            }).encode(),
            CISA_KEV_ENDPOINT: json.dumps({
                "vulnerabilities": [{
                    "cveID": "CVE-2024-1234",
                    "dateAdded": "2024-01-03",
                    "dueDate": "2024-02-01",
                    "knownRansomwareCampaignUse": "Yes",
                }]
            }).encode(),
        })
        repository = InMemoryIntelRepository()
        clock = datetime(2024, 1, 4, tzinfo=timezone.utc)
        scheduler = IntelScheduler(
            repository,
            transport,
            intervals={"nvd": 3600, "epss": 3600, "kev": 3600},
            enabled=False,
            initial_delay_seconds=1,
            clock=lambda: clock,
        )

        results = scheduler.run_once(("nvd", "epss", "kev"), now=clock)

        self.assertEqual([item["state"] for item in results], ["completed"] * 3)
        self.assertEqual(len(repository.epss_records), 1)
        self.assertEqual(len(repository.kev_records), 1)
        status = scheduler.status()
        self.assertFalse(status["running"])
        self.assertEqual(status["feeds"]["nvd"]["runs"], 1)
        self.assertEqual(status["feeds"]["nvd"]["lastFactCount"], 0)
        self.assertIsNotNone(status["feeds"]["kev"]["nextRun"])

    def test_failed_scheduled_feed_is_recorded_and_does_not_block_others(self) -> None:
        transport = SyntheticTransport({
            NVD_ENDPOINT: json.dumps({"vulnerabilities": []}).encode(),
        })
        scheduler = IntelScheduler(
            InMemoryIntelRepository(),
            transport,
            intervals={"nvd": 3600, "epss": 3600, "kev": 3600},
            enabled=False,
            initial_delay_seconds=1,
        )
        now = datetime(2024, 1, 4, tzinfo=timezone.utc)
        results = scheduler.run_once(("nvd", "epss"), now=now)

        self.assertEqual(results[0]["state"], "completed")
        self.assertEqual(results[1]["state"], "failed")
        self.assertIn("unavailable", str(results[1]["error"]))
        self.assertEqual(scheduler.status()["feeds"]["epss"]["state"], "failed")

    def test_scheduler_rejects_unknown_source(self) -> None:
        scheduler = IntelScheduler(
            InMemoryIntelRepository(),
            SyntheticTransport({}),
            intervals={"nvd": 3600},
            enabled=False,
        )
        with self.assertRaises(ValueError):
            scheduler.run_once(("unknown",))
