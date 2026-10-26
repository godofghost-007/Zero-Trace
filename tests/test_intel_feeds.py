import json
import unittest
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from unittest.mock import patch

from app.intel import payload_digest
from app.intel_feeds import (
    CISA_KEV_ENDPOINT,
    EPSS_ENDPOINT,
    NVD_ENDPOINT,
    EpssFeed,
    KevFeed,
    NvdFeed,
    FeedError,
    SyntheticTransport,
    _nvd_record_digest,
    _retry_after_seconds,
    sync_nvd,
    merge_intel_signals,
    RetryingFeedTransport,
    UrllibFeedTransport,
    sync_epss,
)


class IntelFeedTests(unittest.TestCase):
    def test_nvd_parser_validates_and_preserves_provenance(self) -> None:
        record = {
            "cve": {
                "id": "CVE-2024-1234",
                "descriptions": [{"lang": "en", "value": "Example"}],
                "published": "2024-01-01T00:00:00.000Z",
                "lastModified": "2024-01-02T00:00:00.000Z",
                "configurations": [{
                    "nodes": [{
                        "cpeMatch": [{
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*",
                            "versionEndExcluding": "2.0.0",
                        }]
                    }]
                }],
                "metrics": {"cvssMetricV31": [{
                    "cvssData": {"baseScore": 8.1}
                }]},
            }
        }
        body = json.dumps({"vulnerabilities": [record]}).encode()
        fact = NvdFeed().parse(body, retrieved_at=datetime(2024, 1, 3, tzinfo=timezone.utc))[0]
        self.assertEqual(fact.cve_id, "CVE-2024-1234")
        self.assertEqual(fact.cvss_score, 8.1)
        self.assertEqual(fact.payload_digest, _nvd_record_digest(record))
        self.assertNotEqual(fact.payload_digest, payload_digest(body))
        self.assertEqual(fact.cpe_ranges, (
            (
                "cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*",
                None,
                None,
                None,
                "2.0.0",
            ),
        ))

    def test_nvd_parser_treats_documented_naive_timestamps_as_utc(self) -> None:
        body = json.dumps({
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-1234",
                    "descriptions": [{"lang": "en", "value": "Example"}],
                    "published": "2024-01-01T00:00:00.000",
                    "lastModified": "2024-01-02T00:00:00.000",
                    "configurations": [],
                    "metrics": {},
                }
            }]
        }).encode()
        fact = NvdFeed().parse(
            body, retrieved_at=datetime(2024, 1, 3, tzinfo=timezone.utc)
        )[0]
        self.assertEqual(fact.modified_at.tzinfo, timezone.utc)

    def test_epss_and_kev_parsers_bound_numeric_and_boolean_fields(self) -> None:
        epss = EpssFeed().parse(
            b'{"data":[{"cve":"CVE-2024-1234","epss":"0.75","date":"2024-01-03"}]}'
        )
        kev = KevFeed().parse(
            b'{"vulnerabilities":[{"cveID":"CVE-2024-1234","dateAdded":"2024-01-03","dueDate":"2024-02-01","knownRansomwareCampaignUse":"Yes"}]}'
        )
        self.assertEqual(epss[0].score, 0.75)
        self.assertTrue(kev[0].known_ransomware_campaign_use)

    def test_epss_sync_follows_pages_and_rejects_incomplete_results(self) -> None:
        first = json.dumps({
            "total": 3,
            "data": [
                {"cve": "CVE-2024-0001", "epss": "0.10", "date": "2024-01-03"},
                {"cve": "CVE-2024-0002", "epss": "0.20", "date": "2024-01-03"},
            ],
        }).encode()
        second = json.dumps({
            "total": 3,
            "data": [
                {"cve": "CVE-2024-0003", "epss": "0.30", "date": "2024-01-03"},
            ],
        }).encode()
        transport = SyntheticTransport({
            f"{EPSS_ENDPOINT}?limit=2&offset=0": first,
            f"{EPSS_ENDPOINT}?limit=2&offset=2": second,
        })

        records = sync_epss(transport, page_size=2)

        self.assertEqual([record.cve_id for record in records], [
            "CVE-2024-0001",
            "CVE-2024-0002",
            "CVE-2024-0003",
        ])
        incomplete = SyntheticTransport({
            f"{EPSS_ENDPOINT}?limit=2&offset=0": json.dumps({
                "total": 5,
                "data": [
                    {"cve": "CVE-2024-0001", "epss": "0.10", "date": "2024-01-03"},
                ],
            }).encode(),
        })
        with self.assertRaises(FeedError):
            sync_epss(incomplete, page_size=2)

    def test_kev_parser_accepts_current_known_unknown_values(self) -> None:
        kev = KevFeed().parse(
            b'{"vulnerabilities":[{"cveID":"CVE-2024-1234","dateAdded":"2024-01-03","dueDate":"2024-02-01","knownRansomwareCampaignUse":"Unknown"}]}'
        )
        self.assertFalse(kev[0].known_ransomware_campaign_use)

    def test_transport_uses_fixed_allowlisted_endpoints_and_body_cap(self) -> None:
        transport = SyntheticTransport({NVD_ENDPOINT: b"{}"})
        self.assertEqual(transport.get(NVD_ENDPOINT).status, 200)
        with self.assertRaises(FeedError):
            transport.get("https://example.invalid/feed")
        with self.assertRaises(FeedError):
            SyntheticTransport({NVD_ENDPOINT: b"x" * 10}, max_bytes=9).get(NVD_ENDPOINT)
        self.assertEqual(EPSS_ENDPOINT.startswith("https://"), True)
        self.assertEqual(CISA_KEV_ENDPOINT.startswith("https://"), True)

    def test_urllib_transport_allows_bounded_nvd_pagination_query(self) -> None:
        with patch("app.intel_feeds.build_opener") as build_opener:
            opener = build_opener.return_value
            response = opener.open.return_value.__enter__.return_value
            response.status = 200
            response.headers.items.return_value = []
            response.read.return_value = b"{}"
            transport = UrllibFeedTransport()
            transport.get(f"{NVD_ENDPOINT}?startIndex=0&resultsPerPage=1")

        opener.open.assert_called_once()

    def test_nvd_sync_paginates_quarantines_bad_rows_and_records_checkpoint(self) -> None:
        first = json.dumps({
            "startIndex": 0,
            "resultsPerPage": 1,
            "totalResults": 2,
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-1234",
                    "descriptions": [{"lang": "en", "value": "Valid"}],
                    "published": "2024-01-01T00:00:00Z",
                    "lastModified": "2024-01-02T00:00:00Z",
                    "configurations": [],
                    "metrics": {},
                }
            }],
        }).encode()
        second = json.dumps({
            "startIndex": 1,
            "resultsPerPage": 1,
            "totalResults": 2,
            "vulnerabilities": [{"cve": {"id": "not-a-cve"}}],
        }).encode()
        transport = SyntheticTransport(
            {NVD_ENDPOINT + "?startIndex=0&resultsPerPage=1": first,
             NVD_ENDPOINT + "?startIndex=1&resultsPerPage=1": second}
        )
        result = sync_nvd(
            transport,
            page_size=1,
            retrieved_at=datetime(2024, 1, 3, tzinfo=timezone.utc),
        )
        self.assertEqual([fact.cve_id for fact in result.facts], ["CVE-2024-1234"])
        self.assertEqual(len(result.quarantined), 1)
        self.assertEqual(result.next_start_index, 2)
        self.assertEqual(result.state, "fresh")

    def test_nvd_sync_marks_truncation_and_deduplicates_records(self) -> None:
        record = {
            "cve": {
                "id": "CVE-2024-1234",
                "descriptions": [{"lang": "en", "value": "Valid"}],
                "published": "2024-01-01T00:00:00Z",
                "lastModified": "2024-01-02T00:00:00Z",
                "configurations": [],
                "metrics": {},
            }
        }
        first = json.dumps({
            "startIndex": 0,
            "resultsPerPage": 1,
            "totalResults": 3,
            "vulnerabilities": [record],
        }).encode()
        second = json.dumps({
            "startIndex": 1,
            "resultsPerPage": 1,
            "totalResults": 3,
            "vulnerabilities": [record],
        }).encode()
        transport = SyntheticTransport({
            NVD_ENDPOINT + "?startIndex=0&resultsPerPage=1": first,
            NVD_ENDPOINT + "?startIndex=1&resultsPerPage=1": second,
        })
        result = sync_nvd(
            transport,
            page_size=1,
            max_pages=2,
            retrieved_at=datetime(2024, 1, 3, tzinfo=timezone.utc),
        )
        self.assertEqual(len(result.facts), 1)
        self.assertTrue(result.truncated)
        self.assertEqual(result.state, "truncated")
        self.assertEqual(result.checkpoint, "2")
        self.assertEqual(result.total_results, 3)

    def test_failed_sync_preserves_last_known_good_facts(self) -> None:
        transport = SyntheticTransport({NVD_ENDPOINT: b"{bad"})
        result = sync_nvd(
            transport,
            last_known_good=(
                NvdFeed().parse(
                    json.dumps({"vulnerabilities": [{
                        "cve": {
                            "id": "CVE-2024-1234",
                            "descriptions": [{"lang": "en", "value": "Valid"}],
                            "published": "2024-01-01T00:00:00Z",
                            "lastModified": "2024-01-02T00:00:00Z",
                            "configurations": [],
                            "metrics": {},
                        }
                    }]}).encode(),
                    retrieved_at=datetime(2024, 1, 3, tzinfo=timezone.utc),
                )
            ),
        )
        self.assertEqual(result.state, "degraded")
        self.assertEqual(len(result.facts), 1)

    def test_epss_and_kev_signals_are_merged_without_losing_unknowns(self) -> None:
        body = json.dumps({"vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-1234",
                "descriptions": [{"lang": "en", "value": "Valid"}],
                "published": "2024-01-01T00:00:00Z",
                "lastModified": "2024-01-02T00:00:00Z",
                "configurations": [],
                "metrics": {},
            }
        }]}).encode()
        fact = NvdFeed().parse(
            body, retrieved_at=datetime(2024, 1, 3, tzinfo=timezone.utc)
        )[0]
        merged = merge_intel_signals(
            (fact,),
            EpssFeed().parse(
                b'{"data":[{"cve":"CVE-2024-1234","epss":"0.75","date":"2024-01-03"}]}'
            ),
            KevFeed().parse(
                b'{"vulnerabilities":[{"cveID":"CVE-2024-1234","dateAdded":"2024-01-03","dueDate":"2024-02-01","knownRansomwareCampaignUse":"No"}]}'
            ),
        )
        self.assertEqual(merged[0].epss_score, 0.75)
        self.assertTrue(merged[0].kev)

    def test_retry_transport_honors_bounded_retry_after(self) -> None:
        class UnstableTransport:
            def __init__(self) -> None:
                self.calls = 0

            def get(self, endpoint: str) -> object:
                self.calls += 1
                if self.calls == 1:
                    return type("Response", (), {
                        "status": 429,
                        "headers": {"Retry-After": "2"},
                        "body": b"",
                    })()
                return type("Response", (), {
                    "status": 200,
                    "headers": {},
                    "body": b"{}",
                })()

        waits: list[float] = []
        transport = UnstableTransport()
        response = RetryingFeedTransport(
            transport, max_attempts=2, sleep=waits.append
        ).get(NVD_ENDPOINT)
        self.assertEqual(response.status, 200)
        self.assertEqual(waits, [2.0])

    def test_retry_after_accepts_http_dates(self) -> None:
        now = datetime(2026, 10, 27, 12, 0, 0, tzinfo=timezone.utc)
        value = format_datetime(now + timedelta(seconds=12), usegmt=True)

        self.assertEqual(_retry_after_seconds(value, now=now), 12.0)
