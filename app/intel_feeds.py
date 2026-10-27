from dataclasses import dataclass, replace
from datetime import date, datetime, timezone
from email.utils import parsedate_to_datetime
import json
import time
from typing import Callable, Mapping, Protocol
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener
from urllib.parse import urlsplit

from .intel import IntelError, VulnerabilityFact, normalize_cve, normalize_cpe, payload_digest


NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_ENDPOINT = "https://api.first.org/data/v1/epss"
CISA_KEV_ENDPOINT = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_FEED_BYTES = 32 * 1024 * 1024
EPSS_PAGE_SIZE = 10_000
MAX_EPSS_PAGES = 60


class FeedError(ValueError):
    """Raised for bounded transport or malformed feed data."""


@dataclass(frozen=True)
class FeedResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class FeedTransport(Protocol):
    def get(self, endpoint: str) -> FeedResponse:
        ...


def _retry_after_seconds(value: str, *, now: datetime | None = None) -> float | None:
    """Accept both delta-seconds and HTTP-date forms of Retry-After."""

    cleaned = value.strip()
    if not cleaned:
        return None
    try:
        return max(0.0, float(cleaned))
    except ValueError:
        pass
    try:
        parsed = parsedate_to_datetime(cleaned)
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    current = now or datetime.now(timezone.utc)
    return max(0.0, (parsed - current).total_seconds())


class RetryingFeedTransport:
    def __init__(
        self,
        transport: FeedTransport,
        *,
        max_attempts: int = 3,
        max_retry_seconds: float = 60.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not 1 <= max_attempts <= 5 or max_retry_seconds <= 0:
            raise ValueError("retry bounds are invalid")
        self.transport = transport
        self.max_attempts = max_attempts
        self.max_retry_seconds = max_retry_seconds
        self.sleep = sleep

    def get(self, endpoint: str) -> FeedResponse:
        for attempt in range(self.max_attempts):
            try:
                response = self.transport.get(endpoint)
            except FeedError:
                if attempt + 1 == self.max_attempts:
                    raise
                delay = min(self.max_retry_seconds, 2.0 ** attempt)
                self.sleep(delay)
                continue
            if response.status not in {429, 500, 502, 503, 504}:
                return response
            if attempt + 1 == self.max_attempts:
                raise FeedError("feed source remained unavailable")
            retry_after = _retry_after_seconds(
                next(
                    (
                        value
                        for key, value in response.headers.items()
                        if key.lower() == "retry-after"
                    ),
                    "",
                )
            )
            delay = (
                min(self.max_retry_seconds, retry_after)
                if retry_after is not None
                else min(self.max_retry_seconds, 2.0 ** attempt)
            )
            self.sleep(delay)
        raise FeedError("feed source could not be retrieved")


class SyntheticTransport:
    def __init__(self, responses: Mapping[str, bytes], *, max_bytes: int = MAX_FEED_BYTES) -> None:
        self._responses = dict(responses)
        self._max_bytes = max_bytes

    def get(self, endpoint: str) -> FeedResponse:
        base_endpoint = endpoint.split("?", 1)[0]
        if base_endpoint not in {NVD_ENDPOINT, EPSS_ENDPOINT, CISA_KEV_ENDPOINT}:
            raise FeedError("feed source is not allowlisted")
        body = self._responses.get(endpoint, self._responses.get(base_endpoint))
        if body is None or len(body) > self._max_bytes:
            raise FeedError("feed response is unavailable or too large")
        return FeedResponse(200, {"content-type": "application/json"}, body)


class UrllibFeedTransport:
    def __init__(self, *, timeout_seconds: int = 10, max_bytes: int = MAX_FEED_BYTES) -> None:
        if not 1 <= timeout_seconds <= 30:
            raise ValueError("feed timeout is outside the allowed range")
        if not 1024 <= max_bytes <= MAX_FEED_BYTES:
            raise ValueError("feed size limit is outside the allowed range")
        self.timeout_seconds = timeout_seconds
        self.max_bytes = max_bytes
        self._opener = build_opener(_NoRedirectHandler)

    def get(self, endpoint: str) -> FeedResponse:
        base_endpoint = endpoint.split("?", 1)[0]
        if base_endpoint not in {NVD_ENDPOINT, EPSS_ENDPOINT, CISA_KEV_ENDPOINT}:
            raise FeedError("feed source is not allowlisted")
        try:
            with self._opener.open(Request(endpoint, headers={"Accept": "application/json"}), timeout=self.timeout_seconds) as response:
                if response.status != 200:
                    raise FeedError("feed source returned an error")
                body = response.read(self.max_bytes + 1)
                if len(body) > self.max_bytes:
                    raise FeedError("feed response is too large")
                return FeedResponse(response.status, dict(response.headers.items()), body)
        except HTTPError as error:
            # Return retryable status codes to RetryingFeedTransport so it can
            # honor Retry-After. Non-retryable errors are rejected by the feed
            # parser after the bounded body read.
            try:
                body = error.read(self.max_bytes + 1)
            except Exception:
                body = b""
            if len(body) > self.max_bytes:
                raise FeedError("feed response is too large") from error
            headers = dict(error.headers.items()) if error.headers else {}
            return FeedResponse(error.code, headers, body)
        except FeedError:
            raise
        except Exception as error:
            raise FeedError("feed source could not be retrieved") from error


@dataclass(frozen=True)
class EpssRecord:
    cve_id: str
    score: float
    score_date: date


@dataclass(frozen=True)
class KevRecord:
    cve_id: str
    date_added: date
    due_date: date
    known_ransomware_campaign_use: bool


class NvdFeed:
    def parse(self, body: bytes, *, retrieved_at: datetime) -> tuple[VulnerabilityFact, ...]:
        payload = _json_object(body)
        entries = payload.get("vulnerabilities")
        if not isinstance(entries, list) or len(entries) > 20_000:
            raise FeedError("NVD response shape is invalid")
        facts: list[VulnerabilityFact] = []
        for entry in entries:
            try:
                facts.append(_parse_nvd_record(entry, retrieved_at))
            except (KeyError, IndexError, TypeError, ValueError, IntelError) as error:
                raise FeedError("NVD record is invalid") from error
        return tuple(facts)


def _nvd_record_digest(entry: object) -> str:
    """Hash one NVD record, not the page that happened to contain it."""

    canonical = json.dumps(
        entry,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return payload_digest(canonical)


def _parse_nvd_record(
    entry: object,
    retrieved_at: datetime,
) -> VulnerabilityFact:
    if not isinstance(entry, dict):
        raise TypeError("NVD record must be an object")
    cve = entry["cve"]
    cve_id = normalize_cve(cve["id"])
    summary = next(
        item["value"] for item in cve["descriptions"]
        if item.get("lang") == "en"
    )
    configurations = cve.get("configurations", [])
    cpe_names: list[str] = []
    cpe_ranges: list[
        tuple[str, str | None, str | None, str | None, str | None]
    ] = []
    for configuration in configurations:
        if not isinstance(configuration, dict):
            continue
        for node in configuration.get("nodes", []):
            if not isinstance(node, dict):
                continue
            for match in node.get("cpeMatch", []):
                if not isinstance(match, dict) or match.get("vulnerable") is not True:
                    continue
                criteria = match.get("criteria")
                if not isinstance(criteria, str):
                    raise TypeError("CPE criteria must be a string")
                normalized = normalize_cpe(criteria)
                cpe_names.append(normalized)
                bounds = (
                    match.get("versionStartIncluding"),
                    match.get("versionStartExcluding"),
                    match.get("versionEndIncluding"),
                    match.get("versionEndExcluding"),
                )
                if any(value is not None for value in bounds):
                    cpe_ranges.append((normalized, *bounds))
    score = _nvd_score(cve.get("metrics", {}))
    published = _timestamp(cve.get("published"))
    modified = _timestamp(cve.get("lastModified"))
    return VulnerabilityFact(
        cve_id, "nvd", cve_id, modified.isoformat(),
        summary, tuple(dict.fromkeys(cpe_names)),
        score, None, None, published, modified, retrieved_at, 1,
        _nvd_record_digest(entry),
        cpe_ranges=tuple(dict.fromkeys(cpe_ranges)),
    )


def _quarantine_identifier(entry: object) -> str:
    if isinstance(entry, dict):
        cve = entry.get("cve")
        if isinstance(cve, dict) and isinstance(cve.get("id"), str):
            return cve["id"][:64]
    return "unknown"


@dataclass(frozen=True)
class NvdSyncResult:
    facts: tuple[VulnerabilityFact, ...]
    quarantined: tuple[str, ...]
    next_start_index: int
    state: str
    checkpoint: str | None = None
    truncated: bool = False
    total_results: int | None = None
    pages: int = 0


def sync_nvd(
    transport: FeedTransport,
    *,
    page_size: int = 2_000,
    start_index: int = 0,
    last_known_good: tuple[VulnerabilityFact, ...] = (),
    retrieved_at: datetime | None = None,
    max_pages: int = 5,
    sleep: Callable[[float], None] = time.sleep,
) -> NvdSyncResult:
    if not 1 <= page_size <= 2_000 or start_index < 0 or max_pages < 1:
        raise ValueError("NVD pagination bounds are invalid")
    retrieval_time = retrieved_at or datetime.now(timezone.utc)
    facts_by_cve: dict[str, VulnerabilityFact] = {}
    quarantined: list[str] = []
    quarantined_seen: set[str] = set()
    current = start_index
    checkpoint: str | None = None
    total_results: int | None = None
    pages = 0
    truncated = False

    def quarantine(entry: object) -> None:
        identifier = _quarantine_identifier(entry)
        if identifier not in quarantined_seen:
            quarantined_seen.add(identifier)
            quarantined.append(identifier)

    try:
        for _ in range(max_pages):
            endpoint = f"{NVD_ENDPOINT}?startIndex={current}&resultsPerPage={page_size}"
            response = transport.get(endpoint)
            if response.status != 200:
                raise FeedError("NVD feed source returned an error")
            payload = _json_object(response.body)
            entries = payload.get("vulnerabilities")
            total = payload.get("totalResults")
            if isinstance(entries, list) and "totalResults" not in payload:
                for fact in NvdFeed().parse(
                    response.body, retrieved_at=retrieval_time
                ):
                    facts_by_cve[fact.cve_id] = fact
                current += len(entries)
                pages += 1
                checkpoint = str(current)
                return NvdSyncResult(
                    tuple(facts_by_cve.values()),
                    tuple(quarantined),
                    current,
                    "fresh",
                    checkpoint,
                    False,
                    None,
                    pages,
                )
            if not isinstance(entries, list) or not isinstance(total, int):
                raise FeedError("NVD pagination metadata is invalid")
            total_results = total
            for entry in entries:
                try:
                    fact = _parse_nvd_record(entry, retrieval_time)
                except (KeyError, IndexError, TypeError, ValueError, IntelError):
                    quarantine(entry)
                    continue
                facts_by_cve[fact.cve_id] = fact
            current += len(entries)
            pages += 1
            checkpoint = str(current)
            if current >= total or not entries:
                break
            sleep(6.0)
        else:
            truncated = True
        if total_results is not None and current < total_results:
            truncated = True
        return NvdSyncResult(
            tuple(facts_by_cve.values()),
            tuple(quarantined),
            current,
            "truncated" if truncated else "fresh",
            checkpoint,
            truncated,
            total_results,
            pages,
        )
    except FeedError:
        if last_known_good:
            return NvdSyncResult(
                last_known_good,
                tuple(quarantined),
                current,
                "degraded",
                checkpoint,
                False,
                total_results,
                pages,
            )
        raise


def merge_intel_signals(
    facts: tuple[VulnerabilityFact, ...],
    epss_records: tuple["EpssRecord", ...],
    kev_records: tuple["KevRecord", ...],
) -> tuple[VulnerabilityFact, ...]:
    epss = {record.cve_id: record for record in epss_records}
    kev = {record.cve_id: record for record in kev_records}
    return tuple(
        replace(
            fact,
            epss_score=(
                epss[fact.cve_id].score if fact.cve_id in epss else None
            ),
            kev=fact.cve_id in kev if kev else None,
            epss_score_date=(
                epss[fact.cve_id].score_date if fact.cve_id in epss else None
            ),
            kev_due_date=(
                kev[fact.cve_id].due_date if fact.cve_id in kev else None
            ),
        )
        for fact in facts
    )


class EpssFeed:
    def parse(self, body: bytes) -> tuple[EpssRecord, ...]:
        entries = _json_object(body).get("data")
        if not isinstance(entries, list) or len(entries) > 100_000:
            raise FeedError("EPSS response shape is invalid")
        try:
            return tuple(
                EpssRecord(normalize_cve(item["cve"]), _bounded_float(item["epss"], 0.0, 1.0), date.fromisoformat(item["date"]))
                for item in entries
            )
        except (KeyError, TypeError, ValueError, IntelError) as error:
            raise FeedError("EPSS record is invalid") from error


def sync_epss(
    transport: FeedTransport,
    *,
    page_size: int = EPSS_PAGE_SIZE,
    max_pages: int = MAX_EPSS_PAGES,
) -> tuple[EpssRecord, ...]:
    """Read every page of the paged EPSS API with fixed bounds.

    The public EPSS API returns 100 records by default. Production enrichment
    needs the full set, so this helper follows the server's ``total`` while
    capping both page size and page count. A malformed or oversized page fails
    the whole ingestion instead of silently storing a partial score set.
    """

    if not 1 <= page_size <= EPSS_PAGE_SIZE or max_pages < 1:
        raise ValueError("EPSS pagination bounds are invalid")
    records_by_cve: dict[str, EpssRecord] = {}
    offset = 0
    total: int | None = None
    for _ in range(max_pages):
        endpoint = f"{EPSS_ENDPOINT}?limit={page_size}&offset={offset}"
        response = transport.get(endpoint)
        if response.status != 200:
            raise FeedError("EPSS feed source returned an error")
        payload = _json_object(response.body)
        entries = payload.get("data")
        if not isinstance(entries, list) or len(entries) > page_size:
            raise FeedError("EPSS pagination metadata is invalid")
        page_total = payload.get("total")
        if isinstance(page_total, int) and page_total >= 0:
            total = page_total
        for record in EpssFeed().parse(response.body):
            records_by_cve[record.cve_id] = record
        offset += len(entries)
        if not entries:
            break
        if total is not None and offset >= total:
            break
        if len(entries) < page_size:
            break
    else:
        raise FeedError("EPSS pagination exceeded the bounded page count")
    if total is not None and len(records_by_cve) < total:
        raise FeedError("EPSS response was incomplete")
    return tuple(records_by_cve.values())


class KevFeed:
    def parse(self, body: bytes) -> tuple[KevRecord, ...]:
        entries = _json_object(body).get("vulnerabilities")
        if not isinstance(entries, list) or len(entries) > 100_000:
            raise FeedError("KEV response shape is invalid")
        try:
            return tuple(
                KevRecord(
                    normalize_cve(item["cveID"]),
                    date.fromisoformat(item["dateAdded"]),
                    date.fromisoformat(item["dueDate"]),
                    _boolean(item["knownRansomwareCampaignUse"]),
                )
                for item in entries
            )
        except (KeyError, TypeError, ValueError, IntelError) as error:
            raise FeedError("KEV record is invalid") from error


def _json_object(body: bytes) -> dict[str, object]:
    if len(body) > MAX_FEED_BYTES:
        raise FeedError("feed response is too large")
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FeedError("feed response is not valid JSON") from error
    if not isinstance(value, dict):
        raise FeedError("feed response must be an object")
    return value


def _nvd_score(metrics: Mapping[str, object]) -> float | None:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key)
        if isinstance(values, list) and values:
            data = values[0].get("cvssData")
            if isinstance(data, dict) and "baseScore" in data:
                return _bounded_float(data["baseScore"], 0.0, 10.0)
    return None


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp is required")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _bounded_float(value: object, lower: float, upper: float) -> float:
    result = float(value)
    if not lower <= result <= upper:
        raise ValueError("numeric value is out of range")
    return result


def _boolean(value: object) -> bool:
    if value in {"Yes", "Known"}:
        return True
    if value in {"No", "Unknown"}:
        return False
    raise ValueError("boolean value is invalid")


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None
