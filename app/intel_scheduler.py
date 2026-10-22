"""Bounded background scheduling for NVD, EPSS, and CISA KEV ingestion.

The scheduler reuses the same allowlisted ingestion path as the HTTP endpoint.
It never accepts an arbitrary URL, never runs more than one feed at a time, and
persists only the last-run status. A failed feed leaves the previous snapshot in
place and is retried after its interval.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
import threading
from typing import Callable, Mapping

from .intel_api import InMemoryIntelRepository, Ingestion, ingest_source
from .intel_feeds import FeedError, FeedTransport
from .security import AuthorizationError

LOGGER = logging.getLogger("zerotrace.intel_scheduler")

DEFAULT_INTERVALS: Mapping[str, int] = {
    "nvd": 6 * 60 * 60,
    "epss": 12 * 60 * 60,
    "kev": 24 * 60 * 60,
}
MIN_INTERVAL_SECONDS = 60
MAX_INTERVAL_SECONDS = 30 * 24 * 60 * 60


class IntelScheduler:
    def __init__(
        self,
        repository: InMemoryIntelRepository,
        transport: FeedTransport,
        *,
        intervals: Mapping[str, int] | None = None,
        store: object | None = None,
        enabled: bool = True,
        initial_delay_seconds: int = 30,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.repository = repository
        self.transport = transport
        self.store = store
        self.enabled = enabled
        self.initial_delay_seconds = max(1, min(3600, initial_delay_seconds))
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.intervals: dict[str, int] = {}
        for source, interval in (intervals or DEFAULT_INTERVALS).items():
            if source not in DEFAULT_INTERVALS:
                raise ValueError("scheduled feed source is not allowlisted")
            if not MIN_INTERVAL_SECONDS <= int(interval) <= MAX_INTERVAL_SECONDS:
                raise ValueError("scheduled feed interval is outside the allowed range")
            self.intervals[source] = int(interval)
        self._stop = threading.Event()
        self._run_lock = threading.Lock()
        self._status_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._next_due: dict[str, datetime] = {}
        self._state: dict[str, dict[str, object]] = {
            source: {
                "source": source,
                "state": "never",
                "lastStarted": None,
                "lastCompleted": None,
                "lastError": None,
                "lastFactCount": 0,
                "runs": 0,
            }
            for source in self.intervals
        }
        now = self.clock()
        if store is not None and hasattr(store, "load_schedule_state"):
            self._state.update(store.load_schedule_state())
        for source in self.intervals:
            last = self._state[source].get("lastCompleted")
            next_due = now + timedelta(seconds=self.initial_delay_seconds)
            if isinstance(last, str):
                try:
                    parsed = datetime.fromisoformat(last)
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=timezone.utc)
                    next_due = max(next_due, parsed + timedelta(seconds=self.intervals[source]))
                except ValueError:
                    pass
            self._next_due[source] = next_due

    def start(self) -> None:
        if not self.enabled or self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._loop, name="zerotrace-intel-scheduler", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=5)
        self._thread = None

    def _loop(self) -> None:
        while not self._stop.is_set():
            now = self.clock()
            due = [
                source
                for source, next_due in self._next_due.items()
                if next_due <= now
            ]
            if due:
                try:
                    self.run_once(due)
                except Exception:
                    LOGGER.exception("scheduled feed iteration failed")
            self._stop.wait(5)

    def status(self) -> dict[str, object]:
        with self._status_lock:
            feeds = {
                source: {
                    **self._state[source],
                    "nextRun": self._next_due.get(source).isoformat()
                    if self._next_due.get(source)
                    else None,
                    "intervalSeconds": self.intervals[source],
                }
                for source in self.intervals
            }
        return {
            "enabled": self.enabled,
            "running": self._thread is not None and self._thread.is_alive(),
            "initialDelaySeconds": self.initial_delay_seconds,
            "feeds": feeds,
        }

    def run_once(
        self,
        sources: tuple[str, ...] | list[str] | None = None,
        *,
        now: datetime | None = None,
    ) -> list[dict[str, object]]:
        selected = tuple(sources or tuple(self.intervals))
        if any(source not in self.intervals for source in selected):
            raise ValueError("scheduled feed source is not allowlisted")
        if not self._run_lock.acquire(blocking=False):
            return [{
                "source": source,
                "state": "skipped",
                "reason": "a scheduled ingestion is already running",
            } for source in selected]
        results: list[dict[str, object]] = []
        try:
            for source in selected:
                timestamp = now or self.clock()
                started = timestamp.isoformat()
                try:
                    ingestion: Ingestion = ingest_source(
                        self.repository,
                        self.transport,
                        source,
                        idempotency_key=f"scheduled:{source}:{started}",
                        retrieved_at=timestamp,
                    )
                    result = {
                        "source": source,
                        "state": ingestion.state,
                        "factCount": ingestion.fact_count,
                        "error": ingestion.error,
                        "ingestionId": ingestion.ingestion_id,
                    }
                except (AuthorizationError, FeedError, ValueError, OSError) as error:
                    result = {
                        "source": source,
                        "state": "failed",
                        "factCount": 0,
                        "error": str(error)[:300],
                    }
                except Exception:
                    LOGGER.exception("unexpected scheduled ingestion failure")
                    result = {
                        "source": source,
                        "state": "failed",
                        "factCount": 0,
                        "error": "scheduled ingestion failed",
                    }
                self._record(
                    source,
                    started,
                    result,
                    timestamp,
                    completed=self.clock(),
                )
                results.append(result)
        finally:
            self._run_lock.release()
        return results

    def _record(
        self,
        source: str,
        started: str,
        result: dict[str, object],
        timestamp: datetime,
        *,
        completed: datetime | None = None,
    ) -> None:
        finished = completed or timestamp
        with self._status_lock:
            current = self._state[source]
            current["lastStarted"] = started
            current["lastCompleted"] = finished.isoformat()
            current["state"] = result["state"]
            current["lastError"] = result.get("error")
            current["lastFactCount"] = int(result.get("factCount", 0))
            current["runs"] = int(current.get("runs", 0)) + 1
            self._next_due[source] = finished + timedelta(seconds=self.intervals[source])
            state = {**current}
        if self.store is not None and hasattr(self.store, "save_schedule_state"):
            try:
                self.store.save_schedule_state(
                    source,
                    last_started=state["lastStarted"],
                    last_completed=state["lastCompleted"],
                    last_state=str(state["state"]),
                    last_error=state["lastError"],
                    last_fact_count=int(state["lastFactCount"]),
                    runs=int(state["runs"]),
                )
            except Exception:
                LOGGER.exception("could not persist scheduled feed state")
