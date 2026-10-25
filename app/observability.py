"""Small, dependency-free observability primitives.

ZeroTrace deliberately avoids a mandatory APM dependency in the self-hosted
v1. This module provides the pieces the deployment needs without turning the
engine into a monitoring product:

* structured JSON logs with request and trace correlation;
* in-process Prometheus text metrics for HTTP traffic and domain counters;
* W3C ``traceparent`` parsing so a BFF request can be followed into the engine.

The registry is per process. With multiple Gunicorn workers, each worker emits
its own counters; Prometheus must aggregate them with ``sum by (...)``. That is
normal for a multi-process application and is documented in the runbook.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import logging
import math
import re
import threading
import time
from typing import Mapping
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,96}$")
_TRACEPARENT_RE = re.compile(
    r"^(?P<version>[0-9a-f]{2})-(?P<trace>[0-9a-f]{32})-(?P<span>[0-9a-f]{16})-(?P<flags>[0-9a-f]{2})$"
)
_METRIC_NAME_RE = re.compile(r"[^a-zA-Z0-9_:]")
_LABEL_NAME_RE = re.compile(r"[^a-zA-Z0-9_]")
_DEFAULT_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)


def request_id(value: str | None) -> str:
    """Use a bounded caller-supplied ID or create a new one."""

    if value and _REQUEST_ID_RE.fullmatch(value):
        return value
    return str(uuid4())


@dataclass(frozen=True)
class TraceContext:
    trace_id: str
    span_id: str
    sampled: bool


def trace_context(value: str | None) -> TraceContext:
    """Parse a W3C traceparent, falling back to a local trace ID."""

    if value:
        match = _TRACEPARENT_RE.fullmatch(value.strip().lower())
        if match and match.group("version") != "ff":
            return TraceContext(
                trace_id=match.group("trace"),
                span_id=match.group("span"),
                sampled=bool(int(match.group("flags"), 16) & 0x01),
            )
    return TraceContext(trace_id=uuid4().hex, span_id=uuid4().hex[:16], sampled=False)


def _metric_name(value: str) -> str:
    return _METRIC_NAME_RE.sub("_", value)


def _label_name(value: str) -> str:
    return _LABEL_NAME_RE.sub("_", value)


def _label_value(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _labels(values: Mapping[str, object] | None) -> str:
    if not values:
        return ""
    rendered = ",".join(
        f'{_label_name(str(name))}="{_label_value(value)}"'
        for name, value in sorted(values.items())
    )
    return "{" + rendered + "}"


class MetricsRegistry:
    """Thread-safe counters and duration histograms."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = (
            defaultdict(float)
        )
        self._histograms: dict[
            tuple[str, tuple[tuple[str, str], ...]], list[float]
        ] = defaultdict(list)
        self._gauges: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}

    def inc(
        self,
        name: str,
        *,
        value: float = 1.0,
        labels: Mapping[str, object] | None = None,
    ) -> None:
        key = (_metric_name(name), tuple(sorted((str(k), str(v)) for k, v in (labels or {}).items())))
        with self._lock:
            self._counters[key] += value

    def set_gauge(
        self,
        name: str,
        value: float,
        *,
        labels: Mapping[str, object] | None = None,
    ) -> None:
        if not math.isfinite(value):
            return
        key = (
            _metric_name(name),
            tuple(sorted((str(k), str(v)) for k, v in (labels or {}).items())),
        )
        with self._lock:
            self._gauges[key] = value

    def observe(
        self,
        name: str,
        value: float,
        *,
        labels: Mapping[str, object] | None = None,
    ) -> None:
        if not math.isfinite(value) or value < 0:
            return
        key = (_metric_name(name), tuple(sorted((str(k), str(v)) for k, v in (labels or {}).items())))
        with self._lock:
            bucket = self._histograms[key]
            bucket.append(value)
            if len(bucket) > 4096:
                del bucket[: len(bucket) - 4096]

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            counters = {
                name: dict(labels)
                for (name, labels), _value in self._counters.items()
            }
            histograms = {
                name: {"count": len(values), "values": list(values[-16:])}
                for (name, _labels), values in self._histograms.items()
            }
            gauges = {
                name: dict(labels)
                for (name, labels), _value in self._gauges.items()
            }
        return {"counters": counters, "histograms": histograms, "gauges": gauges}

    def render(self) -> str:
        lines: list[str] = []
        with self._lock:
            for (name, labels), value in sorted(self._counters.items()):
                lines.append(f"{name}{_labels(dict(labels))} {value:g}")
            for (name, labels), value in sorted(self._gauges.items()):
                lines.append(f"{name}{_labels(dict(labels))} {value:g}")
            for (name, labels), values in sorted(self._histograms.items()):
                if not values:
                    continue
                label_dict = dict(labels)
                count = len(values)
                total = sum(values)
                lines.append(f"{name}_count{_labels(label_dict)} {count}")
                lines.append(f"{name}_sum{_labels(label_dict)} {total:g}")
                for bucket in _DEFAULT_BUCKETS:
                    bucket_count = sum(1 for item in values if item <= bucket)
                    bucket_labels = dict(label_dict)
                    bucket_labels["le"] = str(bucket)
                    lines.append(
                        f"{name}_bucket{_labels(bucket_labels)} {bucket_count}"
                    )
                infinite = dict(label_dict)
                infinite["le"] = "+Inf"
                lines.append(f"{name}_bucket{_labels(infinite)} {count}")
        return "\n".join(lines) + ("\n" if lines else "")


class JsonFormatter(logging.Formatter):
    """Render one JSON object per log record."""

    _EXTRA_FIELDS = (
        "event",
        "request_id",
        "trace_id",
        "span_id",
        "service",
        "method",
        "path",
        "status",
        "duration_ms",
        "client",
    )

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "time": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for field in self._EXTRA_FIELDS:
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, separators=(",", ":"), default=str)


def install_fastapi_observability(
    app: FastAPI,
    *,
    service: str,
    registry: MetricsRegistry | None = None,
) -> MetricsRegistry:
    """Attach request IDs, JSON access logs, metrics, and a /metrics route."""

    metrics = registry or MetricsRegistry()

    @app.middleware("http")
    async def request_observability(request: Request, call_next):
        rid = request_id(request.headers.get("X-Request-ID"))
        context = trace_context(request.headers.get("traceparent"))
        started = time.perf_counter()
        request.state.request_id = rid
        request.state.trace_id = context.trace_id
        request.state.span_id = context.span_id
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
        except Exception:
            metrics.inc(
                "zerotrace_http_requests_total",
                labels={"service": service, "method": request.method, "route": "unmatched", "status": 500},
            )
            raise
        finally:
            duration = time.perf_counter() - started
            route = getattr(request.scope.get("route"), "path", None) or "unmatched"
            metrics.inc(
                "zerotrace_http_requests_total",
                labels={
                    "service": service,
                    "method": request.method,
                    "route": route,
                    "status": status,
                },
            )
            metrics.observe(
                "zerotrace_http_request_duration_seconds",
                duration,
                labels={"service": service, "method": request.method, "route": route},
            )
            logging.getLogger("zerotrace.http").info(
                "request_completed",
                extra={
                    "event": "request_completed",
                    "service": service,
                    "request_id": rid,
                    "trace_id": context.trace_id,
                    "span_id": context.span_id,
                    "method": request.method,
                    "path": route,
                    "status": status,
                    "duration_ms": round(duration * 1000, 2),
                },
            )
        response.headers["X-Request-ID"] = rid
        response.headers["X-Trace-ID"] = context.trace_id
        return response

    @app.get("/metrics", include_in_schema=False)
    async def metrics_endpoint() -> PlainTextResponse:
        return PlainTextResponse(
            metrics.render(), media_type="text/plain; version=0.0.4"
        )

    app.state.metrics = metrics
    return metrics


def configure_json_logging(level: str = "INFO", *, json_format: bool = False) -> None:
    """Configure root logging once; JSON is opt-in for local readability."""

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    if json_format:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        root.handlers[:] = [handler]
    elif not root.handlers:
        logging.basicConfig(
            level=getattr(logging, level.upper(), logging.INFO),
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )
