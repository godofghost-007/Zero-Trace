from __future__ import annotations

from fastapi.testclient import TestClient

from app.live_store import LiveStore
from app.observability import MetricsRegistry, trace_context
from scripts.live_engine import EngineSettings, create_live_engine


def test_trace_context_parses_w3c_traceparent():
    context = trace_context("00-" + "a" * 32 + "-" + "b" * 16 + "-01")
    assert context.trace_id == "a" * 32
    assert context.span_id == "b" * 16
    assert context.sampled is True


def test_metrics_registry_renders_counters_and_histograms():
    metrics = MetricsRegistry()
    metrics.inc(
        "zerotrace_test_total",
        labels={"route": "/health", "status": 200},
    )
    metrics.observe(
        "zerotrace_test_duration_seconds",
        0.02,
        labels={"route": "/health"},
    )
    metrics.set_gauge("zerotrace_test_feed_age_seconds", 42, labels={"feed": "kev"})
    rendered = metrics.render()
    assert 'zerotrace_test_total{route="/health",status="200"} 1' in rendered
    assert 'zerotrace_test_feed_age_seconds{feed="kev"} 42' in rendered
    assert "zerotrace_test_duration_seconds_count" in rendered
    assert 'le="+Inf"' in rendered


def test_live_engine_exposes_request_ids_and_metrics(tmp_path):
    settings = EngineSettings(
        api_key="sk-test-observability-123456",
        auth_secret=b"test-secret-at-least-32-bytes-long!",
    )
    app = create_live_engine(
        settings, store=LiveStore(tmp_path / "observability.sqlite3")
    )
    with TestClient(app) as client:
        response = client.get(
            "/health",
            headers={
                "X-Request-ID": "engine-request-1",
                "traceparent": "00-" + "c" * 32 + "-" + "d" * 16 + "-01",
            },
        )
        assert response.headers["X-Request-ID"] == "engine-request-1"
        assert response.headers["X-Trace-ID"] == "c" * 32
        metrics = client.get("/metrics")
        assert metrics.status_code == 200
        assert "zerotrace_http_requests_total" in metrics.text
