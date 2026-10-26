"""Fail-closed production configuration for the live engine."""

from __future__ import annotations

import pytest

from scripts.live_engine import DEFAULT_API_KEY, EngineSettings


def _clear(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "ZEROTRACE_ENV",
        "ZEROTRACE_ENGINE_API_KEY",
        "ZEROTRACE_ENGINE_AUTH_SECRET",
        "DATABASE_URL",
        "ZEROTRACE_ENGINE_PORT",
        "ZEROTRACE_TARGET_ALLOWLIST",
        "ZEROTRACE_TARGET_DENYLIST",
        "ZEROTRACE_NMAP_MIN_VERSION",
        "ZEROTRACE_NMAP_EXPECTED_VERSION",
        "ZEROTRACE_SUBFINDER_MIN_VERSION",
        "ZEROTRACE_SUBFINDER_EXPECTED_VERSION",
        "ZEROTRACE_INTEL_SCHEDULE_ENABLED",
        "ZEROTRACE_INTEL_INITIAL_DELAY_SECONDS",
        "ZEROTRACE_SCAN_MAX_QUEUE_DEPTH",
        "ZEROTRACE_SCAN_TARGET_COOLDOWN_SECONDS",
        "ZEROTRACE_SCAN_MAX_CONCURRENT_RUNS",
        "ZEROTRACE_SCAN_MAX_RETRIES",
        "ZEROTRACE_POSTGRES_POOL_MIN_SIZE",
        "ZEROTRACE_POSTGRES_POOL_MAX_SIZE",
        "ZEROTRACE_TLS_PORT",
    ):
        monkeypatch.delenv(name, raising=False)


def test_production_engine_rejects_missing_secrets_and_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear(monkeypatch)
    monkeypatch.setenv("ZEROTRACE_ENV", "production")

    with pytest.raises(ValueError) as error:
        EngineSettings.from_env()

    message = str(error.value)
    assert "ZEROTRACE_ENGINE_API_KEY" in message
    assert "ZEROTRACE_ENGINE_AUTH_SECRET" in message
    assert "DATABASE_URL" in message


def test_production_engine_rejects_demo_default_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear(monkeypatch)
    monkeypatch.setenv("ZEROTRACE_ENV", "production")
    monkeypatch.setenv("ZEROTRACE_ENGINE_API_KEY", DEFAULT_API_KEY)
    monkeypatch.setenv("ZEROTRACE_ENGINE_AUTH_SECRET", "s" * 32)
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@db.example/zt")

    with pytest.raises(ValueError, match="local demo default"):
        EngineSettings.from_env()


def test_production_engine_accepts_postgres_and_explicit_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear(monkeypatch)
    monkeypatch.setenv("ZEROTRACE_ENV", "production")
    monkeypatch.setenv("ZEROTRACE_ENGINE_API_KEY", "k" * 32)
    monkeypatch.setenv("ZEROTRACE_ENGINE_AUTH_SECRET", "s" * 32)
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql+psycopg://user:pass@db.example/zt"
    )

    settings = EngineSettings.from_env()

    assert settings.api_key == "k" * 32
    assert settings.auth_secret == b"s" * 32
    assert settings.database_url == "postgresql://user:pass@db.example/zt"


def test_development_engine_keeps_local_demo_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear(monkeypatch)

    settings = EngineSettings.from_env()

    assert settings.api_key == DEFAULT_API_KEY
    assert len(settings.auth_secret) >= 32
    assert settings.database_url == ""
