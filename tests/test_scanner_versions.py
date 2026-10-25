from __future__ import annotations

import pytest

from app.scanner_versions import (
    ScannerRequirement,
    ScannerVersionError,
    parse_version,
)
from scripts import live_engine


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Nmap version 7.94 ( https://nmap.org )", (7, 94, 0)),
        ("subfinder version v2.6.7", (2, 6, 7)),
        ("Current Version: v2.6.0", (2, 6, 0)),
        ("v1.2", (1, 2, 0)),
        ("no version here", None),
        (None, None),
    ],
)
def test_parse_version(raw, expected):
    assert parse_version(raw) == expected


def test_missing_scanner_is_degraded():
    requirement = ScannerRequirement("nmap", minimum="7.80")
    result = requirement.evaluate(available=False, version_output=None)
    assert result["status"] == "missing"
    assert result["compatible"] is False


def test_below_minimum_scanner_is_degraded():
    requirement = ScannerRequirement("nmap", minimum="7.80")
    result = requirement.evaluate(
        available=True, version_output="Nmap version 7.70"
    )
    assert result["status"] == "below_minimum"
    assert result["compatible"] is False
    assert result["detectedVersion"] == "7.70.0"


def test_compatible_scanner_is_ok():
    requirement = ScannerRequirement("subfinder", minimum="2.6.0")
    result = requirement.evaluate(
        available=True, version_output="subfinder version v2.6.7"
    )
    assert result["status"] == "ok"
    assert result["compatible"] is True
    assert result["requiredMinimum"] == "2.6.0"


def test_exact_pin_rejects_a_newer_build():
    requirement = ScannerRequirement(
        "subfinder", minimum="2.6.0", expected="2.6.7"
    )
    result = requirement.evaluate(
        available=True, version_output="subfinder version v2.6.8"
    )
    assert result["status"] == "unexpected_version"
    assert result["compatible"] is False


def test_unparseable_version_is_degraded():
    requirement = ScannerRequirement("nmap", minimum="7.80")
    result = requirement.evaluate(available=True, version_output="unknown")
    assert result["status"] == "unparseable"
    assert result["compatible"] is False


def test_invalid_requirement_is_rejected():
    with pytest.raises(ScannerVersionError):
        ScannerRequirement("nmap", minimum="not-a-version")
    with pytest.raises(ScannerVersionError):
        ScannerRequirement("nmap", minimum="8.0", maximum="7.0")


def test_scanner_inventory_uses_configured_exact_pin(monkeypatch):
    settings = live_engine.EngineSettings(
        api_key="sk-test-scanner-version-123",
        auth_secret=b"test-secret-at-least-32-bytes-long!",
        subfinder_expected_version="2.6.7",
    )

    def fake_which(name):
        return f"C:/tools/{name}.exe"

    def fake_version(executable):
        return "subfinder version v2.6.8" if "subfinder" in executable else "Nmap version 7.94"

    monkeypatch.setattr(live_engine.shutil, "which", fake_which)
    monkeypatch.setattr(live_engine, "_tool_version", fake_version)
    inventory = live_engine._scanner_inventory(settings)
    assert inventory["nmap"]["compatible"] is True
    assert inventory["subfinder"]["status"] == "unexpected_version"
    assert inventory["subfinder"]["compatible"] is False


def test_ready_is_degraded_when_scanner_is_incompatible(monkeypatch, tmp_path):
    from app.live_store import LiveStore
    from fastapi.testclient import TestClient

    settings = live_engine.EngineSettings(
        api_key="sk-test-scanner-ready-123",
        auth_secret=b"test-secret-at-least-32-bytes-long!",
    )

    monkeypatch.setattr(
        live_engine,
        "_scanner_inventory",
        lambda settings=None: {
            "nmap": {"status": "missing", "compatible": False},
            "subfinder": {"status": "ok", "compatible": True},
        },
    )
    app = live_engine.create_live_engine(
        settings, store=LiveStore(tmp_path / "ready.sqlite3")
    )
    with TestClient(app) as client:
        response = client.get("/ready")
    assert response.status_code == 200
    assert response.json()["status"] == "degraded"
    assert response.json()["checks"]["scanners"]["nmap"] == "missing"
