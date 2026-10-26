import sys

import pytest

from app.recon import ReconError, SubprocessRunner, scanner_environment


def test_scanner_environment_excludes_application_secrets(monkeypatch):
    monkeypatch.setenv("ZEROTRACE_ENGINE_API_KEY", "do-not-leak")
    monkeypatch.setenv("DATABASE_URL", "postgresql://do-not-leak")
    monkeypatch.setenv("ZEROTRACE_TEST_SCANNER_VISIBLE", "yes")
    environment = scanner_environment()
    assert "ZEROTRACE_ENGINE_API_KEY" not in environment
    assert "DATABASE_URL" not in environment
    assert "ZEROTRACE_TEST_SCANNER_VISIBLE" not in environment
    assert "PATH" in environment or "SYSTEMROOT" in environment


def test_subprocess_runner_does_not_inherit_secrets(monkeypatch):
    monkeypatch.setenv("ZEROTRACE_ENGINE_API_KEY", "do-not-leak")
    output = SubprocessRunner().run(
        (
            sys.executable,
            "-c",
            "import os; print(os.environ.get('ZEROTRACE_ENGINE_API_KEY', 'missing'))",
        ),
        timeout_seconds=20,
        max_output_bytes=1024,
    )
    assert output.strip() == b"missing"


def test_subprocess_runner_rejects_missing_executable():
    with pytest.raises(ReconError):
        SubprocessRunner().run(
            ("definitely-not-a-real-scanner",),
            timeout_seconds=1,
            max_output_bytes=1024,
        )
