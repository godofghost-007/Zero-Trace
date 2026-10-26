"""Secret environment/file loading."""

from __future__ import annotations

import pytest

from app.settings import env_or_file


def test_env_value_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ZT_SECRET", "from-env")
    assert env_or_file("ZT_SECRET") == "from-env"


def test_file_value_is_loaded(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    secret_file = tmp_path / "secret"
    secret_file.write_text("from-file\n", encoding="utf-8")
    monkeypatch.delenv("ZT_SECRET", raising=False)
    monkeypatch.setenv("ZT_SECRET_FILE", str(secret_file))
    assert env_or_file("ZT_SECRET") == "from-file"


def test_env_and_file_together_are_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    secret_file = tmp_path / "secret"
    secret_file.write_text("from-file", encoding="utf-8")
    monkeypatch.setenv("ZT_SECRET", "from-env")
    monkeypatch.setenv("ZT_SECRET_FILE", str(secret_file))
    with pytest.raises(ValueError, match="cannot both be set"):
        env_or_file("ZT_SECRET")


def test_unreadable_file_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ZT_SECRET", raising=False)
    monkeypatch.setenv("ZT_SECRET_FILE", "Z:/does/not/exist")
    with pytest.raises(ValueError, match="could not be read"):
        env_or_file("ZT_SECRET")


def test_default_is_returned_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ZT_SECRET", raising=False)
    monkeypatch.delenv("ZT_SECRET_FILE", raising=False)
    assert env_or_file("ZT_SECRET", "fallback") == "fallback"
