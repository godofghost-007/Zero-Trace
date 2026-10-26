from pathlib import Path

import pytest

from backend.env import env_or_file


def test_bff_env_file_is_loaded(monkeypatch, tmp_path: Path) -> None:
    secret = tmp_path / "secret"
    secret.write_text("from-file\n", encoding="utf-8")
    monkeypatch.delenv("ZT_SECRET", raising=False)
    monkeypatch.setenv("ZT_SECRET_FILE", str(secret))
    assert env_or_file("ZT_SECRET") == "from-file"


def test_bff_env_and_file_together_are_rejected(
    monkeypatch, tmp_path: Path
) -> None:
    secret = tmp_path / "secret"
    secret.write_text("from-file", encoding="utf-8")
    monkeypatch.setenv("ZT_SECRET", "from-env")
    monkeypatch.setenv("ZT_SECRET_FILE", str(secret))
    with pytest.raises(ValueError, match="cannot both be set"):
        env_or_file("ZT_SECRET")
