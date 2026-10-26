from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.backup_database import BackupError, _copy_offhost


def test_fake_rclone_receives_encrypted_backup_and_manifest(tmp_path, monkeypatch):
    backup = tmp_path / "state.ztb"
    manifest = tmp_path / "state.ztb.manifest.json"
    backup.write_bytes(b"encrypted")
    manifest.write_text("{}", encoding="utf-8")
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        target = tmp_path / "remote" / command[3].rsplit("/", 1)[-1]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(Path(command[2]).read_bytes())
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr("scripts.backup_database.subprocess.run", fake_run)
    copied = _copy_offhost(
        [backup, manifest],
        SimpleNamespace(offhost_dir=None, rclone_remote="remote:zerotrace"),
    )

    assert calls == [
        ["rclone", "copyto", str(backup), "remote:zerotrace/state.ztb"],
        [
            "rclone",
            "copyto",
            str(manifest),
            "remote:zerotrace/state.ztb.manifest.json",
        ],
    ]
    assert copied == [
        "remote:zerotrace/state.ztb",
        "remote:zerotrace/state.ztb.manifest.json",
    ]
    assert (tmp_path / "remote" / "state.ztb").read_bytes() == b"encrypted"


def test_rclone_failure_is_fail_closed(tmp_path, monkeypatch):
    backup = tmp_path / "state.ztb"
    backup.write_bytes(b"encrypted")
    monkeypatch.setattr(
        "scripts.backup_database.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stderr="denied"),
    )
    with pytest.raises(BackupError, match="denied"):
        _copy_offhost(
            [backup],
            SimpleNamespace(offhost_dir=None, rclone_remote="remote:zerotrace"),
        )
