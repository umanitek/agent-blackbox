"""Git 2.56 moved the x64 runtime from mingw64 to ucrt64."""

from pathlib import Path

import pytest

from hermes_cli import update_cmd_git


@pytest.mark.parametrize("location", ["system", "portable"])
def test_ucrt_git_is_found_and_probe_failures_are_rejected(tmp_path, monkeypatch, location):
    import hermes_constants

    shared = tmp_path / "shared"
    profile = shared / "profiles" / "test"
    monkeypatch.setattr(hermes_constants, "get_default_hermes_root", lambda: shared)
    monkeypatch.setattr(hermes_constants, "get_hermes_home", lambda: profile)
    # Model installation directories as data; no host OS is impersonated.
    system = tmp_path / "system"
    monkeypatch.setattr(update_cmd_git, "Path", lambda value: system if str(value).startswith("C:") else Path(value))
    root = system / "Git" if location == "system" else shared / "git"
    real = root / "ucrt64" / "libexec" / "git-core" / "git.exe"
    real.parent.mkdir(parents=True)
    real.touch()
    monkeypatch.setattr(update_cmd_git, "_probe_fork_bomb", lambda argv: False if argv == [str(real)] else True)
    assert update_cmd_git._locate_real_git() == real

    for rejected in (True, None):
        monkeypatch.setattr(update_cmd_git, "_probe_fork_bomb", lambda _argv, result=rejected: result)
        assert update_cmd_git._locate_real_git() is None
