"""Installer reruns preserve local work and reject commits outside the branch."""

import pytest

from tests.scripts.install.ps1_helpers import _git, _stage

pytestmark = pytest.mark.platforms("windows")


def test_rerun_parks_local_work_and_pins_only_branch_commits(tmp_path):
    origin = tmp_path / "origin"
    origin.mkdir()
    _git(origin, "init", "-q", "-b", "main")
    (origin / "README").write_text("one", encoding="utf-8")
    _git(origin, "add", "README")
    _git(origin, "commit", "-qm", "one")
    home = tmp_path / "home"
    install = home / "hermes-agent"
    assert _stage(origin, home)[1]["ok"] is True
    (install / "README").write_text("local edit", encoding="utf-8")
    (origin / "README").write_text("two", encoding="utf-8")
    _git(origin, "commit", "-qam", "two")
    _git(origin, "checkout", "-qb", "side")
    (origin / "README").write_text("side", encoding="utf-8")
    _git(origin, "commit", "-qam", "side")
    off_branch = _git(origin, "rev-parse", "HEAD")
    _git(origin, "checkout", "-q", "main")

    result, frame = _stage(origin, home)
    assert frame["ok"] is True, result.stdout + result.stderr
    assert (install / "README").read_text(encoding="utf-8-sig") == "two"
    assert "local edit" in _git(install, "stash", "show", "-p", "stash@{0}")

    result, frame = _stage(origin, home, "-Commit", off_branch)
    assert frame["ok"] is False
    assert "is not on branch main" in frame["reason"]
