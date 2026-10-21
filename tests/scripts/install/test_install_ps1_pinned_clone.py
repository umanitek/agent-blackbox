"""Pinned clone contracts run independently of other slow PowerShell scenarios."""

import pytest

from tests.scripts.install.ps1_helpers import _clone_argv, _git, _pin_fixture, _stage

pytestmark = pytest.mark.platforms("windows")


def test_pinned_fresh_clone_never_materializes_the_branch_tip(tmp_path):
    """A pinned install (the desktop bootstrap passes -Commit) checks out only the pin, as install.sh does."""
    origin, pin, _ = _pin_fixture(tmp_path)
    for name, extra, readme, no_checkout in (("pinned", ("-Commit", pin), "one", True), ("tip", (), "tip", False)):
        home, trace = tmp_path / name, tmp_path / f"{name}.trace"
        result, frame = _stage(origin, home, *extra, GIT_TRACE=str(trace))
        assert frame["ok"] is True, result.stdout + result.stderr
        install = home / "hermes-agent"
        assert (install / "README").read_text(encoding="utf-8-sig") == readme
        assert _git(install, "status", "--porcelain") == ""
        assert ("--no-checkout" in _clone_argv(trace)) is no_checkout
    assert _git(tmp_path / "pinned" / "hermes-agent", "rev-parse", "HEAD") == pin


def test_pinned_fresh_clone_publishes_nothing_when_the_pin_is_refused(tmp_path):
    origin, _, off_branch = _pin_fixture(tmp_path)
    home = tmp_path / "home"
    _, frame = _stage(origin, home, "-Commit", off_branch)
    assert frame["ok"] is False
    assert "is not on branch main" in frame["reason"]
    assert not (home / "hermes-agent").exists()
    assert not list(home.glob(".hermes-clone-*"))
