"""Sandbox permissions — a profile per project, picked by the launcher at start
(plugins/blackbox/shields/files/sandbox/profiles.py, platform/macos/launchers.py; design "Sandbox
permissions" 2026-11-23, build step 6, local-only).

Contracts (red on the base ed4152ceac: no project profiles, no projects.idx, no lookup):
* every project a rule names for an agent (or for every agent) gets its own profile and a line in
  that agent's index; a project named for another agent does not; stale ones are removed;
* the launcher picks the LONGEST project folder holding the working folder (spaces and all), the
  agent's own profile when none holds it or the index is missing, and nothing at all inside a
  sandbox (``BLACKBOX_AGENT_SANDBOX=1``); a sibling sharing a prefix is not inside;
* on THIS Mac, end to end through the launcher: a folder kept from Claude Code in one project is
  refused there and readable in another.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.shields.files import mode as files_mode, sandbox
from plugins.blackbox.shields.files.sandbox import permissions, profiles
from plugins.blackbox.shields.files.sandbox.platform.macos import profile as macos_profile

REAL = pytest.mark.skipif(sys.platform != "darwin" or not os.access(macos_profile.SANDBOX_EXEC, os.X_OK),
                          reason="a real Seatbelt sandbox needs macOS")


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    real = tmp_path.resolve()
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.setenv("BLACKBOX_HOME", str(real / "bb"))
    for folder in ("work/my shop/api/src", "work/my shopping", "work/other", "clients"):
        (real / folder).mkdir(parents=True)
    (real / "clients" / "deal.txt").write_text("deal", encoding="utf-8")
    return real


@pytest.fixture
def entry(monkeypatch):
    state: dict = {}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)
    return state


def _mode(sandboxed=("claude-code",)):
    return files_mode.build(enabled=True, protected=(), sandboxed=tuple(sandboxed))


def _rules(entry, *projects, agent="claude-code"):
    entry["agent_sandbox"] = {"folders": [{"path": "~/clients", "access": "none", "project": project,
                                           **({"agent": agent} if agent else {})} for project in projects]}


def test_each_named_project_gets_a_profile_and_an_index_line(home, entry):
    _rules(entry, "~/work/my shop", "~/work/my shop/api")
    entry["agent_sandbox"]["permissions"] = [{"permission": "docker", "mode": "allow", "agent": "codex", "project": "~/work/other"}]
    sandbox.sync(_mode(("claude-code", "codex")))
    index = (profiles.projects_dir("claude-code") / profiles.INDEX).read_text(encoding="utf-8").splitlines()
    assert sorted(line.split("\t")[0] for line in index) == [str(home / "work/my shop"), str(home / "work/my shop/api")]
    assert all((profiles.projects_dir("claude-code") / line.split("\t")[1]).is_file() for line in index)
    assert [line.split("\t")[0] for line in (profiles.projects_dir("codex") / profiles.INDEX).read_text(encoding="utf-8").splitlines()] \
        == [str(home / "work/other")]
    entry["agent_sandbox"] = {}
    sandbox.sync(_mode(("claude-code", "codex")))
    assert not profiles.projects_dir("claude-code").exists() and not profiles.projects_dir("codex").exists()


def _launch(home, cwd, extra_env=None) -> str:
    fake = home / "fakebin"
    fake.mkdir(exist_ok=True)
    agent = fake / "claude"
    agent.write_text("#!/bin/sh\necho \"profile=${BLACKBOX_SANDBOX_PROFILE:-none}\"\n"
                     f"cat '{home}/clients/deal.txt' >/dev/null 2>&1; echo read=$?\n", encoding="utf-8")
    agent.chmod(0o755)
    env = {**os.environ, "PATH": f"{sandbox.launcher_dir()}:{fake}:/usr/bin:/bin", **(extra_env or {})}
    env.pop("BLACKBOX_SANDBOX_PROFILE", None)
    if not extra_env:
        env.pop("BLACKBOX_AGENT_SANDBOX", None)
    done = subprocess.run(["claude"], capture_output=True, text=True, timeout=30, env=env, cwd=str(cwd), check=False)
    return done.stdout


@REAL
def test_the_launcher_picks_the_longest_project_holding_the_working_folder(home, entry):
    _rules(entry, "~/work/my shop", "~/work/my shop/api")
    sandbox.sync(_mode())
    deepest = profiles.projects_dir("claude-code") / profiles.project_file(str(home / "work/my shop/api"))
    outer = profiles.projects_dir("claude-code") / profiles.project_file(str(home / "work/my shop"))
    assert f"profile={deepest}" in _launch(home, home / "work/my shop/api/src")
    assert f"profile={outer}" in _launch(home, home / "work/my shop")
    own = sandbox.layout.agent_profile("claude-code")
    assert f"profile={own}" in _launch(home, home / "work/my shopping")       # a sibling sharing a prefix
    assert f"profile={own}" in _launch(home, home / "work/other")
    (profiles.projects_dir("claude-code") / profiles.INDEX).unlink()
    assert f"profile={own}" in _launch(home, home / "work/my shop/api")      # no index: the agent's own
    assert "profile=none" in _launch(home, home / "work/other", {"BLACKBOX_AGENT_SANDBOX": "1"})


@REAL
def test_a_folder_kept_in_one_project_is_refused_there_only(home, entry):
    _rules(entry, "~/work/my shop")
    sandbox.sync(_mode())
    assert "read=1" in _launch(home, home / "work/my shop/api")
    assert "read=0" in _launch(home, home / "work/other")


def test_a_project_named_for_every_agent_reaches_each_one(home):
    settings = permissions.Settings(folders=(permissions.FolderRule("~/clients", permissions.Access.NONE,
                                                                    permissions.Scope(project="~/work/other")),))
    assert profiles.projects_for(settings, "codex") == (str(home / "work/other"),)
    assert profiles.projects_for(settings, "claude-code") == (str(home / "work/other"),)
