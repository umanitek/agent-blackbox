"""The process observer looks by itself, whoever is watching (KI-553, agent-tracking campaign
2026-11-22: a `claude` started with a new CLAUDE_CONFIG_DIR and no hook event was not found).

Contract, with a REAL process: an agent program running with a moved config home and sending no
hook event has its home learned and Blackbox's hooks written there by ONE step of the dashboard's
background look — no live view read, no event — and that look runs at least every 10 seconds.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from plugins.blackbox import agent_hooks
from plugins.blackbox.agent_hooks import tracking
from plugins.blackbox.agent_hooks.instances import store
from plugins.blackbox.dashboard import agent_hooks_routes as routes


@pytest.fixture(autouse=True)
def _fresh(monkeypatch, tmp_path):
    store.reset()
    monkeypatch.setattr(agent_hooks, "_home", lambda: tmp_path)
    monkeypatch.setattr(agent_hooks, "load_blackbox_config", lambda: type("C", (), {"auto_attach": True, "dashboard_port": 9700})())
    tracking._seen.update(at=0.0, table={}, running=[], pids=frozenset(), new_profiles=False)
    yield
    store.reset()


def test_the_background_look_runs_at_least_every_ten_seconds():
    assert routes.OBSERVE_SECONDS <= 10


@pytest.mark.skipif(sys.platform != "darwin", reason="the process observer reads processes on macOS only")
def test_a_running_agents_moved_home_is_learned_and_hooked_in_one_look_with_nobody_watching(tmp_path):
    (tmp_path / ".claude").mkdir()                     # Claude Code is installed here
    sweeper = routes._Sweeper()
    sweeper.step()                                     # the first look sweeps: start from a swept state
    assert sweeper.step() is False                     # nothing new: no sweep
    moved = tmp_path / "work profile"
    moved.mkdir()
    program = tmp_path / "claude"
    program.symlink_to(sys.executable)
    agent = subprocess.Popen([str(program), "-c", "import sys, time; sys.stdout.write('up'); sys.stdout.flush(); time.sleep(60)"],
                             env={**os.environ, "CLAUDE_CONFIG_DIR": str(moved)}, stdout=subprocess.PIPE)
    try:
        assert agent.stdout.read(2) == b"up"
        assert sweeper.step() is True                  # ONE look: the home is learned and hooked
        settings = moved / "settings.json"
        assert json.loads(settings.read_text(encoding="utf-8"))["hooks"]["PreToolUse"]
    finally:
        agent.kill()
        agent.wait()


