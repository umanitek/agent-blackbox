"""Sandbox permissions — a running agent that still has its old permissions (``restart_needed``)
and Stop (plugins/blackbox/shields/files/sandbox/{__init__,profiles}.py, platform/macos/launchers.py,
agent_hooks/protect/runner.py, agent_hooks/owners.sandboxed_runs; design "Sandbox permissions"
2026-11-23, build step 17, local-only).

A Seatbelt profile is fixed when an agent starts, so a permission changed later reaches it only
after a restart. Contracts (red on the base ed4152ceac: nothing told a running agent's profile
from the current one):
* the launcher hands the agent the profile it chose WITH its digest (``<file>#<digest>``);
* the agent's hook reports it (only from inside the sandbox), and the instance keeps it;
* ``permissions`` lists, after a change, each live agent whose profile's digest changed — never
  reading a file outside Blackbox's profiles folder, whatever the hook reported;
* ``stop-agent`` waits for the person (the approval gate), then stops that agent's own process.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

from plugins.blackbox import approvals
from plugins.blackbox.agent_hooks import observe, owners, tracking
from plugins.blackbox.agent_hooks.instances import store
from plugins.blackbox.agent_hooks.protect import events as hook_events, runner
from plugins.blackbox.dashboard.shields_routes import api_routes
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.kernel import settings as kernel_settings
from plugins.blackbox.shields import RunningAgent
from plugins.blackbox.shields.files import api, mode as files_mode, sandbox
from plugins.blackbox.shields.files.sandbox import profiles
from plugins.blackbox.shields.files.sandbox.platform.macos import launchers, profile as macos_profile

REAL = pytest.mark.skipif(sys.platform != "darwin" or not os.access(macos_profile.SANDBOX_EXEC, os.X_OK),
                          reason="a real Seatbelt sandbox needs macOS")
MAC = pytest.mark.skipif(sys.platform != "darwin", reason="the Seatbelt profile is rendered on macOS")


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    real = tmp_path.resolve()
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.setenv("BLACKBOX_HOME", str(real / "bb"))
    store.reset()
    owners.forget()
    monkeypatch.setattr(observe.platform, "process_table", lambda: "")
    monkeypatch.setattr(observe.platform, "process_ancestry", lambda pid, limit: None)
    tracking._seen.update(at=0.0, table={}, running=[], pids=frozenset(), new_profiles=False)
    yield real
    store.reset()


@pytest.fixture
def entry(monkeypatch):
    state: dict = {"shields": {"file-shield": {"enabled": True, "protected": [], "sandboxed": ["claude-code"]}}}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)
    monkeypatch.setattr(kernel_settings, "_persist", lambda updates: state.update(updates) or True)
    return state


def _sync():
    sandbox.sync(files_mode.build(enabled=True, sandboxed=("claude-code",)))


@REAL
def test_the_launcher_hands_the_agent_its_profile_and_digest(home, entry):
    _sync()
    fake = home / "fakebin"
    fake.mkdir()
    (fake / "claude").write_text('#!/bin/sh\necho "$BLACKBOX_SANDBOX_PROFILE"\n', encoding="utf-8")
    (fake / "claude").chmod(0o755)
    env = {**os.environ, "PATH": f"{sandbox.launcher_dir()}:{fake}:/usr/bin:/bin"}
    env.pop("BLACKBOX_AGENT_SANDBOX", None)
    out = subprocess.run(["claude"], capture_output=True, text=True, timeout=30, env=env, cwd=str(home), check=False).stdout.strip()
    own = str(sandbox.layout.agent_profile("claude-code"))
    assert out == f"{own}#{profiles.digest_of(own)}" and len(profiles.digest_of(own)) == profiles.DIGEST_CHARS


def test_the_hook_reports_it_from_inside_only_and_the_instance_keeps_it(home, monkeypatch):
    monkeypatch.setenv(runner.SANDBOX_PROFILE_ENV, "/x/claude-code.sb#abc")
    monkeypatch.setattr(runner, "sandboxed", lambda: False)
    assert "sandbox_profile" not in runner.summary("claude-code", "session_start", {"session_id": "s"})
    monkeypatch.setattr(runner, "sandboxed", lambda: True)
    body = runner.summary("claude-code", "session_start", {"session_id": "s", "cwd": str(home)})
    assert body["sandbox_profile"] == "/x/claude-code.sb#abc"
    monkeypatch.setattr(hook_events.guard, "tool_call_verdict", lambda **_k: {"findings": [], "decision": ""})
    hook_events.record_event({**body, "agent": "claude-code", "event": "session_start", "session": "s", "cwd": str(home)})
    [run] = owners.sandboxed_runs()
    assert run.profile == "/x/claude-code.sb#abc" and run.agent == "claude-code"
    assert [each.profile for each in api_routes.sandboxed_runs()] == ["/x/claude-code.sb#abc"]


def test_the_launcher_and_the_hook_name_the_same_variable():
    assert f"{runner.SANDBOX_PROFILE_ENV}=" in launchers.pick_profile()


@MAC
def test_a_changed_permission_lists_the_running_agent_and_never_reads_elsewhere(home, entry):
    _sync()
    own = str(sandbox.layout.agent_profile("claude-code"))
    started = RunningAgent("claude-code", "claude-code:aa", 0, f"{own}#{profiles.digest_of(own)}")
    elsewhere = RunningAgent("claude-code", "claude-code:bb", 0, "/etc/passwd#00")
    context = type("Context", (), {"sandboxed_runs": staticmethod(lambda: [started, elsewhere])})()
    assert api.API.reads["permissions"](context, {})["restart_needed"] == []
    api.API.writes["permission-set"](None, {"permission": "docker", "mode": "allow", "agent": "claude-code"})
    [stale] = api.API.reads["permissions"](context, {})["restart_needed"]
    assert stale["instance"] == "claude-code:aa" and stale["name"] == "Claude Code"


@MAC
def test_stop_agent_waits_for_the_person_and_stops_only_that_process(home):
    reasons = approvals.reasons("/api/shields/file-shield/api/stop-agent", {"instance": "claude-code:aa"}, approvals.Current())
    assert reasons == ["Stop Claude Code now, so it starts again with its new sandbox permissions"]
    child = subprocess.Popen(["/bin/sleep", "60"])
    try:
        assert sandbox.stop_run(RunningAgent("claude-code", "claude-code:aa", child.pid, "")) is True
        assert child.wait(timeout=10) != 0
        assert sandbox.stop_run(RunningAgent("claude-code", "claude-code:bb", 1, "")) is False
    finally:
        if child.poll() is None:
            child.kill()
