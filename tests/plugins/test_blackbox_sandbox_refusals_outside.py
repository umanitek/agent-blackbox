"""Sandbox refusals judged OUTSIDE the sandbox, from what the sandbox itself knows.

The dashboard reads a sandboxed agent's tool output in its own process — outside the sandbox — so
anything it looks up on disk is the outside view (LES-157). Two Linux round L4 findings:

* KI-685 (kernels 7.0 and 6.8, real sandboxed Claude Code and Codex): Docker on "ask" never asked.
  Inside, Docker's socket is the sandbox's mask; the dashboard lstat()ed it outside, where it is the
  live socket. The profile the run's launcher applied (``<file>#<digest>``, sent by the run's own
  hook) is what decides now (``shields.run_hides_socket``, wired by the dashboard).
* KI-687 (kernel 6.8: the sandbox is its own PID namespace): a sandboxed ``kill <pid of the
  person's program>`` answered "No such process", so stop-processes on "ask" never asked. Such a
  kill is now read as an UNSEEN signal: never counted as a refusal, the agent's note is the same
  whether the process exists or not, and the broker ASKS (even on "allow") only for a process of
  the person's that runs outside.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

from plugins.blackbox import agent_hooks, shields
from plugins.blackbox.agent_hooks.protect import events, sandbox_errors, sandbox_run
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.shields.files import mode as files_mode, sandbox
from plugins.blackbox.shields.files.sandbox import permissions, platform as sandbox_platform, profiles
from plugins.blackbox.shields.files.sandbox.brokered import stop
from plugins.blackbox.shields.files.sandbox.permissions import requests

#: Linux round L4, raw/k1-u24: a sandboxed Claude Code's `docker ps`, Docker on "ask".
HIDDEN_WORDS = "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?"
#: Linux round L4 (u22, kernel 6.8): a sandboxed Claude Code's `kill <the person's sleep>`.
UNSEEN_KILLS = ["bash: kill: (4242) - No such process", "kill:1: kill 4242 failed: no such process", "sh: 1: kill: 4242: No such process"]


@pytest.fixture(autouse=True)
def setting(monkeypatch, tmp_path):
    real = tmp_path.resolve()
    (real / ".hermes").mkdir()
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.setenv("HERMES_HOME", str(real / ".hermes"))
    monkeypatch.delenv("BLACKBOX_HOME", raising=False)
    monkeypatch.setattr(sandbox_platform, "startup_places", lambda folder: ([], [], []))
    state: dict = {}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)
    monkeypatch.setattr(sandbox_run, "_judge", [])
    requests.reset()
    yield state
    requests.reset()


def _run_of(agent: str) -> sandbox_errors.SandboxRun:
    path = str(sandbox.layout.agent_profile(agent))
    return sandbox_errors.SandboxRun(profile=f"{path}#{profiles.digest_of(path)}")


@pytest.mark.skipif(sandbox.unavailable() is not None, reason="no agent sandbox on this machine")
def test_a_hidden_docker_socket_is_read_from_the_profile_the_run_started_with(setting):
    setting["agent_sandbox"] = {"permissions": [{"permission": "docker", "mode": "allow", "agent": "codex"}]}
    sandbox.sync(files_mode.build(enabled=True, sandboxed=("claude-code", "codex")))
    agent_hooks.answer_hidden_sockets_with(shields.run_hides_socket)   # as the dashboard wires it
    assert not os.path.exists("/var/run/docker.sock") or not sandbox_errors._is_mask("/var/run/docker.sock"), \
        "outside, the socket is never the mask: the old lstat could not see it"
    found = sandbox_errors.refusals(HIDDEN_WORDS, _run_of("claude-code"))
    assert [each.kind for each in found] == [sandbox_errors.DOCKER]
    assert permissions.refused(found[0].kind, "claude-code", "s-1", "/tmp") is True
    assert [each.permission for each in requests.pending()] == ["docker"]
    # Docker allowed for codex: the same words are an engine that is not started; so is a run whose
    # profile changed since it started (another digest), and one naming a file outside the profiles.
    assert sandbox_errors.refusals(HIDDEN_WORDS, _run_of("codex")) == []
    stale = sandbox_errors.SandboxRun(profile=_run_of("claude-code").profile.rpartition("#")[0] + "#0000")
    assert sandbox_errors.refusals(HIDDEN_WORDS, stale) == []
    assert not shields.run_hides_socket("/etc/passwd#" + profiles.digest_of("/etc/passwd"), "/var/run/docker.sock")


def test_the_hook_event_carries_the_runs_profile_to_the_judge():
    asked: list = []
    agent_hooks.answer_hidden_sockets_with(lambda profile, socket: asked.append((profile, socket)) or True)
    body = {"agent": "claude-code", "event": "post_tool", "session": "s", "cwd": "/tmp", "tool_name": "terminal",
            "args": {"command": "docker ps"}, "text": HIDDEN_WORDS, "sandboxed": True, "sandbox_profile": "/p/claude-code.policy#ab12"}
    answer, _judged = events.judge(body)
    assert asked == [("/p/claude-code.policy#ab12", "/var/run/docker.sock")] and "Docker" in answer.get("note", "")


@pytest.mark.parametrize("output", UNSEEN_KILLS)
def test_a_kill_of_a_process_the_agent_can_not_see_is_an_unseen_signal_never_a_counted_refusal(output):
    [found] = sandbox_errors.refusals(output, sandbox_errors.SandboxRun(pid_namespace=True))
    assert (found.kind, found.name) == (sandbox_errors.UNSEEN_SIGNAL, "4242")
    assert sandbox_errors.counted([found]) == []
    assert "if that process runs outside" in sandbox_errors.note([found])
    assert sandbox_errors.refusals(output) == [], "without its own PID namespace it is just a process that is gone"


def _child() -> subprocess.Popen:
    return subprocess.Popen(["/bin/sleep", "60"])


@pytest.mark.skipif(not sys.platform.startswith(("linux", "darwin")), reason="process facts are read on Linux and macOS")
@pytest.mark.parametrize("mode", ["ask", "allow"])
def test_an_unseen_kill_of_the_persons_program_asks_and_stops_it_only_once_allowed(setting, mode):
    child = _child()
    try:
        setting["agent_sandbox"] = {"permissions": [{"permission": "stop-processes", "mode": mode}]}
        sandbox.on_refusal(sandbox_errors.UNSEEN_SIGNAL, str(child.pid), "claude-code", "s-1", "/tmp")
        [request] = requests.pending()
        assert request.pid == child.pid and request.permission == stop.PERMISSION
        assert child.poll() is None, "never stopped unasked, even on allow"
        permissions.answers.answer({"id": request.id, "choice": "once"}, act=sandbox.act_on)
        assert child.wait(timeout=10) != 0
    finally:
        if child.poll() is None:
            child.kill()


def test_an_unseen_kill_of_nothing_or_on_block_asks_nothing(setting):
    gone = _child()
    gone.kill()
    gone.wait()
    sandbox.on_refusal(sandbox_errors.UNSEEN_SIGNAL, str(gone.pid), "claude-code", "s-1", "/tmp")
    child = _child()
    try:
        setting["agent_sandbox"] = {"permissions": [{"permission": "stop-processes", "mode": "block"}]}
        sandbox.on_refusal(sandbox_errors.UNSEEN_SIGNAL, str(child.pid), "claude-code", "s-1", "/tmp")
        assert requests.pending() == [] and child.poll() is None
    finally:
        child.kill()
