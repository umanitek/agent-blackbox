"""Sandbox permissions — stopping a program for a sandboxed agent (``stop-processes``, ask by default)
(plugins/blackbox/shields/files/sandbox/brokered/stop.py, platform/macos/processes.py,
agent_hooks/protect/sandbox_errors.py; design "Sandbox permissions" 2026-11-23, build step 14, local-only).

Contracts (red on the base ed4152ceac: a refused kill stayed refused, with no way to stop a stray
dev server or a port holder from inside the sandbox):
* the hook reads the process id from each shell's refused kill;
* never stopped, whatever the permission: process 1, Blackbox itself, macOS's own programs,
  another user's process, another AI agent — and one no longer running;
* allow → Blackbox stops it at once; ask → ONE request naming it, and Blackbox stops it when the
  person allows it; block → nothing;
* a REAL child process this test started is stopped when allowed.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

from plugins.blackbox.agent_hooks.protect import sandbox_errors
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.shields.files import sandbox
from plugins.blackbox.shields.files.sandbox import permissions, platform as sandbox_platform
from plugins.blackbox.shields.files.sandbox.brokered import stop
from plugins.blackbox.shields.files.sandbox.permissions import requests


@pytest.fixture(autouse=True)
def setting(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    state: dict = {}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)
    requests.reset()
    yield state
    requests.reset()


@pytest.mark.parametrize("output", ["kill:1: kill 8240 failed: operation not permitted",
                                    "bash: kill: (8240) - Operation not permitted", "sh: 1: kill: 8240: Operation not permitted"])
def test_the_hook_reads_the_process_id_from_each_shells_refusal(output):
    [found] = sandbox_errors.refusals(output)
    assert (found.kind, found.name) == (sandbox_errors.SIGNAL, "8240")


def _facts(monkeypatch, uid=None, path="/opt/homebrew/bin/node", args="node server.js"):
    facts = sandbox_platform.ProcessFacts(os.getuid() if uid is None else uid, path, args)
    monkeypatch.setattr(sandbox_platform, "describe", lambda pid: facts)
    stopped: list = []
    monkeypatch.setattr(sandbox_platform, "terminate", lambda pid: stopped.append(pid) or True)
    return stopped


@pytest.mark.parametrize("change, why", [
    ({"uid": 0}, "another user"), ({"path": "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"}, "macOS"),
    ({"path": "/usr/libexec/sshd-session"}, "macOS"), ({"args": "claude --resume"}, "another AI agent"),
    ({"path": "/usr/local/bin/codex"}, "another AI agent"),
])
def test_what_is_never_stopped(monkeypatch, change, why):
    _facts(monkeypatch, **change)
    assert why in stop.never(4242)


def test_blackbox_itself_and_process_one_are_never_stopped(monkeypatch, tmp_path):
    _facts(monkeypatch, args=f"python -m plugins.blackbox.dashboard {stop._PLUGIN}/x")
    assert "Blackbox" in stop.never(4242)
    assert stop.never(1) and stop.never(os.getpid())
    monkeypatch.setattr(sandbox_platform, "describe", lambda pid: None)
    assert stop.never(4242) == "it is not running"


def test_allow_stops_at_once_ask_asks_once_and_block_does_nothing(monkeypatch, setting):
    stopped = _facts(monkeypatch)
    setting["agent_sandbox"] = {"permissions": [{"permission": "stop-processes", "mode": "block"}]}
    assert stop.on_refused(4242, "claude-code", "s-1", "/tmp") == "refused" and stopped == []
    setting["agent_sandbox"] = {}
    assert stop.on_refused(4242, "claude-code", "s-1", "/tmp") == "asked"
    [request] = requests.pending()
    assert request.pid == 4242 and "node" in request.what and stopped == []
    permissions.answers.answer({"id": request.id, "choice": "once"}, act=sandbox.act_on)
    assert stopped == [4242]
    setting["agent_sandbox"] = {"permissions": [{"permission": "stop-processes", "mode": "allow"}]}
    assert stop.on_refused(4243, "claude-code", "s-1", "/tmp") == "stopped" and stopped == [4242, 4243]


def test_a_refused_signal_seen_by_the_hook_reaches_the_stop_broker(monkeypatch, setting):
    stopped = _facts(monkeypatch)
    setting["agent_sandbox"] = {"permissions": [{"permission": "stop-processes", "mode": "allow"}]}
    sandbox.on_refusal(sandbox_errors.SIGNAL, "4244", "claude-code", "s-1", "/tmp")
    assert stopped == [4244]


@pytest.mark.skipif(sys.platform != "darwin", reason="the process facts are read with macOS's ps")
def test_a_real_child_is_stopped_when_allowed(setting):
    child = subprocess.Popen(["/bin/sleep", "60"])
    try:
        setting["agent_sandbox"] = {"permissions": [{"permission": "stop-processes", "mode": "allow"}]}
        assert stop.never(child.pid) == "" and stop.on_refused(child.pid, "claude-code", "s-1", "/tmp") == "stopped"
        assert child.wait(timeout=10) != 0
    finally:
        if child.poll() is None:
            child.kill()
