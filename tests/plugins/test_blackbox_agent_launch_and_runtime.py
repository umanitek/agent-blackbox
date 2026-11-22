"""How an agent was started, agents run by a runtime, and closing what ended with nobody
watching (KI-549, agent-tracking campaign 2026-11-22).

Contracts: a hooked session's launch mode is read from its agent process's command line
(``codex exec`` headless, ``claude`` interactive…) when the agent's own events do not say; an
agent run by any spelling of a runtime (``python3.14``, macOS's framework ``Python``, ``node``
with options, ``python -m``) is recognised by its program — the script's real file and the
package it belongs to — and inline code or an unrelated script is not; an instance whose process
left is closed by the observer's own look, without the live view being read.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from plugins.blackbox.agent_hooks import observe, tracking
from plugins.blackbox.agent_hooks.instances import record, store, views
from tests.waiting import wait_until


@pytest.fixture(autouse=True)
def _fresh():
    store.reset()
    tracking._retried.clear()
    tracking._seen.update(at=0.0, table={}, running=[], pids=frozenset(), new_profiles=False)
    yield
    store.reset()


def _table(*rows):
    return {pid: observe.Proc(pid, ppid, 0.0, command) for pid, ppid, command in rows}


@pytest.mark.parametrize("command, launch", [
    ("/opt/homebrew/bin/codex exec say hi", "headless"),
    ("/opt/homebrew/bin/claude -p hello", "headless"),
    ("/opt/homebrew/bin/claude --resume abc", "interactive"),
    ("/opt/homebrew/bin/codex app-server", "sdk"),
    ("/usr/local/bin/node /usr/local/bin/opencode run fix it", "headless"),
    ("/Applications/Cursor.app/Contents/MacOS/Cursor", "ide"),
])
def test_the_launch_mode_is_read_from_the_agents_command_line(command, launch):
    assert observe.launch_of(_table((10, 1, command)), 10) == launch


@pytest.mark.skipif(sys.platform != "darwin", reason="the process observer reads processes on macOS only")
def test_a_hooked_session_takes_its_launch_mode_from_its_real_process(tmp_path):
    program = tmp_path / "codex"
    program.symlink_to(sys.executable)
    ready = tmp_path / "ready"
    agent = subprocess.Popen([str(program), "-c", f"import time; open({str(ready)!r}, 'w').close(); time.sleep(60)", "exec", "hi"])
    try:
        wait_until(ready.exists, timeout=10)
        tracking.track({"agent": "codex", "event": "pre_tool", "tool_name": "terminal", "args": {"command": "ls"}, "pid": agent.pid},
                       "codex:00000000000000aa")
        session = store.get("codex:00000000000000aa")
        assert session.pid == agent.pid and session.launch == "headless"
    finally:
        agent.kill()
        agent.wait()


def test_claude_codes_own_entry_point_wins_over_the_command_line():
    record({"agent": "claude-code", "event": "session_start", "entry": "sdk-ts", "launch": "interactive", "agent_pid": 10}, "claude-code:1")
    assert store.get("claude-code:1").launch == "sdk"


@pytest.mark.parametrize("runtime", [
    "/Library/Frameworks/Python.framework/Versions/3.12/Resources/Python.app/Contents/MacOS/Python",
    "/opt/homebrew/bin/python3.14", "/usr/bin/python3", "/usr/local/bin/node --require ./trace.js", "bun"])
def test_an_agent_run_by_any_runtime_spelling_is_recognised_by_its_program(runtime):
    assert observe.classify(f"{runtime} /Users/me/.local/bin/claude --print hi").id == "claude-code"


def test_an_npm_installed_agent_is_known_by_the_package_its_script_belongs_to(tmp_path):
    script = tmp_path / "lib" / "node_modules" / "@openai" / "codex" / "bin" / "codex.js"
    script.parent.mkdir(parents=True)
    script.write_text("// codex\n", encoding="utf-8")
    link = tmp_path / "bin" / "cx"
    link.parent.mkdir()
    link.symlink_to(script)
    assert observe.classify(f"/usr/local/bin/node {link} exec").id == "codex"
    assert observe.classify(f"/usr/local/bin/node {script}").id == "codex"


@pytest.mark.parametrize("command", [
    "/usr/bin/python3 -c print('claude')", "python3 -m pytest tests/claude", "node -e require('claude')",
    "vim claude.md", "/opt/homebrew/bin/python3.14 /Users/me/tools/notclaude.py", "python3"])
def test_inline_code_or_another_script_is_not_an_agent(command):
    assert observe.classify(command) is None


def test_an_instance_whose_process_left_is_closed_by_the_observers_own_look(monkeypatch):
    record({"agent": "codex", "event": "pre_tool", "tool_name": "terminal", "args": {}, "agent_pid": 999_999}, "codex:2")
    monkeypatch.setattr(observe.platform, "process_table", lambda: "    1     0 Sun Nov 22 06:51:14 2026     /sbin/launchd\n")
    tracking.observe_now()             # the dashboard's background look — the live view is never read
    ended = store.get("codex:2")
    assert ended.ended is not None and ended.end_reason == "process-exit"
    assert views.history()["instances"][0]["key"] == "codex:2"
