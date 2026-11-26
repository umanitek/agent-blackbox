"""A session learns its agent process from the hook's own ancestry (KI-548, agent-tracking
campaign 2026-11-22: many sessions had no process, so they could not end when it exited).

Contract, on a REAL process tree: an agent program starts a short-lived shell for one hook, the
shell runs the hook; the session gets the agent's pid even though the reused process list was read
before the shell existed. A session whose ancestry holds no agent stays without a process and
does not read the process list again on every event.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from plugins.blackbox.agent_hooks import observe, tracking
from plugins.blackbox.agent_hooks.instances import store, views
from tests.waiting import wait_until

macos_only = pytest.mark.skipif(sys.platform != "darwin", reason="the process observer reads processes on macOS only")


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    store.reset()
    getattr(tracking, "_retried", {}).clear()
    tracking._seen.update(at=0.0, table={}, running=[], pids=frozenset(), new_profiles=False)
    yield
    store.reset()


def _agent_tree(tmp_path: Path, program: str):
    """``<program>`` (a Python under that name) → ``/bin/sh -c`` → a hook process that writes its
    parent's pid (the shell's) and waits until it is told to leave. Returns (agent process, the
    hook's parent pid, the file that lets the hook leave)."""
    agent = tmp_path / program
    agent.symlink_to(sys.executable)
    ready, leave = tmp_path / "ready", tmp_path / "leave"
    hook = (f"import os, time\nopen({str(ready)!r}, 'w', encoding='utf-8').write(str(os.getppid()))\n"
            f"while not os.path.exists({str(leave)!r}): time.sleep(0.02)\n")
    script = textwrap.dedent(f"""
        import subprocess, sys
        subprocess.run(["/bin/sh", "-c", {f'{sys.executable} -c "$0"; true'!r}, {hook!r}])
    """)
    process = subprocess.Popen([str(agent), "-c", script])
    wait_until(lambda: ready.exists() and ready.read_text(encoding="utf-8").strip(), timeout=10)
    return process, int(ready.read_text(encoding="utf-8")), leave


@macos_only
def test_a_hook_run_by_a_short_lived_shell_finds_its_agent_process(tmp_path, monkeypatch):
    monkeypatch.setattr(tracking, "TABLE_SECONDS", 3600.0)   # the reused list is older than the shell
    tracking._snapshot()
    process, shell, leave = _agent_tree(tmp_path, "claude")
    try:
        assert shell != process.pid
        tracking.track({"agent": "claude-code", "event": "pre_tool", "tool_name": "terminal", "args": {"command": "ls"},
                        "pid": shell}, "claude-code:0000000000000001")
        assert store.get("claude-code:0000000000000001").pid == process.pid
    finally:
        leave.write_text("", encoding="utf-8")
        process.wait(timeout=10)
    table = observe.read_table()
    assert views.close_stale(table.keys()) == 1
    assert store.get("claude-code:0000000000000001").end_reason == "process-exit"


@macos_only
def test_a_hook_with_no_agent_above_it_stays_without_a_process_and_is_not_retried_every_event(tmp_path, monkeypatch):
    process, shell, leave = _agent_tree(tmp_path, "not-an-agent")
    reads = []
    real = observe.read_table
    monkeypatch.setattr(observe, "read_table", lambda: reads.append(1) or real())
    try:
        for _ in range(5):
            tracking.track({"agent": "codex", "event": "pre_tool", "tool_name": "terminal", "args": {"command": "ls"},
                            "pid": shell}, "codex:0000000000000002")
        assert store.get("codex:0000000000000002").pid == 0
        assert len(reads) <= 2
    finally:
        leave.write_text("", encoding="utf-8")
        process.wait(timeout=10)


def test_an_agent_started_by_another_run_of_the_same_agent_is_its_own_process():
    """A Claude Code session that runs ``claude -p`` as a tool: the inner run's hook belongs to the
    inner process, not to the outer session."""
    rows = [(100, 1, "/opt/homebrew/bin/claude"), (200, 100, "/bin/zsh -c claude -p hi"),
            (300, 200, "/opt/homebrew/bin/claude -p hi"), (301, 300, "/opt/homebrew/bin/claude --helper"),
            (400, 301, "/bin/sh -c python3 runner.py")]
    table = {pid: observe.Proc(pid, ppid, 0.0, command) for pid, ppid, command in rows}
    assert observe.agent_of(table, 400, "claude-code") == 300
    assert observe.agent_of(table, 200, "claude-code") == 100
