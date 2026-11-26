"""A hook waits only for Blackbox's verdict, never for its bookkeeping (KI-552, agents campaign
scenario 7, 2026-11-22: at about 40 hook events a second p50 was 990 ms, p95 1.72 s and three
calls passed the runner's 2.5 s limit, so the agent went on unchecked).

Measured cause (a dashboard under load, 2026-11-22): the answer waited for the bookkeeping — the
audit append, the per-agent state rewrite under a lock and, worst, the instance tracking, which
re-read EVERY process with ``ps`` (0.7-1.4 s on a busy Mac) behind one lock while each new
session's hook waited — and hooks queued for threads of the pool that also serves long-polls.

Contracts: ``answer_event`` answers while the bookkeeping is held back (here: blocked on
purpose), at N concurrent hook calls p95 stays under :data:`BUDGET_SECONDS` (x4 on CI), and once
the recorder runs every event is recorded, in order, exactly once; the hook's process is read
from its ancestry before the answer, so a hook that has already left still gives its session
the agent's process.
"""

from __future__ import annotations

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from plugins.blackbox import agent_hooks
from plugins.blackbox.agent_hooks import observe, tracking
from plugins.blackbox.agent_hooks.instances import store
from plugins.blackbox.agent_hooks.protect import events, runner

#: p95 of one answer with 40 hook calls in flight in one process (they share one interpreter
#: lock), on the developer's Mac (measured ~0.3 s); CI machines are slower. Before the fix an
#: answer waited for its bookkeeping, which this test holds back: it never came.
BUDGET_SECONDS = 0.6 * (4 if os.environ.get("CI") else 1)
CALLS, IN_FLIGHT = 200, 40


@pytest.fixture(autouse=True)
def _fresh(monkeypatch, tmp_path):
    store.reset()
    events._answered.clear()
    monkeypatch.setattr(observe.platform, "process_table", lambda: "")
    monkeypatch.setattr(agent_hooks, "_home", lambda: tmp_path)
    tracking._seen.update(at=0.0, table={}, running=[], pids=frozenset(), new_profiles=False)
    yield
    agent_hooks.settle(10)
    store.reset()


def _event(number: int) -> dict:
    return runner.summary("claude-code", "pre_tool", {"session_id": f"s{number % 9}", "cwd": "/w/app", "tool_name": "Bash",
                                                      "tool_input": {"command": f"echo {number}"}, "tool_use_id": f"t{number}"})


def test_the_verdict_never_waits_for_the_bookkeeping(monkeypatch):
    held = threading.Event()
    recorded: list[str] = []
    real_track = tracking.track

    def slow_track(event, session, **more):
        held.wait(30)                    # the bookkeeping is stuck until the test lets it go
        recorded.append(str(event.get("tool_call_id")))
        real_track(event, session, **more)
    monkeypatch.setattr(tracking, "track", slow_track)

    def one(number: int) -> float:
        started = time.monotonic()
        answer = agent_hooks.answer_event(_event(number))
        assert answer["decision"] == "allow" and answer["recorded"] is True
        return time.monotonic() - started

    try:
        with ThreadPoolExecutor(IN_FLIGHT) as pool:
            took = sorted(pool.map(one, range(CALLS)))
        assert recorded == []                               # every answer came while nothing was recorded
        p95 = took[int(0.95 * len(took)) - 1]
        assert p95 < BUDGET_SECONDS, f"p95 {p95 * 1000:.0f} ms with {IN_FLIGHT} hook calls in flight"
    finally:
        held.set()
    assert agent_hooks.settle(30)
    assert sorted(recorded) == sorted(f"t{number}" for number in range(CALLS))   # each once, none lost
    assert sum(item.checked for item in store.all_instances() if item.kind == "session") == CALLS


def test_a_repeated_call_is_answered_the_same_before_the_first_is_recorded(monkeypatch):
    held = threading.Event()
    monkeypatch.setattr(tracking, "track", lambda *args, **more: held.wait(30))
    try:
        first = agent_hooks.answer_event(_event(1))
        again = agent_hooks.answer_event(_event(1))
        assert first["recorded"] is True and again == {**first, "recorded": False}
    finally:
        held.set()


def test_the_hooks_process_is_read_before_the_answer_so_a_hook_that_left_still_names_its_agent(monkeypatch):
    """The ancestry is read in judge (while the hook waits), not later by the recorder."""
    chain = {7001: observe.Proc(7001, 7000, 0.0, "/bin/sh -c python3 runner.py"),
             7000: observe.Proc(7000, 1, 0.0, "/opt/homebrew/bin/claude -p fix it")}
    alive = {"hook": True}
    monkeypatch.setattr(observe, "ancestry", lambda pid: dict(chain) if alive["hook"] else {})
    held = threading.Event()
    real_track = tracking.track
    monkeypatch.setattr(tracking, "track", lambda *args, **more: (held.wait(30), real_track(*args, **more)))
    try:
        agent_hooks.answer_event({**_event(5), "pid": 7001})
        alive["hook"] = False                               # the hook has its answer and exits
    finally:
        held.set()
    assert agent_hooks.settle(30)
    session, = [item for item in store.all_instances() if item.kind == "session"]
    assert session.pid == 7000 and session.launch == "headless"
