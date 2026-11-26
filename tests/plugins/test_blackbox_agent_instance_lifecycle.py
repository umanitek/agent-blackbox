"""Ended means ended, and one call is counted once (KI-551, agent-tracking campaign 2026-11-22).

Contracts: an event that arrives after its session's end event is added to that session's
timeline marked ``late`` and never brings the session back to life; only the agent's own start
event (a resume) reopens it, or — when Blackbox only inferred the end — an event from another
live process of the agent. A repeated event (the same tool-call id in one session) is answered
once and counted once, however late it comes and however busy other sessions are.
"""

from __future__ import annotations

import pytest

from plugins.blackbox import agent_hooks
from plugins.blackbox.agent_hooks import observe, tracking
from plugins.blackbox.agent_hooks.instances import record, store, views
from plugins.blackbox.agent_hooks.protect import events, runner


@pytest.fixture(autouse=True)
def _fresh(monkeypatch, tmp_path):
    store.reset()
    events._answered.clear()
    monkeypatch.setattr(observe.platform, "process_table", lambda: "")
    monkeypatch.setattr(observe.platform, "process_environment", lambda pid: "")
    monkeypatch.setattr(observe.platform, "process_variable", lambda pid, name: "")
    monkeypatch.setattr(agent_hooks, "_home", lambda: tmp_path)
    tracking._seen.update(at=0.0, table={}, running=[], pids=frozenset(), new_profiles=False)
    yield
    store.reset()


def _send(agent, kind, payload):
    return events.record_event(runner.summary(agent, kind, payload))


def _session():
    found, = [item for item in store.all_instances() if item.kind == "session"]
    return found


#: Each platform's end event, and a tool call after it (documented payload fields).
ENDS = [
    ("claude-code", {"session_id": "s1", "cwd": "/w/app", "reason": "prompt_input_exit"},
     {"session_id": "s1", "tool_name": "Bash", "tool_input": {"command": "echo late"}, "tool_use_id": "toolu_late"}),
    ("codex", {"session_id": "s1", "cwd": "/w/app", "reason": "prompt_input_exit"},
     {"session_id": "s1", "tool_name": "shell", "tool_input": {"command": ["bash", "-lc", "echo late"]}, "call_id": "c-late"}),
    ("cursor", {"conversation_id": "s1", "workspace_roots": ["/w/app"], "status": "completed"},
     {"conversation_id": "s1", "tool_name": "Shell", "tool_input": {"command": "echo late"}, "tool_use_id": "t-late"}),
    ("gemini-cli", {"session_id": "s1", "cwd": "/w/app", "reason": "exit"},
     {"session_id": "s1", "tool_name": "run_shell_command", "tool_input": {"command": "echo late"}}),
]


@pytest.mark.parametrize("agent, end, late_call", ENDS)
def test_a_late_event_after_the_end_is_kept_as_late_and_never_reopens_the_session(agent, end, late_call):
    _send(agent, "session_start", {key: value for key, value in end.items() if key not in ("reason", "status")})
    _send(agent, "stop", end)
    ended = _session()
    ended_at, last = ended.ended, ended.last
    assert ended_at is not None
    _send(agent, "post_tool", late_call)
    _send(agent, "pre_tool", late_call)
    session = _session()
    assert session.ended == ended_at and session.end_reason == ended.end_reason
    assert session.last == last <= session.ended
    tree = views.live()
    assert tree["counts"]["live"] == 0
    timeline = store.actions(session.key)
    assert [action.late for action in timeline][-2:] == [True, True]
    assert not any(action.late for action in timeline[:-2])


def test_a_late_sub_agent_event_never_reopens_the_sub_agent_or_makes_a_new_one():
    _send("claude-code", "session_start", {"session_id": "s", "cwd": "/w/app"})
    _send("claude-code", "subagent_start", {"session_id": "s", "agent_id": "a1", "agent_type": "Explore"})
    _send("claude-code", "stop", {"session_id": "s", "reason": "other"})
    _send("claude-code", "pre_tool", {"session_id": "s", "agent_id": "a1", "tool_name": "Bash", "tool_input": {"command": "ls"}})
    _send("claude-code", "pre_tool", {"session_id": "s", "agent_id": "a-new", "tool_name": "Bash", "tool_input": {"command": "ls"}})
    subs = [item for item in store.all_instances() if item.kind == "sub-agent"]
    assert len(subs) == 1 and subs[0].ended is not None and subs[0].end_reason == "session-ended"
    assert all(item.ended is not None for item in store.all_instances())


def test_the_agents_own_start_event_resumes_the_same_session():
    _send("claude-code", "session_start", {"session_id": "s", "cwd": "/w/app", "source": "startup"})
    _send("claude-code", "stop", {"session_id": "s", "reason": "prompt_input_exit"})
    _send("claude-code", "session_start", {"session_id": "s", "cwd": "/w/app", "source": "resume"})
    assert _session().ended is None
    assert len([item for item in store.all_instances() if item.kind == "session"]) == 1


def _event(pid):
    return {"agent": "opencode", "event": "pre_tool", "tool_name": "terminal", "args": {"command": "ls"}, "agent_pid": pid}


def test_an_inferred_end_reopens_only_for_another_live_process_of_the_agent():
    record(_event(500), "opencode:aaaa")
    views.close_stale(alive=[1])
    assert store.get("opencode:aaaa").end_reason == "process-exit"
    record(_event(500), "opencode:aaaa")          # the same, gone process: late
    record(_event(0), "opencode:aaaa")            # no process known: late
    assert store.get("opencode:aaaa").ended is not None
    record(_event(777), "opencode:aaaa")          # `opencode --session` started again in a new process
    again = store.get("opencode:aaaa")
    assert again.ended is None and again.pid == 777


def test_a_repeated_tool_call_is_counted_once_however_late_and_whatever_else_runs(monkeypatch):
    call = {"session_id": "s", "cwd": "/w/app", "tool_name": "Bash", "tool_input": {"command": "echo once"}, "tool_use_id": "toolu_1"}
    first = _send("claude-code", "pre_tool", call)
    for number in range(600):   # 60 other sessions, ten calls each, in between
        _send("codex", "pre_tool", {"session_id": f"o{number % 60}", "tool_name": "shell", "tool_input": {"command": "ls"},
                                    "call_id": f"c{number}"})
    clock = events.time.monotonic() + 3600.0
    monkeypatch.setattr(events.time, "monotonic", lambda: clock)   # and an hour later
    again = _send("claude-code", "pre_tool", call)
    assert again["recorded"] is False and again["decision"] == first["decision"]
    session = store.get(events.session_key("claude-code", "s", "/w/app"))
    assert session.checked == 1 and len(store.actions(session.key)) == 1


def test_the_memory_of_answered_calls_is_bounded():
    for number in range(events.MAX_ANSWERED_PER_SESSION + 40):
        _send("codex", "pre_tool", {"session_id": "busy", "tool_name": "shell", "tool_input": {"command": "ls"}, "call_id": f"c{number}"})
    for number in range(events.MAX_ANSWERED_SESSIONS + 40):
        _send("codex", "turn_end", {"session_id": f"x{number}"})
        _send("codex", "pre_tool", {"session_id": f"x{number}", "tool_name": "shell", "tool_input": {"command": "ls"}, "call_id": "c"})
    assert len(events._answered) <= events.MAX_ANSWERED_SESSIONS
    assert all(len(calls) <= events.MAX_ANSWERED_PER_SESSION for calls in events._answered.values())
