"""The Hermes agent — Blackbox's own host — is in the instance tree beside the coding agents
(agents campaign, "REAL — the Hermes agent", 2026-11-22: Hermes sessions were guarded by the
plugin's own hooks but did not appear in the live view).

Contracts, driven through the REAL guard hooks Hermes calls: a Hermes session is a "Hermes
agent" instance under its profile (the Hermes home), with its tool calls counted and its
refusals; it ends with ``on_session_end``; a task Hermes delegates is a sub-agent of the
delegating session; each event is recorded once, also across a restart.
"""

from __future__ import annotations

import pytest

from plugins.blackbox.agent_hooks import hermes_sessions, observe, tracking
from plugins.blackbox.agent_hooks.instances import store
from plugins.blackbox.guard import hooks
from plugins.blackbox.kernel import constants


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    store.reset()
    hermes_sessions.reset()
    monkeypatch.setattr(observe.platform, "process_table", lambda: "")
    tracking._seen.update(at=0.0, table={}, running=[], pids=frozenset(), new_profiles=False)
    hermes_sessions.catch_up()   # the dashboard's first look: nothing logged yet
    yield
    store.reset()
    hermes_sessions.reset()


def _hermes_product(tree):
    found = [product for product in tree["products"] if product["id"] == "hermes"]
    return found[0] if found else None


def test_a_hermes_session_is_an_instance_of_the_hermes_agent_with_its_tool_calls():
    hooks.on_session_start(session_id="h-1")
    hooks.on_pre_tool_call(tool_name="terminal", args={"command": "ls"}, session_id="h-1", tool_call_id="c1")
    hooks.on_post_tool_call(tool_name="terminal", args={"command": "ls"}, result="a b", session_id="h-1", tool_call_id="c1")
    hooks.on_pre_tool_call(tool_name="read_file", args={"path": "README.md"}, session_id="h-1", tool_call_id="c2")
    product = _hermes_product(tracking.live())
    assert product is not None and product["name"] == "Hermes agent"
    profile, = product["profiles"]
    assert profile["home"] == str(constants.hermes_home())
    session, = profile["instances"]
    assert session["status"] == "live" and session["checked"] == 2 and session["refused"] == 0
    hooks.on_session_end(session_id="h-1")
    hermes_sessions.catch_up()
    ended, = [item for item in store.all_instances() if item.agent == "hermes"]
    assert ended.ended is not None


def test_a_delegated_task_is_a_sub_agent_of_the_delegating_session():
    hooks.on_session_start(session_id="parent")
    hooks.on_pre_tool_call(tool_name="delegate_task", args={"goal": "review"}, session_id="parent", tool_call_id="d1")
    hooks.on_pre_tool_call(tool_name="terminal", args={"command": "git diff"}, session_id="child", tool_call_id="k1")
    hooks.on_session_end(session_id="child")
    hermes_sessions.catch_up()
    sessions = [item for item in store.all_instances() if item.agent == "hermes" and item.kind == "session"]
    subs = [item for item in store.all_instances() if item.agent == "hermes" and item.kind == "sub-agent"]
    assert len(sessions) == 1 and len(subs) == 1
    assert subs[0].parent == sessions[0].key and subs[0].checked == 1 and subs[0].ended is not None
    assert sessions[0].ended is None and sessions[0].checked == 2   # its own call and its sub-agent's


def test_each_event_is_recorded_once_also_across_a_restart():
    hooks.on_session_start(session_id="h-2")
    hooks.on_pre_tool_call(tool_name="terminal", args={"command": "ls"}, session_id="h-2", tool_call_id="c1")
    assert hermes_sessions.catch_up() == 2 and hermes_sessions.catch_up() == 0
    hermes_sessions.reset()                              # a dashboard restart: the cursor is on disk
    assert hermes_sessions.catch_up() == 0
    session, = [item for item in store.all_instances() if item.agent == "hermes"]
    assert session.checked == 1


def test_another_agents_rows_are_not_the_hermes_agent():
    assert hermes_sessions.apply({"event": "pre_tool_call", "framework": "codex", "detail": {"session_id": "x"}}) is False
    assert hermes_sessions.apply({"event": "api_request", "detail": {"session_id": "x"}}) is False
