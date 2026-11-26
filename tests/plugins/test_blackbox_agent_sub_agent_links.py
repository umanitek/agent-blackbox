"""A sub-agent its agent reports as a session of its own is shown under the session that started
it, with what it was asked to do (KI-555 OpenCode's task tool, KI-557 Codex's spawn_agent;
agent-tracking campaign 2026-11-22).

Contracts: OpenCode 1's plugin names a child session's parent (from OpenCode's own session events,
or by asking OpenCode once) with every call; Blackbox records that child as the parent's
sub-agent, with the ``task`` call's description as its task and the call's type. Where nothing
names a parent (OpenCode 2, a Codex ``spawn_agent`` thread reporting under its own id), a new
session whose first event is a tool call, in the same agent process as a session with an
unclaimed spawn call, is that call's sub-agent — oldest spawn first; a session a person starts
(its start event or a prompt first) is never taken for one. A spawn call is shown by its
description, never its prompt.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import textwrap

import pytest

from plugins.blackbox import agent_hooks
from plugins.blackbox.agent_hooks import observe, tracking
from plugins.blackbox.agent_hooks.instances import links, store, views
from plugins.blackbox.agent_hooks.protect import events, own_files, runner
from plugins.blackbox.kernel import agent_hosts as hosts

NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="node is not installed")


@pytest.fixture(autouse=True)
def _fresh(monkeypatch, tmp_path):
    store.reset()
    links.reset()
    events._answered.clear()
    monkeypatch.setattr(observe.platform, "process_table", lambda: "")
    monkeypatch.setattr(observe.platform, "process_environment", lambda pid: "")
    monkeypatch.setattr(observe.platform, "process_variable", lambda pid, name: "")
    monkeypatch.setattr(observe.platform, "process_ancestry", lambda pid, limit: None)   # the stand-in below answers
    monkeypatch.setattr(agent_hooks, "_home", lambda: tmp_path)
    # Every hook here runs in agent process 4242 (the process walk has its own test file).
    monkeypatch.setattr(tracking, "agent_process", lambda key, parent, agent: parent)
    tracking._seen.update(at=0.0, table={}, running=[], pids=frozenset(), new_profiles=False)
    yield
    store.reset()
    links.reset()


def _send(agent, kind, payload, pid=4242):
    return events.record_event({**runner.summary(agent, kind, payload), "pid": pid})


def _sessions():
    return [item for item in store.all_instances() if item.kind == "session"]


def _subs():
    return [item for item in store.all_instances() if item.kind == "sub-agent"]


TASK_CALL = {"description": "Find the failing test", "prompt": "a long private instruction", "subagent_type": "general"}


def test_an_opencode_child_session_named_by_its_parent_is_that_sessions_sub_agent():
    _send("opencode", "pre_tool", {"tool": "task", "args": TASK_CALL, "sessionID": "ses_parent", "callID": "c1", "cwd": "/w/app",
                                   "parents_named": True})
    for number in range(3):
        _send("opencode", "pre_tool", {"tool": "bash", "args": {"command": f"echo {number}"}, "sessionID": "ses_child",
                                       "callID": f"k{number}", "cwd": "/w/app", "parent_session_id": "ses_parent", "parents_named": True})
    session, = _sessions()
    sub, = _subs()
    assert sub.parent == session.key and sub.checked == 3 and session.checked == 4
    assert (sub.task, sub.type) == ("Find the failing test", "general")
    tree = views.live()["products"][0]["profiles"][0]["instances"][0]
    assert [row["task"] for row in tree["sub_agents"]] == ["Find the failing test"]
    task_action = store.actions(session.key)[0]
    assert task_action.what == "Find the failing test" and "private instruction" not in json.dumps(views.detail(session.key))


def test_a_spawned_thread_in_the_same_process_is_linked_oldest_spawn_first():
    _send("codex", "session_start", {"session_id": "thread-main", "cwd": "/w/app", "source": "startup"})
    _send("codex", "pre_tool", {"session_id": "thread-main", "tool_name": "spawn_agent", "call_id": "s1",
                                "tool_input": {"description": "review the diff", "agent_type": "reviewer"}})
    _send("codex", "pre_tool", {"session_id": "thread-main", "tool_name": "spawn_agent", "call_id": "s2",
                                "tool_input": {"description": "write the tests", "agent_type": "worker"}})
    _send("codex", "pre_tool", {"session_id": "thread-a", "tool_name": "shell", "call_id": "a1", "tool_input": {"command": "git diff"}})
    _send("codex", "pre_tool", {"session_id": "thread-b", "tool_name": "shell", "call_id": "b1", "tool_input": {"command": "pytest"}})
    _send("codex", "stop", {"session_id": "thread-a", "reason": "done"})      # a child's own end ends only the sub-agent
    session, = _sessions()
    by_task = {item.task: item for item in _subs()}
    assert set(by_task) == {"review the diff", "write the tests"} and by_task["write the tests"].type == "worker"
    assert all(item.parent == session.key for item in by_task.values())
    assert by_task["review the diff"].ended is not None and session.ended is None


def test_a_session_a_person_starts_in_the_same_process_is_never_taken_for_a_sub_agent():
    _send("codex", "session_start", {"session_id": "thread-main", "cwd": "/w/app"})
    _send("codex", "pre_tool", {"session_id": "thread-main", "tool_name": "spawn_agent", "call_id": "s1",
                                "tool_input": {"description": "review"}})
    _send("codex", "session_start", {"session_id": "thread-person", "cwd": "/w/app", "source": "startup"})
    _send("codex", "prompt", {"session_id": "thread-other", "cwd": "/w/app", "prompt": "hello"})
    _send("codex", "pre_tool", {"session_id": "thread-elsewhere", "tool_name": "shell", "call_id": "e1",
                                "tool_input": {"command": "ls"}}, pid=5555)   # another process
    assert len(_sessions()) == 4 and _subs() == []


def test_hooks_that_name_parents_are_never_linked_by_process():
    _send("opencode", "pre_tool", {"tool": "task", "args": TASK_CALL, "sessionID": "ses_a", "callID": "c1", "parents_named": True})
    _send("opencode", "pre_tool", {"tool": "bash", "args": {"command": "ls"}, "sessionID": "ses_b", "callID": "c2", "parents_named": True})
    assert len(_sessions()) == 2 and _subs() == []


def test_claude_codes_sub_agent_carries_its_task_calls_description():
    _send("claude-code", "session_start", {"session_id": "s", "cwd": "/w/app"})
    _send("claude-code", "pre_tool", {"session_id": "s", "tool_name": "Task", "tool_use_id": "t1", "tool_input": TASK_CALL})
    _send("claude-code", "subagent_start", {"session_id": "s", "agent_id": "a1", "agent_type": "general-purpose"})
    sub, = _subs()
    assert sub.task == "Find the failing test" and sub.type == "general-purpose"


@needs_node
def test_opencode_1s_plugin_names_a_child_sessions_parent(tmp_path):
    stub = tmp_path / "stub.py"
    stub.write_text("import sys\nopen(sys.argv[1], 'a', encoding='utf-8').write(sys.stdin.read() + '\\n')\nprint('{}')\n",
                    encoding="utf-8")
    seen = tmp_path / "seen.jsonl"
    opencode = hosts.BY_ID["opencode"]
    invocations = {event: ([sys.executable, str(stub), str(seen)], "true") for event in opencode.events}
    assert own_files.install(opencode, tmp_path, invocations).ok
    plugin = opencode.config_path(tmp_path)
    script = textwrap.dedent(f"""
        const {{ BlackboxPlugin }} = await import({json.dumps(plugin.as_uri())});
        const client = {{ session: {{ get: async ({{ path }}) => ({{ data: {{ id: path.id, parentID: path.id === "ses_asked" ? "ses_top" : undefined }} }}) }} }};
        const hooks = await BlackboxPlugin({{ directory: "/w/app", client }});
        await hooks.event({{ event: {{ type: "session.created", properties: {{ info: {{ id: "ses_child", parentID: "ses_parent" }} }} }} }});
        await hooks["tool.execute.before"]({{ tool: "bash", sessionID: "ses_child", callID: "c1" }}, {{ args: {{ command: "ls" }} }});
        await hooks["tool.execute.before"]({{ tool: "bash", sessionID: "ses_asked", callID: "c2" }}, {{ args: {{ command: "ls" }} }});
        await hooks["tool.execute.before"]({{ tool: "bash", sessionID: "ses_parent", callID: "c3" }}, {{ args: {{ command: "ls" }} }});
        console.log("{{}}");
    """)
    run = subprocess.run([NODE, "--input-type=module", "-e", script], cwd=tmp_path, capture_output=True, encoding="utf-8",
                         timeout=60, check=False)
    assert run.returncode == 0, run.stderr
    sent = [json.loads(line) for line in seen.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert [(row["sessionID"], row["parent_session_id"], row["callID"]) for row in sent] == [
        ("ses_child", "ses_parent", "c1"), ("ses_asked", "ses_top", "c2"), ("ses_parent", "", "c3")]
    assert all(row["parents_named"] is True for row in sent)
