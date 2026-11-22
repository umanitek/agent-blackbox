"""Every instance of every coding agent is tracked: sessions, the sub-agents they spawn, every
config home (profile) and the agent processes Blackbox has no hook in (Amos, 2026-11-22: "if
Claude spins off 5 agents to do work it should all be tracked by Blackbox as well").

Contracts: each agent's documented sub-agent and session events land on the right instance with a
parent link; a session's totals include its sub-agents'; an instance ends when the agent says so,
when its process leaves or when it goes quiet; ids are hashed and no prompt text is kept; another
config home is found, remembered and hooked; a switch that turns hooks off is reported; an agent
process with no hook shows as unprotected; the live view answers a long-poll when something
changes. Payloads are the examples in each agent's official hook reference (docs/agent-compat/).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time

import pytest
from fastapi.testclient import TestClient

from plugins.blackbox import agent_hooks
from plugins.blackbox.agent_hooks import observe, profiles, tracking
from plugins.blackbox.agent_hooks.instances import store, views
from plugins.blackbox.agent_hooks.instances.model import Running
from plugins.blackbox.agent_hooks.protect import config_edit, events, identity, runner
from plugins.blackbox.dashboard import server
from plugins.blackbox.kernel import agent_hosts as hosts


@pytest.fixture(autouse=True)
def _fresh(monkeypatch, tmp_path):
    store.reset()
    monkeypatch.setattr(observe.platform, "process_table", lambda: "")
    monkeypatch.setattr(observe.platform, "process_environment", lambda pid: "")
    monkeypatch.setattr(observe.platform, "process_variable", lambda pid, name: "")
    monkeypatch.setattr(observe.platform, "process_ancestry", lambda pid, limit: None)   # the faked list is the only one
    monkeypatch.setattr(agent_hooks, "_home", lambda: tmp_path)
    tracking._seen.update(at=0.0, table={}, running=[], pids=frozenset(), new_profiles=False)
    yield
    store.reset()


def _send(agent, kind, payload):
    return events.record_event(runner.summary(agent, kind, payload))


# The sub-agent examples of each agent's hook reference (2026-11-22).
SUBAGENT_STARTS = [
    ("claude-code", {"session_id": "abc123", "cwd": "/Users/x/proj", "hook_event_name": "SubagentStart",
                     "agent_id": "agent-abc123", "agent_type": "Explore"}, "Explore"),
    ("codex", {"session_id": "parent-1", "cwd": "/Users/x/proj", "hook_event_name": "SubagentStart", "turn_id": "t1",
               "agent_id": "sub-9", "agent_type": "reviewer", "model": "gpt-5", "permission_mode": "default"}, "reviewer"),
    ("cursor", {"conversation_id": "conv-456", "hook_event_name": "subagentStart", "subagent_id": "abc-123",
                "subagent_type": "generalPurpose", "task": "Explore the authentication flow", "parent_conversation_id": "conv-456",
                "subagent_model": "claude-sonnet-4-20250514", "is_parallel_worker": False, "workspace_roots": ["/Users/x/proj"]},
     "generalPurpose"),
    ("copilot-cli", {"sessionId": "cop-1", "cwd": "/Users/x/proj", "agentId": "sa-1", "agentType": "explore"}, "explore"),
]


@pytest.mark.parametrize("agent, payload, kind", SUBAGENT_STARTS)
def test_a_sub_agent_is_its_own_instance_under_its_session(agent, payload, kind):
    _send(agent, "session_start", {key: value for key, value in payload.items() if key in ("session_id", "sessionId", "conversation_id", "cwd", "workspace_roots")})
    _send(agent, "subagent_start", payload)
    session, = [item for item in store.all_instances() if item.kind == "session"]
    sub, = [item for item in store.all_instances() if item.kind == "sub-agent"]
    assert sub.parent == session.key and sub.type == kind and sub.agent == agent and sub.ended is None
    assert session.folder == "proj"
    tree = views.live()["products"][0]["profiles"][0]["instances"][0]
    assert [row["key"] for row in tree["sub_agents"]] == [sub.key] and tree["status"] == "live"


def test_five_sub_agents_are_five_instances_and_their_tool_calls_are_theirs():
    _send("claude-code", "session_start", {"session_id": "s", "cwd": "/w/app", "source": "startup", "model": "claude-opus-5-5"})
    for number in range(5):
        _send("claude-code", "subagent_start", {"session_id": "s", "agent_id": f"a{number}", "agent_type": "general-purpose"})
    _send("claude-code", "pre_tool", {"session_id": "s", "agent_id": "a3", "agent_type": "general-purpose", "tool_name": "Bash",
                                      "tool_input": {"command": "ls -la"}, "tool_use_id": "t1"})
    _send("claude-code", "pre_tool", {"session_id": "s", "tool_name": "Read", "tool_input": {"file_path": "/w/app/a.py"}})
    session = next(item for item in store.all_instances() if item.kind == "session")
    subs = sorted((item for item in store.all_instances() if item.kind == "sub-agent"), key=lambda item: item.checked)
    assert len(subs) == 5 and [item.checked for item in subs] == [0, 0, 0, 0, 1]
    assert session.checked == 2 and session.model == "claude-opus-5-5"   # the session's totals include its sub-agents'
    timeline = views.detail(subs[-1].key)["actions"]
    assert [(row["kind"], row["tool"], row["what"], row["verdict"]) for row in timeline][-1] == ("pre_tool", "terminal", "ls -la", "allow")


def test_a_sub_agent_ends_at_its_stop_event_and_a_session_end_closes_what_is_open():
    _send("claude-code", "session_start", {"session_id": "s", "cwd": "/w/app"})
    _send("claude-code", "subagent_start", {"session_id": "s", "agent_id": "def456", "agent_type": "Explore"})
    _send("claude-code", "subagent_start", {"session_id": "s", "agent_id": "ghi789", "agent_type": "Plan"})
    _send("claude-code", "subagent_stop", {"session_id": "s", "hook_event_name": "SubagentStop", "agent_id": "def456",
                                           "agent_type": "Explore", "last_assistant_message": "Analysis complete."})
    by_type = {item.type: item for item in store.all_instances() if item.kind == "sub-agent"}
    assert by_type["Explore"].ended is not None and by_type["Plan"].ended is None
    _send("claude-code", "stop", {"session_id": "s", "hook_event_name": "SessionEnd", "reason": "prompt_input_exit"})
    session = next(item for item in store.all_instances() if item.kind == "session")
    assert session.ended is not None and session.end_reason == "prompt_input_exit"
    assert all(item.ended is not None for item in store.all_instances())
    assert views.history()["instances"][0]["key"] == session.key


def test_cursors_stop_names_only_the_type_and_closes_that_sub_agent():
    _send("cursor", "subagent_start", {"conversation_id": "c", "subagent_id": "abc-123", "subagent_type": "explore"})
    _send("cursor", "subagent_stop", {"conversation_id": "c", "subagent_type": "explore", "status": "completed", "duration_ms": 45000})
    sub, = [item for item in store.all_instances() if item.kind == "sub-agent"]
    assert sub.ended is not None and sub.end_reason == "completed"


def test_no_agent_id_or_prompt_text_is_kept():
    _send("claude-code", "prompt", {"session_id": "secret-session-id", "prompt": "my very private plan", "cwd": "/w/app"})
    _send("claude-code", "subagent_start", {"session_id": "secret-session-id", "agent_id": "agent-private-77", "agent_type": "Explore"})
    store.flush()
    written = "".join(path.read_text(encoding="utf-8", errors="replace") for path in store.folder().rglob("*") if path.is_file())
    assert written and "secret-session-id" not in written and "agent-private-77" not in written and "private plan" not in written


def test_an_instance_ends_when_its_process_leaves_or_it_goes_quiet():
    _send("codex", "session_start", {"session_id": "a", "cwd": "/w/x"})
    _send("codex", "session_start", {"session_id": "b", "cwd": "/w/y"})
    first, second = sorted(store.all_instances(), key=lambda item: item.folder)
    first.pid = 4242
    second.last = time.time() - views.QUIET_SECONDS - 5
    assert views.close_stale(alive=[1, 2, 3]) == 2
    assert (store.get(first.key).end_reason, store.get(second.key).end_reason) == ("process-exit", "quiet")


# ---------------------------------------------------------------- profiles

def test_a_moved_config_home_is_remembered_and_hooked(tmp_path, monkeypatch):
    work = tmp_path / "claude-work"
    work.mkdir()
    (tmp_path / ".claude").mkdir()
    monkeypatch.setattr(agent_hooks, "load_blackbox_config", lambda: type("C", (), {"auto_attach": True, "dashboard_port": 9700})())
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(work))
    body = runner.summary("claude-code", "session_start", {"session_id": "s", "cwd": "/w/app"})
    assert body["profile"] == str(work)
    monkeypatch.delenv("CLAUDE_CONFIG_DIR")
    events.record_event(body)
    assert tracking.new_profiles() is True and tracking.new_profiles() is False
    agent_hooks.sweep()
    claude = hosts.BY_ID["claude-code"]
    variant = profiles.variant(claude, work.resolve(), default=False)
    assert config_edit.installed_commands(variant, tmp_path) and config_edit.installed_commands(claude, tmp_path)
    assert json.loads((work / "settings.json").read_text(encoding="utf-8"))["hooks"]["SubagentStart"]


def test_a_running_agent_names_a_config_home_blackbox_has_not_hooked(tmp_path, monkeypatch):
    other = tmp_path / "codex-alt"
    other.mkdir()
    monkeypatch.setattr(observe.platform, "process_table",
                        lambda: "  501     1 Sun Nov 22 06:51:14 2026     /Users/x/.local/bin/codex exec review\n")
    monkeypatch.setattr(observe.platform, "process_environment", lambda pid: f"codex exec review HOME=/Users/x CODEX_HOME={other} TERM=xterm")
    tracking.live()
    assert tracking.new_profiles() is True
    assert (other.resolve(), False) in profiles.homes(hosts.BY_ID["codex"], tmp_path)


def test_a_running_agents_moved_home_is_read_whole_even_with_a_space_in_it(tmp_path, monkeypatch):
    other = tmp_path / "my profiles" / "claude work"
    other.mkdir(parents=True)
    monkeypatch.setattr(observe.platform, "process_table",
                        lambda: "  777     1 Sun Nov 22 06:51:14 2026     /Users/x/.local/bin/claude\n")
    monkeypatch.setattr(observe.platform, "process_variable", lambda pid, name: str(other) if name == "CLAUDE_CONFIG_DIR" else "")
    tracking.live()
    assert (other.resolve(), False) in profiles.homes(hosts.BY_ID["claude-code"], tmp_path)


@pytest.mark.skipif(sys.platform != "darwin", reason="reads the macOS kernel's record of a process")
def test_macos_gives_a_same_user_programs_variable_and_nothing_for_a_process_it_may_not_read(tmp_path):
    """Measured, not assumed (2026-11-22): a non-Apple program this user started answers with its
    environment; a process that does not exist, or that macOS keeps closed, answers ""."""
    from plugins.blackbox.agent_hooks.observe.platform import macos

    home = str(tmp_path / "with space" / "home")
    child = subprocess.Popen([sys.executable, "-c", "import sys, time; sys.stdout.write('up'); sys.stdout.flush(); time.sleep(30)"],
                             env={**os.environ, "CLAUDE_CONFIG_DIR": home}, stdout=subprocess.PIPE)
    try:
        assert child.stdout.read(2) == b"up"
        assert macos.process_variable(child.pid, "CLAUDE_CONFIG_DIR") == home
        assert macos.process_variable(child.pid, "BLACKBOX_NOT_SET_ANYWHERE") == ""
    finally:
        child.kill()
        child.wait()
    assert macos.process_variable(child.pid, "CLAUDE_CONFIG_DIR") == ""      # gone: nothing, never an error
    assert macos.process_variable(1, "PATH") == ""                           # launchd (root): closed to this user


@pytest.mark.parametrize("agent, relative, text, key", [
    ("claude-code", ".claude/settings.json", '{"disableAllHooks": true}', "disableAllHooks"),
    ("claude-code", ".claude/settings.local.json", '{"disableAllHooks": true}', "disableAllHooks"),
    ("gemini-cli", ".gemini/settings.json", '{"hooksConfig": {"enabled": false}}', "hooksConfig.enabled"),
    ("codex", ".codex/config.toml", "[features]\nhooks = false\n", "features.hooks"),
])
def test_a_switch_that_turns_hooks_off_is_reported(tmp_path, agent, relative, text, key):
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    host = hosts.BY_ID[agent]
    folder, _default = profiles.homes(host, tmp_path)[0]
    found = profiles.problems(host, folder)
    assert [(item.kind, item.file) for item in found] == [("hooks-off", str(path))] and key in found[0].detail


def test_a_project_that_turns_hooks_off_is_reported_and_a_clean_one_is_not(tmp_path):
    project = tmp_path / "proj"
    (project / ".claude").mkdir(parents=True)
    host = hosts.BY_ID["claude-code"]
    assert profiles.problems(host, tmp_path / ".claude", [str(project)]) == []
    (project / ".claude" / "settings.json").write_text('{"disableAllHooks": true}', encoding="utf-8")
    assert [item.file for item in profiles.problems(host, tmp_path / ".claude", [str(project)])] == [str(project / ".claude" / "settings.json")]


def test_gemini_lifecycle_hooks_carry_no_tool_matcher(tmp_path):
    """Gemini CLI compares a lifecycle matcher as an exact string, so ".*" never matched there."""
    gemini = hosts.BY_ID["gemini-cli"]
    config_edit.install(gemini, tmp_path, {event: f"/x/agent-hooks/python runner {event}" for event in gemini.events})
    written = json.loads((tmp_path / ".gemini" / "settings.json").read_text(encoding="utf-8"))["hooks"]
    assert "matcher" not in written["SessionStart"][0] and "matcher" not in written["SessionEnd"][0]
    assert written["BeforeTool"][0]["matcher"] == ".*" and "AfterAgent" in written


# ---------------------------------------------------------------- the read-only observer

PS = """\
  100     1 Sun Nov 22 06:00:00 2026     /sbin/launchd
  501   100 Sun Nov 22 06:51:14 2026     claude --dangerously-skip-permissions --resume 47decf0f
  502   501 Sun Nov 22 06:51:20 2026     /bin/sh -c /Users/x/.hermes/blackbox/agent-hooks/python runner.py claude-code pre_tool
  503   100 Sun Nov 22 06:52:00 2026     claude --bare -p "Summarize README.md"
  504   100 Sun Nov 22 06:52:10 2026     node /opt/homebrew/bin/gemini -p hello
  505   100 Sun Nov 22 06:52:20 2026     vim claude.md
  506   100 Sun Nov 22 06:52:30 2026     cat codex
"""


def test_agent_processes_are_recognised_by_their_program_not_by_a_word(monkeypatch):
    monkeypatch.setattr(observe.platform, "process_table", lambda: PS)
    table = observe.read_table()
    found = {proc.pid: (proc.agent, proc.launch, bool(proc.hooks_skipped)) for proc in observe.running(table)}
    assert found == {501: ("claude-code", "interactive", False), 503: ("claude-code", "headless", True),
                     504: ("gemini-cli", "headless", False)}
    assert observe.agent_of(table, 502, "claude-code") == 501 and observe.agent_of(table, 505, "claude-code") == 0


def test_an_agent_process_with_no_hook_event_shows_as_unprotected(monkeypatch):
    monkeypatch.setattr(observe.platform, "process_table", lambda: PS)
    body = runner.summary("claude-code", "session_start", {"session_id": "s", "cwd": "/w/app"})
    events.record_event({**body, "pid": 502})
    view = tracking.live()
    session = view["products"][0]["profiles"][0]["instances"][0]
    assert session["pid"] == 501 and session["status"] == "live"
    unprotected = {row["pid"]: row for row in view["unprotected"]}
    assert set(unprotected) == {503, 504} and "--bare" in unprotected[503]["reason"]


def test_the_observer_never_starts_anything_but_the_process_list():
    import ast
    import inspect
    from plugins.blackbox.agent_hooks.observe.platform import macos
    calls = [node for node in ast.walk(ast.parse(inspect.getsource(macos))) if isinstance(node, ast.Constant)
             and isinstance(node.value, str) and node.value.startswith("/")]
    assert {node.value for node in calls} == {"/bin/ps"}


# ---------------------------------------------------------------- the API

def _client() -> TestClient:
    client = TestClient(server.create_app(), base_url="http://127.0.0.1")
    client.headers["X-Blackbox-Token"] = client.get("/api/session").json()["token"]
    return client


def test_the_live_view_answers_a_waiting_reader_when_something_changes():
    client = _client()
    first = client.get("/api/agent-instances/live").json()
    assert first["products"] == [] and first["counts"] == {"live": 0, "root": 0, "sub_agents": 0}
    answers = []
    waiter = threading.Thread(target=lambda: answers.append(client.get(f"/api/agent-instances/live?cursor={first['cursor']}&wait=20").json()))
    started = time.monotonic()
    waiter.start()
    _send("gemini-cli", "session_start", {"session_id": "g1", "cwd": "/w/site", "source": "startup"})
    waiter.join(10)
    assert answers and time.monotonic() - started < 5
    assert answers[0]["cursor"] > first["cursor"] and answers[0]["products"][0]["id"] == "gemini-cli"


def test_history_and_detail_are_served_and_an_unknown_key_is_404():
    client = _client()
    _send("claude-code", "pre_tool", {"session_id": "s", "cwd": "/w/app", "tool_name": "Bash", "tool_input": {"command": "git status"}})
    _send("claude-code", "stop", {"session_id": "s", "reason": "other"})
    rows = client.get("/api/agent-instances/history?agent=claude-code").json()["instances"]
    assert len(rows) == 1 and rows[0]["status"] == "ended" and rows[0]["checked"] == 1
    detail = client.get("/api/agent-instances/detail", params={"key": rows[0]["key"]}).json()
    assert [row["what"] for row in detail["actions"] if row["kind"] == "pre_tool"] == ["git status"]
    assert client.get("/api/agent-instances/detail?key=nope").status_code == 404
    assert client.get("/api/agent-instances/history?agent=nobody").status_code == 400
    assert "profiles" in client.get("/api/agent-instances/profiles").json()


def test_devin_reading_claudes_hooks_is_devins_event_and_not_counted_twice(tmp_path, monkeypatch):
    monkeypatch.setenv(identity.DEVIN_ENV, "/w/app")
    monkeypatch.setattr(identity, "devin_config", lambda: tmp_path / "config.json")
    assert runner.effective_agent("claude-code") == "devin" and runner.effective_agent("codex") == "codex"
    (tmp_path / "config.json").write_text('{"hooks": {"PreToolUse": [{"hooks": [{"command": "/x/agent-hooks/python"}]}]}}', encoding="utf-8")
    assert runner.effective_agent("claude-code") == ""


def test_the_history_filters_by_project_date_and_outcome_and_names_its_choices():
    """The core dashboard's history view filters on the server (agent, project, date, had
    refusals or too-late) and offers the agents and projects it holds as choices."""
    from plugins.blackbox.agent_hooks.instances.model import Instance
    base = float(int(time.time()) - 7200)   # within the history's retention
    rows = [("claude-code", "app", 1000, 0, 0), ("claude-code", "site", 2000, 2, 0), ("codex", "app", 3000, 0, 1)]
    for number, (agent, folder, offset, refused, too_late) in enumerate(rows):
        store.put(Instance(key=f"{agent}:{number:016x}", agent=agent, kind="session", started=base + offset - 10, last=base + offset,
                           folder=folder, ended=base + offset, refused=refused, too_late=too_late))
    client = _client()

    def keys(**params):
        answer = client.get("/api/agent-instances/history", params=params)
        assert answer.status_code == 200, answer.text
        return [row["folder"] + "@" + str(int(row["ended"] - base)) for row in answer.json()["instances"]]

    assert keys() == ["app@3000", "site@2000", "app@1000"]
    assert keys(project="app") == ["app@3000", "app@1000"]
    assert keys(since=str(base + 1500), until=str(base + 2500)) == ["site@2000"]
    assert keys(outcome="refused") == ["site@2000"] and keys(outcome="too-late") == ["app@3000"]
    assert keys(outcome="stopped") == ["app@3000", "site@2000"]
    assert keys(agent="claude-code", project="app") == ["app@1000"]
    facets = client.get("/api/agent-instances/history").json()["facets"]
    assert facets == {"agents": [{"id": "claude-code", "name": "Claude Code"}, {"id": "codex", "name": "Codex"}],
                      "projects": ["app", "site"]}
    assert client.get("/api/agent-instances/history?outcome=maybe").status_code == 400
