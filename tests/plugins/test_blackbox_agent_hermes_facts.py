"""A Hermes agent session shows its project folder, process, launch, model and prompts, and every
child of one delegation is its sub-agent (KI-572).

Real runs of the Hermes agent 2026.9.24 on the test VM (2026-11-22, `hermes chat -Q -q … --provider
openrouter -m nvidia/nemotron-3.5-lightning:free --yolo` in ~/camp/projects/rh-s1): the instance
showed folder ``.hermes`` and cwd ~/.hermes (the Hermes home, which is the PROFILE), pid 0,
prompts 0, launch "unknown", model ''; two runs in two projects shared one ".hermes" lane; one
`delegate_task` that started two children showed the second child as a session of its own (its
first audit event is a tool call); `/api/agent-instances/history?agent=hermes` answered "unknown
agent or kind". Driven here through the REAL guard hooks Hermes calls, with that command line.
"""

from __future__ import annotations

import os
import sys

import pytest

from plugins.blackbox import audit
from plugins.blackbox.agent_hooks import hermes_sessions, observe, tracking
from plugins.blackbox.agent_hooks.instances import store
from plugins.blackbox.guard import hooks

ARGV = ["hermes", "chat", "-Q", "-q", "run ls", "--provider", "openrouter", "-m", "nvidia/nemotron-3.5-lightning:free", "--yolo"]
MODEL = "nvidia/nemotron-3.5-lightning:free"


@pytest.fixture(autouse=True)
def _fresh(monkeypatch, tmp_path):
    store.reset()
    hermes_sessions.reset()
    monkeypatch.setattr(observe.platform, "process_table", lambda: "")
    tracking._seen.update(at=0.0, read_at=0.0, table={}, running=[], pids=frozenset(), new_profiles=False)
    monkeypatch.setattr(sys, "argv", ARGV)
    monkeypatch.delenv("TERMINAL_CWD", raising=False)
    project = tmp_path / "camp" / "projects" / "rh-s1"
    project.mkdir(parents=True)
    monkeypatch.chdir(project)
    hermes_sessions.catch_up()
    yield project
    store.reset()
    hermes_sessions.reset()


def _hermes():
    hermes_sessions.catch_up()
    return {item.key: item for item in store.all_instances() if item.agent == "hermes"}


def test_a_headless_run_shows_its_project_process_launch_model_and_prompts(_fresh):
    hooks.on_session_start(session_id="rh-s1", model=MODEL, platform="cli")
    for call in (1, 2):   # two model calls in ONE turn: one prompt
        hooks.on_pre_api_request(session_id="rh-s1", turn_id="t1", model=MODEL, provider="openrouter", user_message="run ls",
                                 request_messages=[], api_call_count=call)
    hooks.on_pre_tool_call(tool_name="terminal", args={"command": "ls"}, session_id="rh-s1", tool_call_id="c1")
    hooks.on_pre_api_request(session_id="rh-s1", turn_id="t2", model=MODEL, provider="openrouter", user_message="and again",
                             request_messages=[])
    [session] = _hermes().values()
    assert (session.folder, session.cwd) == ("rh-s1", str(_fresh))
    assert session.pid == os.getpid() and session.launch == "headless" and session.model == MODEL
    assert session.prompts == 2 and session.checked == 1


def test_two_projects_are_two_lanes(_fresh, tmp_path, monkeypatch):
    hooks.on_session_start(session_id="rh-s2a", model=MODEL, platform="cli")
    other = tmp_path / "camp" / "projects" / "rh-s2b"
    other.mkdir(parents=True)
    monkeypatch.setenv("TERMINAL_CWD", str(other))   # Hermes's own working-folder setting wins
    hooks.on_session_start(session_id="rh-s2b", model=MODEL, platform="cli")
    assert sorted(item.folder for item in _hermes().values()) == ["rh-s1", "rh-s2b"]


def test_every_child_of_one_delegation_is_its_sub_agent_and_another_process_is_not(_fresh):
    hooks.on_session_start(session_id="rh-s3", model=MODEL, platform="cli")
    hooks.on_pre_tool_call(tool_name="delegate_task", args={"tasks": ["a", "b"]}, session_id="rh-s3", tool_call_id="d1")
    hooks.on_session_start(session_id="child-1", model=MODEL, platform="cli")
    hooks.on_pre_tool_call(tool_name="terminal", args={"command": "echo sub-1-1 && echo sub-1-2"}, session_id="child-1", tool_call_id="k1")
    # The real second child: its first audit event is a tool call (no session start).
    hooks.on_pre_tool_call(tool_name="terminal", args={"command": "echo sub-2-1"}, session_id="child-2", tool_call_id="k2")
    hooks.on_pre_tool_call(tool_name="terminal", args={"command": "echo sub-2-2"}, session_id="child-2", tool_call_id="k3")
    # Meanwhile another Hermes run in another process starts in the same home: its own session.
    audit.record(event="session_start", detail={"session_id": "elsewhere", "pid": os.getpid() + 1, "cwd": "/w/other",
                                                 "launch": "interactive", "model": MODEL})
    found = _hermes()
    sessions = [item for item in found.values() if item.kind == "session"]
    subs = [item for item in found.values() if item.kind == "sub-agent"]
    assert sorted(item.folder for item in sessions) == ["other", "rh-s1"]
    assert len(subs) == 2 and {sub.parent for sub in subs} == {next(s.key for s in sessions if s.folder == "rh-s1")}
    assert sorted(sub.checked for sub in subs) == [1, 2]


def test_the_history_answers_for_the_hermes_agent():
    assert tracking.known("hermes") and not tracking.known("nobody")
