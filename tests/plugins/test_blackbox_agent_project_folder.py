"""Every session carries its project folder (KI-547, agent-tracking campaign 2026-11-22:
Windsurf and Cline sessions had none).

Contracts: the folder is read from each agent's documented payload field — ``cwd``, Cursor's
``workspace_roots``, Cline's ``workspaceRoots``, Windsurf's ``tool_info.cwd`` — and, when the
payload names none, from the hook's own working folder (a hook starts in its agent's), never
``/`` or the person's home.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from plugins.blackbox.agent_hooks.protect import runner

#: (agent, event, payload) — the documented field each agent names its project in.
PAYLOADS = [
    ("claude-code", "pre_tool", {"session_id": "s", "cwd": "/w/app", "tool_name": "Bash", "tool_input": {"command": "ls"}}),
    ("cursor", "pre_tool", {"conversation_id": "c", "workspace_roots": ["/w/app"], "tool_name": "Shell", "tool_input": {"command": "ls"}}),
    ("cline", "pre_tool", {"taskId": "t", "workspaceRoots": ["/w/app"], "preToolUse": {"toolName": "execute_command",
                                                                                      "parameters": {"command": "ls"}}}),
    ("windsurf", "pre_tool", {"trajectory_id": "w", "agent_action_name": "pre_run_command",
                              "tool_info": {"command_line": "ls", "cwd": "/w/app"}}),
]


@pytest.mark.parametrize("agent, event, payload", PAYLOADS)
def test_the_project_folder_is_read_from_each_agents_own_field(agent, event, payload, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert runner.summary(agent, event, payload)["cwd"] == "/w/app"


def test_without_a_field_the_hooks_own_working_folder_is_the_project(tmp_path, monkeypatch):
    project = tmp_path / "site"
    project.mkdir()
    monkeypatch.chdir(project)
    payload = {"trajectory_id": "w", "agent_action_name": "pre_read_code", "tool_info": {"file_path": str(project / "a.py")}}
    cwd = runner.summary("windsurf", "pre_tool", payload)["cwd"]
    assert cwd and Path(cwd).resolve() == project.resolve()


@pytest.mark.parametrize("folder", ["/", "home"])
def test_the_root_or_the_home_folder_is_never_taken_for_a_project(folder, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir("/" if folder == "/" else tmp_path)
    assert runner.summary("opencode", "pre_tool", {"tool": "bash", "args": {"command": "ls"}, "sessionID": "o"})["cwd"] == ""
