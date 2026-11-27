"""What the hook runner makes of payloads it can not fully read, and of tool shapes it once dropped
(``agent_hooks.protect.runner`` / ``.tool_shapes``; review findings of 2026-11-26).

* A pre-tool payload the runner can not read whole (larger than it reads, nested too deep to
  parse, not JSON) was turned into "no call" and ALLOWED unjudged on every agent. It is now
  refused like a call not checked in time; a post-tool or observing event still fails open.
* Gemini CLI's ``read_many_files`` names its files in lists (``paths``, ``include``); only the
  single-path keys were read, so none of its files was judged. Every listed file is now carried.
* PowerShell tools (Copilot CLI ``powershell``, Claude Code ``PowerShell`` on Windows) passed
  under their own names, so no shell check saw them. They are the guard's ``terminal`` now.
* A tool's arguments sent as JSON text are read by one tolerant parser: one nested too deep is
  kept as text, never an error.
"""

from __future__ import annotations

import json

import pytest

from plugins.blackbox.agent_hooks.protect import answers, events, runner, tool_shapes

DOWN = "http://127.0.0.1:9"   # nothing listens on the discard port: the dashboard is never reached


@pytest.fixture
def machine(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))
    monkeypatch.setattr(runner, "process_age", lambda: 0.0)
    asked: list = []
    monkeypatch.setattr(runner, "answer_in_time", lambda *a, **k: asked.append(a) or runner.Verdict({}))
    events._answered.clear()
    return asked


def _run(monkeypatch, capsys, agent: str, event: str, raw: bytes) -> tuple[int, str]:
    stdin = type("In", (), {"buffer": type("B", (), {"read": lambda self, n=-1: raw if n < 0 else raw[:n]})()})()
    monkeypatch.setattr(runner.sys, "stdin", stdin)
    code = runner.main(["runner.py", agent, event, DOWN])
    return code, capsys.readouterr().out


def _oversized() -> bytes:
    payload = {"session_id": "s", "tool_name": "Write",
               "tool_input": {"file_path": "/tmp/x", "content": "a" * (runner.MAX_INPUT_BYTES + 10)}}
    return json.dumps(payload).encode()


@pytest.mark.parametrize("raw", [_oversized(), b"[" * 200_000, b"{not json"], ids=["too-large", "too-deep", "not-json"])
def test_a_pre_tool_payload_that_can_not_be_read_whole_is_refused_not_allowed(machine, monkeypatch, capsys, raw):
    code, out = _run(monkeypatch, capsys, "claude-code", "pre_tool", raw)
    expected, expected_code = answers.deny_output("claude-code", runner.NOT_READ)
    assert (code, json.loads(out)) == (expected_code, json.loads(expected))
    assert machine == []   # nothing unjudged was sent on to be "judged" as an empty call


def test_every_agent_reads_the_refusal_in_its_own_format(machine, monkeypatch, capsys):
    for agent in ("codex", "cursor", "gemini-cli", "copilot-cli", "cline", "opencode", "windsurf"):
        code, out = _run(monkeypatch, capsys, agent, "pre_tool", b"[" * 200_000)
        assert (out, code) == answers.deny_output(agent, runner.NOT_READ), agent


def test_an_unreadable_post_tool_or_prompt_payload_still_fails_open(machine, monkeypatch, capsys):
    for event in ("post_tool", "prompt", "session_start"):
        code, out = _run(monkeypatch, capsys, "claude-code", event, _oversized())
        assert code == 0 and "deny" not in out and "block" not in out, event


def test_gemini_read_many_files_carries_every_listed_file():
    name, args = runner._canonical("read_many_files", {"paths": ["~/.ssh/id_rsa", "notes.md"], "include": ["~/.aws/*"]})
    assert name == "read_file"
    assert args["path"] == "~/.ssh/id_rsa" and args["paths"] == ["~/.ssh/id_rsa", "notes.md", "~/.aws/*"]


def test_each_file_of_a_many_file_read_is_judged(monkeypatch):
    judged: list = []
    monkeypatch.setattr(events.guard, "tool_call_verdict", lambda **call: judged.append(call["args"]) or {})
    name, args = runner._canonical("read_many_files", {"paths": ["a.txt", "~/.ssh/id_rsa"]})
    events._tool_verdicts(name, args)
    assert {str(call.get("path")) for call in judged} >= {"a.txt", "~/.ssh/id_rsa"}


@pytest.mark.parametrize("agent,payload", [
    ("copilot-cli", {"sessionId": "s", "toolName": "powershell",
                     "toolArgs": json.dumps({"command": "Remove-Item -Recurse $HOME\\.blackbox", "description": "x"})}),
    ("claude-code", {"session_id": "s", "tool_name": "PowerShell",
                     "tool_input": {"command": "Remove-Item -Recurse $HOME\\.blackbox"}}),
    ("codex", {"session_id": "s", "tool_name": "shell",
               "tool_input": {"command": ["pwsh", "-Command", "Remove-Item -Recurse $HOME\\.blackbox"]}}),
], ids=["copilot-cli", "claude-code", "codex"])
def test_a_windows_powershell_call_is_judged_as_a_shell_command(agent, payload):
    body = runner.summary(agent, "pre_tool", payload)
    assert body["tool_name"] == "terminal"
    assert "Remove-Item -Recurse" in body["args"]["command"]


def test_json_text_arguments_nested_too_deep_stay_text():
    deep = "{" + '"a":' * 50_000 + "1" + "}" * 50_000
    assert tool_shapes.parsed_json(deep) == deep
    assert runner._canonical("x_tool", deep) == ("x_tool", deep)
    assert tool_shapes.parsed_json('{"command": "ls"}') == {"command": "ls"}
