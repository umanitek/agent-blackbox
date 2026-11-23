"""Every kernel refusal a sandboxed agent meets says Blackbox refused it, and is counted (KI-599).

Security round 4 (REAL, Claude Code haiku sandboxed, s4-fps / s4-fpks, b1406e6191): only the setuid
stand-ins (sudo, crontab, top) said "Blackbox's sandbox refused this"; ``open -a TextEdit`` (error
-54), ``osascript`` and ``kill -0 <outside pid>`` stayed bare, and s4-fps counted refused 0 although
crontab and top were refused. Root cause: a refused command FAILS (non-zero exit), and Claude Code
reports a failed call through PostToolUseFailure — which Blackbox never hooked — so the output
carrying the error never reached the refusal reader; the stand-ins' own words were not read as
refusals either. Also (round-4 UX): a nested sandbox names the escape that costs nothing
(``swift build --disable-sandbox``), and an installer refused its shell startup file hands the
person the exact lines.
"""

from __future__ import annotations

import json

import pytest

from plugins.blackbox.agent_hooks import hermes_sessions
from plugins.blackbox.agent_hooks.instances import store
from plugins.blackbox.agent_hooks.protect import answers, events as hook_events, runner, sandbox_errors
from plugins.blackbox.kernel.agent_hosts import BY_ID

#: Round 4's real outputs (s4-fps / s4-fpks).
CRONTAB = ("Blackbox's sandbox refused this (crontab): macOS doesn't allow setuid programs inside the agent sandbox; run it in "
           "your own terminal.")
KILL_0 = "(eval):kill:1: kill -0 512 failed: operation not permitted"
NVM = ("=> Appending nvm source string to /Users/admin/.zshrc\n"
       "bash: line 412: /Users/admin/.zshrc: Operation not permitted")


@pytest.fixture(autouse=True)
def fresh(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    store.reset()
    hermes_sessions.reset()
    hook_events._answered.clear()   # one test's tool-call id is not another's repeat
    monkeypatch.setattr(hook_events.guard, "text_verdict", lambda *_a, **_k: {"findings": [], "blocked": [], "decision": "", "message": ""})
    monkeypatch.setattr(hook_events.guard, "after_tool_call_verdict", lambda **_k: {"findings": [], "notes": []})
    yield
    store.reset()


def _failed_call(command: str, error: str) -> dict:
    """Claude Code 2.1.330's PostToolUseFailure payload for a Bash call that exited non-zero."""
    return {"session_id": "s4-fps", "cwd": "/Users/admin/camp/projects/s4-fps", "hook_event_name": "PostToolUseFailure",
            "tool_name": "Bash", "tool_input": {"command": command}, "tool_use_id": "toolu_x", "error": error}


def test_claude_codes_failed_tool_calls_are_hooked():
    assert BY_ID["claude-code"].events.get("PostToolUseFailure") == "post_tool"


@pytest.mark.parametrize("command, error, said", [
    ("kill -0 512", KILL_0, "Blackbox's sandbox refused this (a signal to a process outside the sandbox)"),
    ("osascript -e 'x'", "(eval):1: operation not permitted: osascript", "Blackbox's sandbox refused this (osascript)"),
    ("open -a TextEdit", "_LSOpenURLsWithCompletionHandler() failed for the application /System/Applications/TextEdit.app "
                         "with error -54.", "Blackbox's sandbox refused this (open)"),
])
def test_a_failed_calls_refusal_reaches_the_agent_and_is_counted(command, error, said, monkeypatch):
    monkeypatch.setattr(runner, "sandboxed", lambda: True)
    body = runner.summary("claude-code", "post_tool", _failed_call(command, error))
    assert body["text"] == error
    answer = hook_events.record_event(body)
    assert answer["note"].startswith(said)
    [instance] = store.all_instances()
    assert instance.refused == 1
    out = json.loads(answers.note_output("claude-code", answer["note"], "PostToolUseFailure"))
    assert out["hookSpecificOutput"]["hookEventName"] == "PostToolUseFailure"


def test_blackboxs_own_stand_in_is_counted_and_not_said_twice(monkeypatch):
    monkeypatch.setattr(runner, "sandboxed", lambda: True)
    answer = hook_events.record_event(runner.summary("claude-code", "post_tool", _failed_call("crontab -l", CRONTAB)))
    assert "note" not in answer   # the agent already read Blackbox's sentence
    [instance] = store.all_instances()
    assert instance.refused == 1
    [row] = [row for row in store.actions(instance.key) if row.verdict == "block"]
    assert row.reason == "Blackbox's sandbox refused this (crontab)."


def test_an_installer_refused_its_startup_file_hands_the_person_the_exact_lines():
    [found] = sandbox_errors.refusals(NVM)
    assert found.kind == sandbox_errors.STARTUP and found.installer == "nvm"
    said = sandbox_errors.note([found])
    assert 'export NVM_DIR="$HOME/.nvm"' in said and '[ -s "$NVM_DIR/nvm.sh" ]' in said and "/Users/admin/.zshrc yourself" in said
