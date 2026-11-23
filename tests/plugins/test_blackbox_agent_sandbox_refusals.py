"""KI-590: the OS sandbox's refusals reach the agent and the person as Blackbox's, and are counted.

Sandbox developer day (2026-11-22, a sandboxed Claude Code): the kernel refused ``sudo``,
``osascript``, ``open -a`` and ``kill <outside pid>`` cleanly, but the agent saw bare OS errors
(exit 127, LaunchServices -54) and was unsure what stopped it. Only the ``.zshrc`` refusal was
counted on the session (refused 3, not 7). Contracts, with the outputs the agent really got:

* each error is read as the refusal it is, and the agent gets one line beside the output,
  "Blackbox's sandbox refused this (<what>): …", without the output being refused;
* the call is counted as refused on its instance, with that line as the reason, for every kind
  but a file's (the helper's deny-log watch counts those with their exact path);
* only in a session the hook proved sandboxed; the Hermes agent's sandboxed shells alike.
"""

from __future__ import annotations

import io
import json
import sys

import pytest

from plugins.blackbox.agent_hooks import hermes_sessions
from plugins.blackbox.agent_hooks.instances import store
from plugins.blackbox.agent_hooks.protect import answers, events as hook_events, runner, sandbox_errors

SUDO = "(eval):1: operation not permitted: sudo"
OSASCRIPT = "(eval):1: operation not permitted: osascript"
OPEN = ("The application /System/Applications/TextEdit.app cannot be opened for an unexpected reason, error=Error "
        "Domain=NSOSStatusErrorDomain Code=-54\n_LSOpenURLsWithCompletionHandler() failed for the application "
        "/System/Applications/TextEdit.app with error -54.")
KILL = "(eval):kill:1: kill 8240 failed: operation not permitted"
BREW = "sandbox-exec: sandbox_apply: Operation not permitted\nError: Failure while executing; `/usr/bin/sandbox-exec -f …` exited with 71."
ZSHRC = "(eval):1: operation not permitted: /Users/admin/.zshrc"
SETUID = "macOS doesn't allow setuid programs inside the agent sandbox; run it in your own terminal"


@pytest.fixture(autouse=True)
def fresh(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    store.reset()
    hermes_sessions.reset()
    monkeypatch.setattr(hook_events.guard, "text_verdict", lambda *_a, **_k: {"findings": [], "blocked": [], "decision": "", "message": ""})
    yield
    store.reset()


@pytest.mark.parametrize("output, kind, said", [
    (SUDO, sandbox_errors.SETUID, f"(sudo, a setuid program): {SETUID}"),
    (OSASCRIPT, sandbox_errors.APP_DRIVER, "(osascript): a program that drives another app"),
    (OPEN, sandbox_errors.OPEN_APP, "(open): opening another app would run it outside the sandbox"),
    (KILL, sandbox_errors.SIGNAL, "(kill): an agent may stop only the programs it started itself"),
    (BREW, sandbox_errors.NESTED, "(a second sandbox): a tool that starts its own sandbox (Homebrew, for one)"),
    (ZSHRC, sandbox_errors.FILE, "(/Users/admin/.zshrc): this file is kept closed to agents"),
])
def test_each_bare_os_error_is_read_as_the_sandbox_refusal_it_is(output, kind, said):
    found = sandbox_errors.refusals(output)
    assert [each.kind for each in found] == [kind]
    assert sandbox_errors.note(found).startswith(f"Blackbox's sandbox refused this {said}")


def test_ordinary_output_is_no_refusal():
    assert sandbox_errors.refusals("added 12 packages\nTests: 8 passed") == []


def _call(output, sandboxed=True, session="dd-blocked-A"):
    base = {"agent": "claude-code", "session": session, "cwd": "/Users/admin/camp/projects/dd-blocked-A", "sandboxed": sandboxed}
    hook_events.record_event({**base, "event": "session_start"})
    return hook_events.record_event({**base, "event": "post_tool", "tool_name": "terminal", "args": {"command": "sudo -n true"},
                                     "text": output})


def test_the_agent_is_told_beside_the_output_and_the_session_counts_the_refusal():
    answer = _call(SUDO)
    assert answer["decision"] == "allow" and answer["note"].startswith("Blackbox's sandbox refused this (sudo, a setuid program)")
    [instance] = [item for item in store.all_instances() if item.agent == "claude-code"]
    assert instance.refused == 1
    [row] = [row for row in store.actions(instance.key) if row.verdict == "block"]
    assert row.reason.startswith("Blackbox's sandbox refused this (sudo")


@pytest.mark.parametrize("output", [OSASCRIPT, OPEN, KILL, BREW])
def test_every_kernel_refusal_kind_is_counted_not_only_file_writes(output):
    _call(output)
    [instance] = [item for item in store.all_instances() if item.agent == "claude-code"]
    assert instance.refused == 1


def test_a_file_refusal_is_explained_and_left_for_the_deny_log_to_count():
    answer = _call(ZSHRC)
    assert "kept closed to agents" in answer["note"]
    [instance] = [item for item in store.all_instances() if item.agent == "claude-code"]
    assert instance.refused == 0


def test_a_session_not_proven_sandboxed_is_never_told_the_sandbox_refused_it():
    answer = _call(SUDO, sandboxed=False)
    assert "note" not in answer
    [instance] = [item for item in store.all_instances() if item.agent == "claude-code"]
    assert instance.refused == 0


@pytest.mark.parametrize("agent, field", [("claude-code", "additionalContext"), ("codex", "additionalContext"),
                                          ("gemini-cli", "additionalContext"), ("cline", "contextModification")])
def test_the_note_goes_beside_the_output_in_each_agents_own_format(agent, field):
    out = json.loads(answers.note_output(agent, "Blackbox's sandbox refused this (sudo …)."))
    assert field in json.dumps(out) and "block" not in json.dumps(out) and "deny" not in json.dumps(out)


def test_the_runner_prints_the_note_and_never_refuses_the_output(monkeypatch, capsys):
    monkeypatch.setattr(runner, "ask", lambda _url, _body: {"decision": "allow", "note": "Blackbox's sandbox refused this (kill)."})
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps({"session_id": "s", "tool_name": "Bash",
                                                                               "tool_response": KILL}).encode("utf-8"))))
    assert runner.main(["runner.py", "claude-code", "post_tool", "http://127.0.0.1:9"]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["hookSpecificOutput"]["additionalContext"] == "Blackbox's sandbox refused this (kill)."


def test_the_hermes_agents_sandboxed_shell_refusals_are_counted_too():
    start = {"event": "session_start", "workspace": "/h", "detail": {"session_id": "hs1", "shells_sandboxed": True, "pid": 4242}}
    post = {"event": "post_tool_call", "workspace": "/h", "detail": {"session_id": "hs1", "tool_name": "terminal", "result": KILL}}
    assert hermes_sessions.apply(start) and hermes_sessions.apply(post)
    [instance] = [item for item in store.all_instances() if item.agent == "hermes"]
    assert instance.refused == 1
