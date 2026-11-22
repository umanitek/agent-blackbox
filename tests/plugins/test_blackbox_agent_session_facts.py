"""What an instance says about itself matches what the agent really did (KI-566, KI-567, KI-569,
KI-573, KI-574 — real runs on the test VM, 2026-11-22).

* KI-566: Claude Code 2.1.330 and Gemini CLI 0.70.0 name no model in any hook payload (the real
  keys are below). The model is taken from the agent's command line (``--model`` / ``-m``) and
  from the first lines of the transcript the payload points at — the model field only.
* KI-567: five background sub-agents made one Claude Code prompt count six times; a Codex
  sub-agent's task counted as a prompt of its session.
* KI-569: hooks switched off by ``--settings '{"disableAllHooks": true}'`` or a project's
  settings showed only "Blackbox has seen no hook event from this process".
* KI-573: a headless ``cline … --json`` run showed as "interactive"; Cline's prompt is wrapped
  in its mode tag.
* KI-574: OpenCode's task sub-agents stayed live until the quiet limit.
"""

from __future__ import annotations

import json

import pytest

from plugins.blackbox import agent_hooks
from plugins.blackbox.agent_hooks import observe, tracking
from plugins.blackbox.agent_hooks.instances import links, store, views
from plugins.blackbox.agent_hooks.protect import events, runner
from plugins.blackbox.kernel import agent_hosts as hosts


@pytest.fixture(autouse=True)
def _fresh(monkeypatch, tmp_path):
    store.reset()
    links.reset()
    events._answered.clear()
    monkeypatch.setattr(observe.platform, "process_table", lambda: "")
    monkeypatch.setattr(observe.platform, "process_environment", lambda pid: "")
    monkeypatch.setattr(observe.platform, "process_variable", lambda pid, name: "")
    monkeypatch.setattr(observe.platform, "process_ancestry", lambda pid, limit: None)
    monkeypatch.setattr(agent_hooks, "_home", lambda: tmp_path)
    monkeypatch.setattr(tracking, "agent_process", lambda key, parent, agent: parent)
    monkeypatch.setattr(events.guard, "tool_call_verdict", lambda **_k: {"findings": [], "blocked": [], "decision": "", "message": ""})
    monkeypatch.setattr(events.guard, "text_verdict", lambda _t: {"findings": [], "blocked": [], "decision": "", "message": ""})
    tracking._seen.update(at=0.0, read_at=0.0, table={}, running=[], pids=frozenset(), new_profiles=False)
    yield tmp_path
    store.reset()
    links.reset()


def _send(agent, kind, payload, pid=4242):
    return events.record_event({**runner.summary(agent, kind, payload), "pid": pid})


def _proc(command, pid=4242):
    return {pid: observe.Proc(pid, 1, 0.0, command)}


# -- KI-566: the model ---------------------------------------------------------------------------

def test_the_model_comes_from_the_command_line_the_person_gave():
    assert observe.model_of(_proc("/opt/homebrew/bin/claude -p 'say ok' --model haiku --max-turns 1"), 4242) == "haiku"
    gemini = "node /opt/homebrew/bin/gemini -p hi -o stream-json --skip-trust -m gemini-3.5-flash-lite"
    assert observe.model_of(_proc(gemini), 4242) == "gemini-3.5-flash-lite"
    assert observe.model_of(_proc("/opt/homebrew/bin/claude -p hi"), 4242) == ""


def test_the_model_comes_from_the_transcript_once_it_has_answered(_fresh):
    transcript = _fresh / "44a8ad40.jsonl"
    transcript.write_text("\n".join(json.dumps(line) for line in (
        {"type": "user", "message": {"role": "user", "content": "list the files"}},
        {"type": "assistant", "message": {"model": "claude-haiku-5-5", "role": "assistant", "content": []}})) + "\n", encoding="utf-8")
    # The REAL Claude Code 2.1.330 keys: no model anywhere.
    start = {"cwd": str(_fresh), "hook_event_name": "SessionStart", "session_id": "44a8ad40", "source": "startup",
             "transcript_path": str(transcript)}
    stop = {"cwd": str(_fresh), "hook_event_name": "Stop", "session_id": "44a8ad40", "transcript_path": str(transcript)}
    assert runner.summary("claude-code", "session_start", start)["model"] == ""
    assert runner.summary("claude-code", "turn_end", stop)["model"] == "claude-haiku-5-5"
    _send("claude-code", "session_start", start)
    _send("claude-code", "turn_end", stop)
    [session] = store.all_instances()
    assert session.model == "claude-haiku-5-5"


# -- KI-567: one prompt, counted once ----------------------------------------------------------------

def test_one_prompt_is_counted_once_however_many_turns_it_causes(_fresh):
    base = {"cwd": str(_fresh), "hook_event_name": "UserPromptSubmit", "permission_mode": "default", "session_id": "rc-s3",
            "transcript_path": "", "prompt_id": "p-1"}
    _send("claude-code", "prompt", {**base, "prompt": "Start five sub-agents"})
    for _sub in range(5):   # each background sub-agent's result reached the session as a new turn
        _send("claude-code", "prompt", {**base, "prompt": "Start five sub-agents"})
    _send("claude-code", "prompt", {**base, "prompt_id": "p-2", "prompt": "<task-notification>task 3 finished</task-notification>"})
    _send("claude-code", "prompt", {**base, "prompt_id": "p-3", "prompt": "Now a second question"})
    [session] = store.all_instances()
    assert session.prompts == 2


def test_a_sub_agents_task_is_not_a_prompt_of_its_session(_fresh):
    base = {"cwd": str(_fresh), "session_id": "rx-s3b", "turn_id": "t"}
    _send("codex", "prompt", {**base, "hook_event_name": "UserPromptSubmit", "prompt": "spawn three"})
    _send("codex", "prompt", {**base, "hook_event_name": "UserPromptSubmit", "prompt": "echo sub-1", "agent_id": "a1",
                              "agent_type": "default"})
    session = next(item for item in store.all_instances() if item.kind == "session")
    sub = next(item for item in store.all_instances() if item.kind == "sub-agent")
    assert (session.prompts, sub.prompts) == (1, 1)


# -- KI-569: which setting switched the hooks off ----------------------------------------------------

def test_hooks_switched_off_by_a_settings_flag_are_named_exactly():
    claude = hosts.BY_ID["claude-code"]
    words = ["-p", "--settings", '{"disableAllHooks": true}', "do it"]
    assert "--settings that sets disableAllHooks = true" in observe.hooks_switched_off(claude, words, 4242)
    [row] = observe.running(_proc("""/opt/homebrew/bin/claude -p --settings '{"disableAllHooks": true}' 'sleep 15'"""))
    assert "disableAllHooks" in row.hooks_skipped


def test_hooks_switched_off_by_the_projects_settings_name_the_file(_fresh, monkeypatch):
    project = _fresh / "rc-s7off"
    (project / ".claude").mkdir(parents=True)
    (project / ".claude" / "settings.json").write_text('{"disableAllHooks": true}', encoding="utf-8")
    monkeypatch.setattr(observe.platform, "process_cwd", lambda pid: str(project))
    reason = observe.hooks_switched_off(hosts.BY_ID["claude-code"], ["-p", "hi"], 4242)
    assert str(project / ".claude" / "settings.json") in reason and "disableAllHooks" in reason


# -- KI-573: Cline's launch and prompt ---------------------------------------------------------------

def test_a_cline_json_run_is_headless_and_its_prompt_is_the_persons_words():
    assert observe.launch_of(_proc("cline -P gemini -m gemini-3.5-flash-lite --json 'echo two-1'"), 4242) == "headless"
    payload = {"taskId": "t", "userPromptSubmit": {"prompt": '<user_input mode="act">echo two-1</user_input>', "attachments": []}}
    assert runner.prompt_text("cline", payload) == "echo two-1"


# -- KI-574: OpenCode's sub-agents end with their task ------------------------------------------------

TASK = {"description": "echo task 1", "prompt": "a private instruction", "subagent_type": "general"}


def test_an_opencode_sub_agent_ends_when_its_task_call_returns(_fresh):
    _send("opencode", "pre_tool", {"tool": "task", "args": TASK, "sessionID": "ses_p", "callID": "c1", "cwd": "/w/ro-s3",
                                   "parents_named": True})
    _send("opencode", "pre_tool", {"tool": "bash", "args": {"command": "echo 1"}, "sessionID": "ses_c", "callID": "k1",
                                   "cwd": "/w/ro-s3", "parent_session_id": "ses_p", "parents_named": True})
    [sub] = [item for item in store.all_instances() if item.kind == "sub-agent"]
    assert sub.ended is None
    _send("opencode", "post_tool", {"tool": "task", "sessionID": "ses_p", "callID": "c1", "cwd": "/w/ro-s3", "output": "done",
                                    "parents_named": True})
    assert store.get(sub.key).ended is not None and store.get(sub.key).end_reason == "finished"


def test_sub_agents_end_with_a_session_whose_process_left(_fresh):
    _send("opencode", "pre_tool", {"tool": "task", "args": TASK, "sessionID": "ses_p", "callID": "c1", "cwd": "/w/x", "parents_named": True})
    _send("opencode", "pre_tool", {"tool": "bash", "args": {"command": "echo 1"}, "sessionID": "ses_c", "callID": "k1", "cwd": "/w/x",
                                   "parent_session_id": "ses_p", "parents_named": True})
    session = next(item for item in store.all_instances() if item.kind == "session")
    session.pid = 99999
    store.put(session)
    views.close_stale(alive=[1], read_at=session.last + 1)
    assert all(item.ended is not None for item in store.all_instances())
