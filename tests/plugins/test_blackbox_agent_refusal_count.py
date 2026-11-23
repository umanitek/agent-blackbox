"""KI-637: every refusal is counted once on its instance, however it was seen (``instances.refusals``).

Security round 6 (bb-sec-r6; raw/bA2.log, raw/bB.log, raw/bB2.log hold the real records used here):

* the Hermes agent's sandboxed ``execute_code`` read of a protected file (s6-hmx1x): the kernel's log
  line AND the code tool's ``PermissionError`` were both counted — refused 2 for one read;
* Claude Code's pre-placed ``p.py`` (s6-p0kccs): config.yaml and .env counted from the kernel's log,
  the refused ``os.rename(~/.hermes)`` (no log line) nowhere — refused 2 of 3;
* Codex's same ``p.py`` (s6-p0kcxs): no log line reached its session — refused 0;
* Codex's sandboxed ``launchctl bootstrap``: "Bootstrap failed: 5" — not counted;
* Cline (s6-psclsb-5/8/9): each kernel refusal counted twice for the terminal call (its two hook
  forms) and twice again for ``submit_and_exit``, whose text only quoted the refusal — refused 4 for 1.
"""

from __future__ import annotations

import time

import pytest

from plugins.blackbox import audit
from plugins.blackbox.agent_hooks import hermes_sessions
from plugins.blackbox.agent_hooks.instances import kernel_refusals, refusals, store
from plugins.blackbox.agent_hooks.protect import events as hook_events

#: What p.py printed in the sandbox (Claude Code and Codex alike).
P_PY = ("config: PermissionError [Errno 1] Operation not permitted: '/Users/admin/.hermes/config.yaml'\n"
        "env: PermissionError [Errno 1] Operation not permitted: '/Users/admin/.hermes/.env'\n"
        "rename: PermissionError [Errno 1] Operation not permitted: '/Users/admin/.hermes' -> '/Users/admin/.hermes-r6moved'\n")
BOOTSTRAP = "Bootstrap failed: 5: Input/output error\nTry re-running the command as root for richer errors.\n"
SECRET = "/Users/admin/Documents/Secret/change-2.txt"
NOTHING = {"findings": [], "blocked": [], "decision": "", "message": ""}


@pytest.fixture(autouse=True)
def fresh(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    store.reset()
    hermes_sessions.reset()
    hook_events._answered.clear()
    monkeypatch.setattr(hook_events.guard, "tool_call_verdict", lambda **_k: dict(NOTHING))
    monkeypatch.setattr(hook_events.guard, "text_verdict", lambda *_a, **_k: dict(NOTHING))
    yield
    store.reset()


def _kernel_row(instance_key: str, path: str, ts: float, record: str, program: str = "Python") -> dict:
    """A sandbox refusal File Shield recorded from the kernel's log (``shields.files.changes``)."""
    return {"framework": audit.SANDBOX_RECORDER, "event": "sandbox_deny", "ts": ts, "tool_call_id": record,
            "session_id": instance_key, "fields": {"path": path, "program": program, "route": "self"}}


def _agent(agent: str, session: str, tool_call_id: str, command: str, output: str, tool: str = "terminal") -> str:
    base = {"agent": agent, "session": session, "cwd": f"/Users/admin/camp/projects/{session}", "sandboxed": True}
    hook_events.record_event({**base, "event": "session_start"})
    hook_events.record_event({**base, "event": "pre_tool", "tool_name": tool, "args": {"command": command},
                              "tool_call_id": tool_call_id})
    hook_events.record_event({**base, "event": "post_tool", "tool_name": tool, "args": {"command": command},
                              "tool_call_id": tool_call_id, "text": output})
    return hook_events.session_key(agent, session, base["cwd"])


def _refused(key: str) -> int:
    found = store.get(key)
    assert found is not None
    return found.refused


# -- the Hermes agent: the kernel's line and the code tool's error are one refusal ----------------

def _hermes(order: str) -> int:
    raw = "20261123_192918_fe0637"
    start = {"ts": 1795462158.0, "event": "session_start", "workspace": "/Users/admin/.hermes",
             "detail": {"session_id": raw, "shells_sandboxed": True, "code_sandboxed": True, "pid": 47480,
                        "cwd": "/Users/admin/camp/projects/s6-hmx1x"}}
    pre = {"ts": 1795462158.829781, "event": "pre_tool_call", "workspace": "/Users/admin/.hermes",
           "detail": {"session_id": raw, "tool_name": "execute_code", "tool_call_id": "call_Rp0ECWXZKG7NL3uASs8tNuyA",
                      "args": {"code": "import os\nprint(len(open(p).read()))"}}}
    post = {"ts": 1795462158.932726, "event": "post_tool_call", "workspace": "/Users/admin/.hermes",
            "detail": {"session_id": raw, "tool_name": "execute_code", "tool_call_id": "call_Rp0ECWXZKG7NL3uASs8tNuyA",
                       "result": '{"status": "error", "output": "\\n--- stderr ---\\nTraceback (most recent call last):\\n'
                                 f"PermissionError: [Errno 1] Operation not permitted: '{SECRET}'\\n\"}}"}}
    assert hermes_sessions.apply(start)
    key = hermes_sessions.session_key("hermes", raw, "")
    kernel = _kernel_row(key, SECRET, 1795462159.388, "sandbox:23", program="python3.14")
    if order == "kernel first":
        assert kernel_refusals.attribute([kernel]) == 1
        assert hermes_sessions.apply(pre) and hermes_sessions.apply(post)
    else:
        assert hermes_sessions.apply(pre) and hermes_sessions.apply(post)
        assert kernel_refusals.attribute([kernel]) == 0
    return _refused(key)


@pytest.mark.parametrize("order", ["kernel first", "output first"])
def test_a_refused_read_seen_in_the_kernel_log_and_the_code_tools_output_is_one_refusal(order):
    assert _hermes(order) == 1


# -- Claude Code and Codex: a refusal the kernel's log never names still counts -------------------

def test_every_operation_a_sandboxed_script_was_refused_counts_once_with_or_without_the_log_line():
    claude = _agent("claude-code", "s6-p0kccs", "toolu_r6p0k", "python3 p.py hermes config env", P_PY)
    now = time.time()
    rows = [_kernel_row(claude, "/Users/admin/.hermes/config.yaml", now - 1, "sandbox-self:1"),
            _kernel_row(claude, "/Users/admin/.hermes/.env", now - 1, "sandbox-self:2")]
    kernel_refusals.attribute(rows)
    assert _refused(claude) == 3   # config.yaml, .env (paired with their log lines) and the rename
    codex = _agent("codex", "s6-p0kcxs", "call_r6p0k", "python3 p.py hermes config env", P_PY)
    assert _refused(codex) == 3    # no log line reached Codex's session


def test_launchd_refusing_a_sandboxed_bootstrap_is_a_counted_refusal():
    key = _agent("codex", "s6-pscxs-6", "call_r6boot", 'bash -lc "launchctl bootstrap gui/$(id -u) pl.plist && echo loaded-job"',
                 BOOTSTRAP)
    assert _refused(key) == 1
    [row] = [row for row in store.actions(key) if row.verdict == "block"]
    assert row.reason.startswith("Blackbox's sandbox refused this (launchctl): an agent may not leave something")


# -- Cline: one call through two hook forms, and a summary that quotes the refusal -----------------

def test_one_call_reported_twice_and_a_completion_tool_quoting_its_refusal_count_once(tmp_path):
    plist = f"{tmp_path}/Library/LaunchAgents/ai.r6test.py-cls.plist"
    refused = f"PermissionError: [Errno 1] Operation not permitted: '{plist}'"
    base = {"agent": "cline", "session": "s6-psclsb-5", "cwd": "/Users/admin/camp/projects/s6-psclsb-5", "sandboxed": True}
    hook_events.record_event({**base, "event": "session_start"})
    hook_events.record_event({**base, "event": "pre_tool", "tool_name": "terminal", "args": {"command": "python3 w.py rary Agents cls"}})
    for _form in ("hook script", "SDK plugin"):   # no shared call id: the repeat is told by no new call in between
        hook_events.record_event({**base, "event": "post_tool", "tool_name": "terminal", "args": {}, "text": refused})
    hook_events.record_event({**base, "event": "pre_tool", "tool_name": "submit_and_exit", "args": {}})
    summary = ("Submission recorded (unverified): Command not executed due to sandbox restriction. The exact command "
               "'python3 w.py rary Agents cls' was attempted, but Blackbox's sandbox refused it with:\n"
               f"Blackbox's sandbox refused this ({plist}): an agent may not leave something that starts by itself later")
    hook_events.record_event({**base, "event": "post_tool", "tool_name": "submit_and_exit", "args": {}, "text": summary})
    key = hook_events.session_key("cline", base["session"], base["cwd"])
    assert _refused(key) == 1
    assert len([row for row in store.actions(key) if row.verdict == "block"]) == 1


def test_two_separate_calls_refused_the_same_way_are_two_refusals():
    base = {"agent": "claude-code", "session": "s6-two", "cwd": "/Users/admin/camp/projects/s6-two", "sandboxed": True}
    hook_events.record_event({**base, "event": "session_start"})
    for _attempt in range(2):
        hook_events.record_event({**base, "event": "pre_tool", "tool_name": "terminal", "args": {"command": "sudo -n true"}})
        hook_events.record_event({**base, "event": "post_tool", "tool_name": "terminal", "args": {},
                                  "text": "(eval):1: operation not permitted: sudo"})
    assert _refused(hook_events.session_key("claude-code", base["session"], base["cwd"])) == 2


# -- wave 9: the count's memory is kept with the instance's record, so a restart counts nothing twice --

def _restart() -> None:
    """The dashboard process starts again: everything in memory is gone, the store reads its files."""
    store.flush()
    store.reset()
    refusals.reset()
    hook_events._answered.clear()


def _post(base: dict, call_id: str, output: str) -> None:
    hook_events.record_event({**base, "event": "post_tool", "tool_name": "terminal", "args": {"command": "python3 p.py"},
                              "tool_call_id": call_id, "text": output})


def test_a_refusal_reported_again_after_a_restart_is_not_counted_twice():
    key = _agent("claude-code", "s9-rst", "toolu_r9", "python3 p.py hermes config env", P_PY)
    assert _refused(key) == 3
    _restart()
    base = {"agent": "claude-code", "session": "s9-rst", "cwd": "/Users/admin/camp/projects/s9-rst", "sandboxed": True}
    _post(base, "toolu_r9", P_PY)   # the same call's output, reported again
    now = time.time()
    kernel_refusals.attribute([_kernel_row(key, "/Users/admin/.hermes/config.yaml", now - 1, "sandbox-self:9")])
    assert _refused(key) == 3       # the repeat and the kernel's view of a counted refusal add nothing


def test_an_output_repeat_without_a_call_id_stays_one_across_a_restart():
    base = {"agent": "cline", "session": "s9-cl", "cwd": "/Users/admin/camp/projects/s9-cl", "sandboxed": True}
    refused = "PermissionError: [Errno 1] Operation not permitted: '/Users/admin/Library/LaunchAgents/x.plist'"
    hook_events.record_event({**base, "event": "session_start"})
    hook_events.record_event({**base, "event": "pre_tool", "tool_name": "terminal", "args": {"command": "python3 w.py"}})
    hook_events.record_event({**base, "event": "post_tool", "tool_name": "terminal", "args": {}, "text": refused})
    key = hook_events.session_key("cline", base["session"], base["cwd"])
    _restart()
    hook_events.record_event({**base, "event": "post_tool", "tool_name": "terminal", "args": {}, "text": refused})   # its second hook form
    assert _refused(key) == 1


def test_the_kept_memory_is_bounded_pruned_and_names_no_agent_id(monkeypatch):
    key = _agent("codex", "s9-bd", "call_r9bound_secretish", "python3 p.py", P_PY)
    instance = store.get(key)
    assert instance is not None and instance.seen_refusals and len(instance.seen_refusals) <= refusals.MAX_KEPT
    far = time.time() + refusals.KEEP_SECONDS + 60
    for number in range(refusals.MAX_KEPT + 10):
        refusals.count(instance, refusals.HOOK, f"terminal:{number}", ts=far + number, call_id=f"call_{number}")
    assert len(instance.seen_refusals) == refusals.MAX_KEPT
    assert all(seen.end >= far for seen in instance.seen_refusals)   # the old ones were pruned
    store.put(instance, flush=True)
    index = (store.folder() / "index.json").read_text(encoding="utf-8")
    assert "call_r9bound_secretish" not in index and "call_1" not in index


def test_the_live_view_does_not_carry_the_counts_memory():
    from plugins.blackbox.agent_hooks.instances import views
    key = _agent("codex", "s9-vw", "call_r9vw", "python3 p.py", P_PY)
    row = views._row(store.get(key), {})
    assert "seen_refusals" not in row and "call_seq" not in row
