"""Agent hook trust: hooks in an agent's config are not hooks that run (agent_hooks/observe/hook_trust).

Linux round L7 (BB-LINUX-PENDING-735ee6, Medium): Codex 0.172 skips a hook until the person
trusts it in Codex (/hooks). Blackbox's hooks sat in ~/.codex/hooks.json, Blackbox showed Codex
as hooked, and a real ``codex exec`` ran 58 commands with nothing checked or recorded.

Contracts: Blackbox reads Codex's OWN trust record (``[hooks.state."<key>"] trusted_hash`` in
``$CODEX_HOME/config.toml``) keyed and hashed exactly as Codex 0.172 does — proven against
Codex's own test vectors and the hashes the real Codex reported on the test VM; only "every
Blackbox hook trusted" (or managed) counts as running — untrusted, changed, switched off and
unreadable are all NOT protected, said with the one step; the agents list, ``blackbox status``
and the protect answer say so; a Codex run while its hooks are untrusted is a HIGH finding at
once, and Codex's own per-run bypass option is not taken for an unseen run. Blackbox never
writes the trust itself.
"""

from __future__ import annotations

import argparse

import json
from pathlib import Path

import pytest

from plugins.blackbox import agent_hooks, audit, cli
from plugins.blackbox.agent_hooks import observe, tracking, unguarded
from plugins.blackbox.agent_hooks.instances import links, store, views
from plugins.blackbox.agent_hooks.observe import hook_trust
from plugins.blackbox.agent_hooks.protect import config_edit, events
from plugins.blackbox.kernel import agent_hosts as hosts

CODEX = hosts.BY_ID["codex"]

#: The real hooks.json Blackbox wrote on the L7 test VM (bb-l7-u24, 2026-11-26), verbatim.
_VM_HOOKS = json.loads(
    '{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"/home/admin/.hermes/blackbox/agent-hooks/python '
    '/home/admin/.hermes/blackbox/agent-hooks/runner.py codex session_start http://127.0.0.1:9700","timeout":10}]}],'
    '"UserPromptSubmit":[{"hooks":[{"type":"command","command":"/home/admin/.hermes/blackbox/agent-hooks/python '
    '/home/admin/.hermes/blackbox/agent-hooks/runner.py codex prompt http://127.0.0.1:9700","timeout":10}]}],'
    '"PreToolUse":[{"hooks":[{"type":"command","command":"/home/admin/.hermes/blackbox/agent-hooks/python '
    '/home/admin/.hermes/blackbox/agent-hooks/runner.py codex pre_tool http://127.0.0.1:9700","timeout":10}]}],'
    '"PostToolUse":[{"hooks":[{"type":"command","command":"/home/admin/.hermes/blackbox/agent-hooks/python '
    '/home/admin/.hermes/blackbox/agent-hooks/runner.py codex post_tool http://127.0.0.1:9700","timeout":10}]}],'
    '"Stop":[{"hooks":[{"type":"command","command":"/home/admin/.hermes/blackbox/agent-hooks/python '
    '/home/admin/.hermes/blackbox/agent-hooks/runner.py codex turn_end http://127.0.0.1:9700","timeout":10}]}],'
    '"SessionEnd":[{"hooks":[{"type":"command","command":"/home/admin/.hermes/blackbox/agent-hooks/python '
    '/home/admin/.hermes/blackbox/agent-hooks/runner.py codex stop http://127.0.0.1:9700","timeout":3}]}],'
    '"SubagentStart":[{"hooks":[{"type":"command","command":"/home/admin/.hermes/blackbox/agent-hooks/python '
    '/home/admin/.hermes/blackbox/agent-hooks/runner.py codex subagent_start http://127.0.0.1:9700","timeout":10}]}],'
    '"SubagentStop":[{"hooks":[{"type":"command","command":"/home/admin/.hermes/blackbox/agent-hooks/python '
    '/home/admin/.hermes/blackbox/agent-hooks/runner.py codex subagent_stop http://127.0.0.1:9700","timeout":10}]}]}}')
#: What the real Codex 0.172.0 reported for that file (``codex app-server`` → ``hooks/list``), verbatim.
_VM_CODEX_SAYS = {
    "/home/admin/.codex/hooks.json:pre_tool_use:0:0": "sha256:57d051053b8df29998e0100bc291a25a24460f3b2cd4acfdf94e2033c78527d1",
    "/home/admin/.codex/hooks.json:post_tool_use:0:0": "sha256:f7af175b4aa20ffaa2d66f3346ec82d60d650847fec1cebf3688a783a5f531e2",
    "/home/admin/.codex/hooks.json:session_start:0:0": "sha256:1211de1b25d620a54ccb68733944b5756b8ec517b2602b3ded636b9893cd0e31",
    "/home/admin/.codex/hooks.json:session_end:0:0": "sha256:e9818092990db6eda0626b68f4edf6a4b189b1fe1f9f505a0385b1994f0b51ae",
    "/home/admin/.codex/hooks.json:user_prompt_submit:0:0": "sha256:718d6e87bb5a8df11dd2fe1661dabf8b36f771c250b0d78d4fe4caff12aee950",
    "/home/admin/.codex/hooks.json:subagent_start:0:0": "sha256:99d70ec4bd104d6c197e990d36bf9e304fc83e36a8dce0405f7dd7829c37992f",
    "/home/admin/.codex/hooks.json:subagent_stop:0:0": "sha256:90de615986e1c0313f8834053eeb8a7b276684a9a0bcfb0e47d852cfb104f097",
    "/home/admin/.codex/hooks.json:stop:0:0": "sha256:33d66586d7b69958809b0efa3139ae32556acd79a29f36ddc3d24f5908d0d2c7",
}


@pytest.fixture(autouse=True)
def _home(monkeypatch, tmp_path):
    store.reset()
    links.reset()
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(agent_hooks, "_home", lambda: tmp_path)
    monkeypatch.setattr(hook_trust, "CODEX_SYSTEM_HOOKS", tmp_path / "etc-codex" / "hooks.json")
    monkeypatch.setattr(hosts.shutil, "which", lambda name, path=None: None)
    for name in ("process_table", "process_environment"):
        monkeypatch.setattr(observe.platform, name, lambda *_a: "")
    monkeypatch.setattr(observe.platform, "process_variable", lambda pid, name: "")
    monkeypatch.setattr(observe.platform, "process_argv", lambda pid: [], raising=False)
    monkeypatch.setattr(observe.platform, "process_cwd", lambda pid: str(tmp_path))
    monkeypatch.setattr(events.guard, "tool_call_verdict", lambda **_k: {"findings": [], "blocked": [], "decision": "", "message": ""})
    monkeypatch.setattr(tracking, "agent_process", lambda key, parent, agent: parent)
    (tmp_path / ".codex").mkdir()
    yield tmp_path
    store.reset()
    links.reset()


def _protect() -> Path:
    assert agent_hooks.set_protection("codex", True)["ok"]
    return CODEX.config_path(agent_hooks._home())


def _trust_all(hooks_file: Path, *, override: dict[str, str] | None = None) -> None:
    """What Codex's /hooks writes when the person trusts every hook (config.toml, user layer)."""
    data = json.loads(hooks_file.read_text(encoding="utf-8"))
    lines = []
    for key, current in hook_trust._our_handlers(hooks_file, data):
        lines += [f'[hooks.state."{key}"]', f'{(override or {}).get(key, "trusted_hash")} = "{current}"', ""]
    hooks_file.with_name("config.toml").write_text("\n".join(lines), encoding="utf-8")


def _state() -> dict[str, tuple[str, str]]:
    return {row.id: (row.state, row.detail) for row in agent_hooks.rows()}


# ------------------------------------------------------------- the hash rule IS Codex's

def test_the_hash_rule_matches_codexs_own_test_vectors():
    """codex-rs/core/tests/suite/hooks.rs (rust-v0.172.0): two declaration hashes it pins."""
    command = "python3 -I -S ${PLUGIN_ROOT}/hooks/pre_tool_use_hook.py"
    handler = {"type": "command", "command": command}
    assert hook_trust.codex_hook_hash("pre_tool_use", "^Bash$", handler) == \
        "sha256:c9ee1aca1b5d8c72b99df6571c87d61350b09f7f4594ae30e7250a2027e9d76b"
    assert hook_trust.codex_hook_hash("post_tool_use", "^Bash$", handler) == \
        "sha256:9eef43ad6f26b1f9b94f318a50445f8bb62c363da08152a2966b73d308bf42ba"


def test_every_blackbox_hook_is_keyed_and_hashed_as_the_real_codex_did():
    ours = dict(hook_trust._our_handlers(Path("/home/admin/.codex/hooks.json"), _VM_HOOKS))
    assert ours == _VM_CODEX_SAYS


def test_the_mark_is_the_one_blackbox_writes():
    assert hook_trust.MARK == config_edit.MARK


# ------------------------------------------------------------- honest states

def test_hooks_written_but_not_trusted_are_not_protected_even_after_an_event(_home):
    hooks_file = _protect()
    trust = hook_trust.read(CODEX, _home)
    assert trust.state == hook_trust.UNTRUSTED and not trust.runs and len(trust.keys) == len(_VM_CODEX_SAYS)
    state, detail = _state()["codex"]
    assert state == "trust-required" and "NOT protected" in detail and "/hooks" in detail
    # An event from a run that bypassed trust once does not make the next ordinary run protected.
    agent_hooks.record_event({"agent": "codex", "event": "pre_tool", "session": "c", "tool_name": "terminal", "args": {}})
    assert _state()["codex"][0] == "trust-required"
    assert hooks_file.with_name("config.toml").exists() is False   # Blackbox never writes the trust itself


def test_the_protect_answer_says_codex_waits_for_the_persons_trust():
    answer = agent_hooks.set_protection("codex", True)
    assert answer["ok"] and answer["trust_required"] is True and "/hooks" in answer["note"]


def test_trusted_hooks_count_as_running_and_are_proven_by_an_event(_home):
    _trust_all(_protect())
    assert hook_trust.read(CODEX, _home).runs
    assert _state()["codex"][0] == "hooked"
    agent_hooks.record_event({"agent": "codex", "event": "pre_tool", "session": "c", "tool_name": "terminal", "args": {}})
    assert _state()["codex"][0] == "connected"
    assert agent_hooks.set_protection("codex", True)["trust_required"] is False


def test_a_hook_changed_since_it_was_trusted_is_not_protected(_home):
    hooks_file = _protect()
    _trust_all(hooks_file)
    config = hooks_file.with_name("config.toml")
    config.write_text(config.read_text(encoding="utf-8").replace("sha256:", "sha256:0", 1), encoding="utf-8")
    trust = hook_trust.read(CODEX, _home)
    assert trust.state == hook_trust.MODIFIED and not trust.runs and len(trust.keys) == 1
    assert _state()["codex"][0] == "trust-required"


def test_a_hook_switched_off_in_codex_is_degraded(_home):
    hooks_file = _protect()
    _trust_all(hooks_file)
    config = hooks_file.with_name("config.toml")
    first = config.read_text(encoding="utf-8").splitlines()[0]   # [hooks.state."<one of Blackbox's keys>"]
    config.write_text(config.read_text(encoding="utf-8").replace(first, first + "\nenabled = false", 1), encoding="utf-8")
    trust = hook_trust.read(CODEX, _home)
    assert trust.state == hook_trust.DISABLED and not trust.runs
    assert _state()["codex"][0] == "degraded"


@pytest.mark.parametrize("config_text", ["[hooks.state\nbroken = ", "\x00" * 10])
def test_a_trust_record_blackbox_cannot_read_takes_the_protective_answer(_home, config_text):
    _protect().with_name("config.toml").write_text(config_text, encoding="utf-8")
    trust = hook_trust.read(CODEX, _home)
    assert trust.state == hook_trust.UNKNOWN and not trust.runs
    assert _state()["codex"][0] == "trust-required"


def test_blackbox_hooks_in_codexs_system_file_are_managed(_home):
    hooks_file = _protect()
    system = hook_trust.CODEX_SYSTEM_HOOKS
    system.parent.mkdir(parents=True)
    system.write_text(hooks_file.read_text(encoding="utf-8"), encoding="utf-8")
    assert hook_trust.read(CODEX, _home).state == hook_trust.MANAGED


def test_status_says_codex_is_not_protected_and_how_to_fix_it(capsys):
    _protect()
    cli._print_coding_agents()
    out = capsys.readouterr().out
    line = next(line for line in out.splitlines() if "Codex" in line)
    assert line.strip().startswith("- !! Codex: trust-required") and "NOT protected" in line and "/hooks" in line


def test_attach_says_codex_is_not_protected_until_the_person_trusts_its_hooks(capsys, monkeypatch, _home):
    """Linux round L8 (BB-LINUX-PENDING-61d736): ``blackbox attach`` (the installer runs it) said
    "All 1 agent(s) found are protected" while Codex's hooks waited for the person's trust."""
    _protect()
    monkeypatch.setattr(cli.attach, "cmd_attach", lambda args: 0)
    monkeypatch.setattr(cli.shields, "apply_sandbox_default", list)
    assert cli._cmd_attach(argparse.Namespace()) == 0
    out = capsys.readouterr().out
    assert "NOT protected yet" in out
    line = next(line for line in out.splitlines() if "Codex" in line)
    assert "trust-required" in line and "/hooks" in line
    _trust_all(_home / ".codex" / "hooks.json")
    cli._cmd_attach(argparse.Namespace())
    assert "Codex" not in capsys.readouterr().out          # trusted: nothing to say


# ------------------------------------------------------------- a run while untrusted is a HIGH finding

_RUN = "/usr/local/bin/codex exec --json --skip-git-repo-check Run exactly: ls"


def test_a_codex_run_while_its_hooks_are_untrusted_is_unseen_at_once_and_a_high_finding():
    _protect()
    [row] = observe.running({4242: observe.Proc(4242, 1, 0.0, _RUN)})
    assert "NOT protected" in row.hooks_skipped and "/hooks" in row.hooks_skipped
    [unprotected] = views.live([row])["unprotected"]   # no grace period: Codex will never send an event
    assert unguarded.report([unprotected]) == 1
    [finding] = [found for found in audit.read_findings(limit=50) if found.get("identifier") == unguarded.UNGUARDED_ID]
    assert finding["severity"] == "high" and "/hooks" in finding["evidence"]


def test_a_trusted_codex_run_and_a_bypassed_run_are_not_named_unseen():
    _trust_all(_protect())
    [row] = observe.running({4242: observe.Proc(4242, 1, 0.0, _RUN)})
    assert row.hooks_skipped == ""
    (agent_hooks._home() / ".codex" / "config.toml").unlink()
    [row] = observe.running({4242: observe.Proc(4242, 1, 0.0, _RUN.replace("exec", "exec --dangerously-bypass-hook-trust"))})
    assert row.hooks_skipped == ""   # Codex runs enabled hooks for this run; its events prove it


#: What the real Codex 0.172.0 TUI left running on bb-l7-u24 after it exited (2026-11-26), verbatim.
_DAEMON = ("/home/admin/.codex/packages/app-server-daemon/releases/0.172.0-aarch64-unknown-linux-musl/bin/codex app-server "
           "--listen unix:// --analytics-default-enabled --managed-daemon")


def test_codexs_idle_managed_daemon_is_not_an_unseen_run_while_its_hooks_would_run(monkeypatch):
    """Linux round L8 (BB-LINUX-PENDING-d53bcb): after a trusted TUI session ended, its daemon (then a
    child of init, no hook event while idle) was flagged HIGH. Idle, it is not unseen; untrusted, it is."""
    monkeypatch.setattr(views, "GRACE_SECONDS", 0.0)
    _trust_all(_protect())
    [row] = observe.running({5151: observe.Proc(5151, 1, 0.0, _DAEMON)})
    assert row.launch == "background" and row.hooks_skipped == ""
    assert unguarded.report(views.live([row])["unprotected"]) == 0
    (agent_hooks._home() / ".codex" / "config.toml").unlink()           # the trust taken away
    [row] = observe.running({5151: observe.Proc(5151, 1, 0.0, _DAEMON)})
    assert "/hooks" in row.hooks_skipped
    assert unguarded.report(views.live([row])["unprotected"]) == 1      # its turns would run unseen: reported

