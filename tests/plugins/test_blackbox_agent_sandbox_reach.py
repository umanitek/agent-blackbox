"""File Shield's agent sandbox reaches every launch Blackbox can control, closes what an agent
inside it could use against Blackbox, covers the Hermes agent's shells, and records the kernel's
refusals on the instance (plugins/blackbox/shields/files/sandbox, kernel/shell_path,
agent_hooks/instances/kernel_refusals.py).

Real runs on the test VM (2026-11-22): a headless run started over SSH (`zsh -c`) got the agent's
real program — the launcher was first on PATH in interactive zsh only (finding
2026-11-22-hooks-only-file-shield-an-agent-written); inside the sandbox an agent could open its own
hook config for writing and signal Blackbox's processes (finding
2026-11-22-agent-sandbox-lets-the-agent-open-its-own); the Hermes agent had no sandbox at all; a
kernel refusal never reached the instance (KI-568: ``python3 r.py allow``, refused 0). Round 2
(KI-581): the kernel refused a sandboxed Claude Code's script writing its OWN hook config
(~/.claude/settings.json), and nothing recorded it.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest

from plugins.blackbox import audit
from plugins.blackbox.agent_hooks import tracking
from plugins.blackbox.agent_hooks.instances import kernel_refusals, store
from plugins.blackbox.agent_hooks.protect import events as hook_events
from plugins.blackbox.kernel import agent_hosts, shell_path
from plugins.blackbox.shields.files import api as files_api, changes, mode as files_mode, sandbox
from plugins.blackbox.shields.files.sandbox.platform import macos

VAULT = "~/Documents/Vault"
REAL = pytest.mark.skipif(sys.platform != "darwin" or not os.access(macos.SANDBOX_EXEC, os.X_OK),
                          reason="a real Seatbelt sandbox needs macOS")


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    real = tmp_path.resolve()
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.setenv("BLACKBOX_HOME", str(real / "bb"))
    (real / "Documents" / "Vault").mkdir(parents=True)
    (real / "Documents" / "Vault" / "secret.txt").write_text("secret", encoding="utf-8")
    (real / ".claude").mkdir()
    (real / ".claude" / "settings.json").write_text("{}", encoding="utf-8")
    changes.reset()
    yield real
    changes.reset()


def _mode(sandboxed=("claude-code",)):
    return files_mode.build(enabled=True, protected=(VAULT,), sandboxed=tuple(sandboxed))


def _run(script: str) -> dict[str, str]:
    done = subprocess.run([macos.SANDBOX_EXEC, "-f", str(sandbox.profile_path()), "/bin/sh", "-c", script],
                          capture_output=True, text=True, timeout=30, check=False)
    return dict(line.split("=", 1) for line in done.stdout.split() if "=" in line)


# -- every launch Blackbox can control ------------------------------------------------------

def test_the_block_is_in_zshenv_so_zsh_without_a_terminal_reaches_the_launchers(home):
    sandbox.sync(_mode())
    assert shell_path.BEGIN in (home / ".zshenv").read_text(encoding="utf-8")
    rows = {row["launch"]: row for row in sandbox.status(_mode())["coverage"]}
    assert all(row["covered"] for launch, row in rows.items() if "zsh" in launch or "interactive" in launch)
    assert any(not row["covered"] for row in rows.values())   # the honest "not reached" row is there


@pytest.mark.skipif(not os.path.exists("/bin/zsh"), reason="needs zsh")
def test_zsh_c_like_an_ssh_command_finds_the_launcher_first(home):
    sandbox.sync(_mode())
    env = {"HOME": str(home), "PATH": "/usr/bin:/bin"}
    done = subprocess.run(["/bin/zsh", "-c", "command -v claude || echo none"], capture_output=True, text=True,
                          timeout=30, env=env, check=False)
    assert done.stdout.strip() == str(sandbox.launcher_dir() / "claude")


def test_each_agent_says_plainly_how_it_is_protected(home):
    view = sandbox.status(_mode(("claude-code", "hermes")))
    levels = {agent["id"]: agent["protection"] for agent in view["agents"]}
    if sandbox.platform.unavailable() is None:
        assert levels["claude-code"] == agent_hosts.PROTECTION_SANDBOXED
        # The Hermes agent's shells are sandboxed; Hermes starts execute_code's Python by full path (KI-580).
        assert levels["hermes"] == agent_hosts.PROTECTION_SHELLS == "terminal tool sandboxed; execute_code hooks only"
    assert levels["gemini-cli"] == levels["codex"] == agent_hosts.PROTECTION_HOOKS


def test_the_hermes_agent_can_be_picked(home):
    assert files_mode._sandboxed(["hermes", "gemini-cli"]) == ("hermes", "gemini-cli")
    assert files_mode._sandboxed(["not-an-agent"]) is None


# -- inside: nothing against Blackbox -------------------------------------------------------

@REAL
def test_inside_the_sandbox_an_agents_hook_config_can_not_be_written_or_moved(home):
    sandbox.sync(_mode())
    config = home / ".claude" / "settings.json"
    lines = _run(f"""
echo '{{}}' > '{config}' 2>/dev/null; echo write=$?
mv '{home}/.claude' '{home}/.claude-old' 2>/dev/null; echo move_folder=$?
echo x > '{home}/.claude/other.json' 2>/dev/null; echo beside=$?
""")
    assert (lines["write"], lines["move_folder"], lines["beside"]) == ("1", "1", "0"), lines
    assert config.read_text(encoding="utf-8") == "{}"


@REAL
def test_inside_the_sandbox_a_process_outside_can_not_be_signalled_but_its_own_children_can(home):
    sandbox.sync(_mode())
    outside = subprocess.Popen(["/bin/sleep", "30"])
    try:
        lines = _run(f"""
kill -TERM {outside.pid} 2>/dev/null; echo outside=$?
/bin/sleep 30 & child=$!; kill $child 2>/dev/null; echo own_child=$?
""")
        assert (lines["outside"], lines["own_child"]) == ("1", "0"), lines
        assert outside.poll() is None
    finally:
        outside.kill()
        outside.wait()


# -- the Hermes agent's shells ---------------------------------------------------------------

@REAL
def test_the_hermes_agents_terminal_shell_runs_inside_the_sandbox(home):
    sandbox.sync(_mode(("hermes",)))
    env = {"PATH": "/usr/bin:/bin"}
    assert sandbox.enter_hermes_process(_mode(("hermes",)), env) is True
    assert env["PATH"].split(os.pathsep)[0] == str(sandbox.hermes_shell_dir())
    bash = subprocess.run(["bash", "-c", f"cat '{home}/Documents/Vault/secret.txt' >/dev/null 2>&1; echo read=$?"],
                          capture_output=True, text=True, timeout=30, env=env, check=False)
    assert bash.stdout.strip() == "read=1", bash.stderr
    sandbox.sync(_mode(()))
    assert sandbox.enter_hermes_process(_mode(()), env) is False
    assert str(sandbox.hermes_shell_dir()) not in env["PATH"]


# -- KI-568: the kernel's refusal on the instance ------------------------------------------------

def test_a_kernel_refusal_is_counted_and_shown_on_the_sandboxed_instance(home, monkeypatch):
    monkeypatch.setattr(hook_events.guard, "tool_call_verdict", lambda **_k: {"findings": [], "blocked": [], "decision": "", "message": ""})
    base = {"agent": "claude-code", "session": "rc-s5x1", "cwd": str(home / "camp"), "sandboxed": True}
    hook_events.record_event({**base, "event": "session_start"})
    hook_events.record_event({**base, "event": "pre_tool", "tool_name": "terminal", "args": {"command": "python3 r.py"}})
    secret = str(home / "Documents" / "Vault" / "secret.txt")
    changes.record([{"path": secret, "kind": "denied", "program": "python3.14", "ts": int(time.time())}], files_mode.build(
        enabled=True, protected=(VAULT,)))
    hook_events.record_event({**base, "event": "post_tool", "tool_name": "terminal", "args": {}, "text": "PermissionError"})
    [instance] = [item for item in store.all_instances() if item.agent == "claude-code"]
    assert instance.refused == 1
    rows = [row for row in store.actions(instance.key) if row.verdict == "block"]
    assert rows and "sandbox" in rows[-1].reason and "python3.14" in rows[-1].reason
    assert tracking.attribute_kernel_refusals() == 0   # given once


def test_a_refusal_with_two_equally_likely_sessions_is_not_guessed(home, monkeypatch):
    monkeypatch.setattr(kernel_refusals, "_candidates", lambda ts: [store.Instance("a:1", "a", "session", 0, ts),
                                                                     store.Instance("b:1", "b", "session", 0, ts)])
    row = {"framework": audit.SANDBOX_RECORDER, "event": "sandbox_deny", "ts": time.time(), "tool_call_id": "sandbox:9",
           "fields": {"path": "/x"}}
    assert kernel_refusals.attribute([row]) == 0


# -- KI-581: the kernel's refusal of an agent rewriting its own hook config ------------------------

def test_the_helper_watches_the_hook_configs_the_sandbox_keeps_closed(home, monkeypatch):
    if sandbox.platform.unavailable() is not None:
        pytest.skip("this system can not sandbox agents")
    monkeypatch.setattr(files_mode, "current", lambda: _mode())
    monkeypatch.setattr(files_api.helper_link, "signed", lambda body, _params: body)
    monkeypatch.setattr(files_api, "_sync_sandbox", lambda: None)
    paths = files_api.watch_plan(None, {})["paths"]
    assert paths[0] == str(home / "Documents" / "Vault")   # the person's items come first
    assert str(home / ".claude" / "settings.json") in paths
    assert sandbox.self_protected_files(_mode(())) == ()   # nothing sandboxed: nothing extra watched


def test_a_kernel_refusal_of_an_agent_writing_its_own_hook_config_is_recorded_as_self_protection(home, monkeypatch):
    if sandbox.platform.unavailable() is not None:
        pytest.skip("this system can not sandbox agents")
    monkeypatch.setattr(hook_events.guard, "tool_call_verdict", lambda **_k: {"findings": [], "blocked": [], "decision": "", "message": ""})
    base = {"agent": "claude-code", "session": "s2-cc-self", "cwd": str(home / "camp"), "sandboxed": True}
    hook_events.record_event({**base, "event": "session_start"})
    hook_events.record_event({**base, "event": "pre_tool", "tool_name": "Bash", "args": {"command": "python3 w.py"}})
    config = str(home / ".claude" / "settings.json")
    kept = changes.record([{"path": config, "kind": "denied", "program": "python3.14", "ts": int(time.time())},
                           {"path": str(home / "elsewhere.txt"), "kind": "denied", "program": "python3.14", "ts": int(time.time())}],
                          _mode(), self_protected=sandbox.self_protected_files(_mode()))
    assert kept == []   # not a change inside a protected item
    [finding] = [row for row in audit.read_findings(limit=50) if (row.get("fields") or {}).get("route") == "self"]
    assert finding["identifier"] == "fileaccess:sandbox:blackbox-settings" and finding["fields"]["path"] == config
    tracking.attribute_kernel_refusals()
    instance = store.get(hook_events.session_key("claude-code", base["session"], base["cwd"]))
    assert instance.refused == 1
    [row] = [action for action in store.actions(instance.key) if action.verdict == "block"]
    assert config in row.reason and "self-protection" in row.reason and "python3.14" in row.reason
