"""Agent Hooks: the coding agents protected through their own hooks (plugins/blackbox/agent_hooks).

Contracts: each agent's payload becomes one tool call the guard reads, and a block comes back in
that agent's documented format; Blackbox's hook entries sit beside the user's own and leave them
exactly as they were when removed; a broken or missing dashboard never stops an agent (fail-open);
every event lands in the agent's own audit log with a hashed session id, so Agent activity shows
its sessions; the Agents list never says "connected" before an event has been seen.
Amos, 2026-11-21: protect Claude Code, Codex, Cursor, Gemini, Copilot, Windsurf, Cline, OpenCode.
"""

from __future__ import annotations

import io
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from plugins.blackbox import audit
from plugins.blackbox import agent_hooks
from plugins.blackbox.agent_hooks.protect import config_edit, events, judge_here, own_files, runner
from plugins.blackbox.kernel import agent_hosts as hosts

CLAUDE = hosts.BY_ID["claude-code"]


# ---------------------------------------------------------------- runner: payload → one tool call

@pytest.mark.parametrize("agent, payload, tool, args", [
    ("claude-code", {"session_id": "s1", "tool_name": "Bash", "tool_input": {"command": "npm i evil"}, "tool_use_id": "t1"},
     "terminal", {"command": "npm i evil"}),
    ("codex", {"session_id": "s1", "turn_id": "x", "tool_name": "shell", "tool_input": {"command": "ls"}}, "terminal", {"command": "ls"}),
    ("codex", {"session_id": "s1", "turn_id": "x", "tool_name": "shell", "tool_input": {"command": ["bash", "-lc", "npm i evil"]}},
     "terminal", {"command": "npm i evil"}),
    ("cursor", {"conversation_id": "c", "command": "curl http://bad.example"}, "terminal", {"command": "curl http://bad.example"}),
    ("cursor", {"conversation_id": "c", "file_path": "/Users/a/.ssh/id_rsa", "content": "x"}, "read_file", {"path": "/Users/a/.ssh/id_rsa"}),
    ("gemini-cli", {"session_id": "g", "tool_name": "run_shell_command", "tool_input": {"command": "pip install x"}}, "terminal", {"command": "pip install x"}),
    ("copilot-cli", {"toolName": "bash", "toolArgs": json.dumps({"command": "echo hi"})}, "terminal", {"command": "echo hi"}),
    ("windsurf", {"trajectory_id": "w", "agent_action_name": "pre_run_command", "tool_info": {"command_line": "rm -rf /", "cwd": "/p"}},
     "terminal", {"command": "rm -rf /"}),
    ("cline", {"taskId": "t", "preToolUse": {"toolName": "read_file", "parameters": {"path": "/etc/shadow"}}}, "read_file", {"path": "/etc/shadow"}),
    ("opencode", {"sessionID": "o", "tool": "write", "args": {"filePath": "x", "file_path": "/tmp/a", "content": "c"}},
     "write_file", {"path": "/tmp/a", "content": "c"}),
])
def test_each_agents_payload_becomes_one_tool_call_the_guard_reads(agent, payload, tool, args):
    body = runner.summary(agent, "pre_tool", payload)
    assert (body["tool_name"], body["args"]) == (tool, args)
    assert body["agent"] == agent and body["event"] == "pre_tool"


def test_a_prompts_text_is_checked_locally_but_never_recorded():
    """The prompt goes to the LOCAL guard for the injection check (2026-11-21); the records keep
    only its length — see test_desktop_agent_security.py for the full contract."""
    body = runner.summary("claude-code", "prompt", {"session_id": "s", "prompt": "my secret plan"})
    assert body["text"] == "my secret plan" and body["prompt_chars"] == len("my secret plan")
    events.record_event(body)
    from plugins.blackbox.kernel import constants
    written = [f.read_text(encoding="utf-8", errors="replace") for f in constants.blackbox_home().rglob("*") if f.is_file()]
    assert written and not any("my secret plan" in text for text in written)


@pytest.mark.parametrize("agent, check", [
    ("claude-code", lambda out: json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"),
    ("codex", lambda out: json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"),
    ("cursor", lambda out: json.loads(out)["permission"] == "deny"),
    ("gemini-cli", lambda out: json.loads(out)["decision"] == "deny"),
    ("copilot-cli", lambda out: json.loads(out)["permissionDecision"] == "deny"),
    ("cline", lambda out: json.loads(out)["cancel"] is True),
    ("opencode", lambda out: json.loads(out)["decision"] == "block"),
])
def test_a_block_comes_back_in_the_agents_own_format(agent, check, monkeypatch):
    out, code = _run(monkeypatch, agent, {"decision": "block", "message": "verified threat"})
    assert check(out) and code == 0 and "verified threat" in out


def test_windsurf_is_blocked_by_exit_code_2(monkeypatch):
    out, code = _run(monkeypatch, "windsurf", {"decision": "block", "message": "no"})
    assert code == 2 and out == ""


def test_no_dashboard_lets_every_agent_continue(monkeypatch):
    for host in hosts.HOSTS:
        monkeypatch.setattr("sys.stdin", _Stdin(json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}})))
        assert runner.main(["runner", host.id, "pre_tool", "http://127.0.0.1:9"]) == 0, host.id


def test_the_runner_asks_a_real_dashboard_with_its_token():
    seen: dict = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):   # /api/session
            self._send({"token": "tok"})

        def do_POST(self):
            seen["token"] = self.headers.get("X-Blackbox-Token")
            seen["body"] = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            self._send({"decision": "block", "message": "Blocked by Blackbox"})

        def _send(self, data):
            raw = json.dumps(data).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        answer = judge_here.ask(f"http://127.0.0.1:{server.server_port}", {"agent": "cursor", "event": "pre_tool"})
    finally:
        server.shutdown()
    assert answer["decision"] == "block" and seen["token"] == "tok" and seen["body"]["agent"] == "cursor"


class _Stdin:
    def __init__(self, text):
        self.buffer = io.BytesIO(text.encode())


def _run(monkeypatch, agent, answer):
    monkeypatch.setattr(judge_here, "ask", lambda url, body, deadline=0.0: answer)
    monkeypatch.setattr("sys.stdin", _Stdin(json.dumps({"tool_name": "Bash", "tool_input": {"command": "x"}})))
    out = io.StringIO()
    monkeypatch.setattr("sys.stdout", out)
    monkeypatch.setattr("sys.stderr", io.StringIO())
    code = runner.main(["runner", agent, "pre_tool", "http://127.0.0.1:9700"])
    return out.getvalue(), code


# ---------------------------------------------------------------- install beside the user's hooks

USER_HOOK = {"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/my-linter"}]}
COMMAND = "/py /home/.blackbox/agent-hooks/runner.py claude-code pre_tool http://127.0.0.1:9700"


def test_install_keeps_the_users_hooks_and_uninstall_restores_them_exactly(tmp_path):
    path = CLAUDE.config_path(tmp_path)
    path.parent.mkdir(parents=True)
    original = {"model": "opus", "hooks": {"PreToolUse": [USER_HOOK]}}
    path.write_text(json.dumps(original), encoding="utf-8")
    assert config_edit.install(CLAUDE, tmp_path, {"PreToolUse": COMMAND, "Stop": COMMAND}).ok
    assert config_edit.install(CLAUDE, tmp_path, {"PreToolUse": COMMAND, "Stop": COMMAND}).ok   # idempotent
    data = json.loads(path.read_text(encoding="utf-8"))
    assert USER_HOOK in data["hooks"]["PreToolUse"] and len(data["hooks"]["PreToolUse"]) == 2
    assert config_edit.installed_commands(CLAUDE, tmp_path) == [COMMAND, COMMAND]
    assert path.with_name("settings.json.blackbox-backup").exists()
    assert config_edit.uninstall(CLAUDE, tmp_path).ok
    assert json.loads(path.read_text(encoding="utf-8")) == original


def test_a_config_that_is_not_plain_json_is_never_rewritten(tmp_path):
    path = CLAUDE.config_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text('{ // my comment\n "a": 1 }', encoding="utf-8")
    result = config_edit.install(CLAUDE, tmp_path, {"PreToolUse": COMMAND})
    assert not result.ok and "untouched" in result.error
    assert path.read_text(encoding="utf-8").startswith("{ // my comment")


def test_cline_keeps_the_users_own_script_for_an_event(tmp_path):
    cline = hosts.BY_ID["cline"]
    folder = cline.config_path(tmp_path)
    folder.mkdir(parents=True)
    (folder / "PreToolUse").write_text("#!/bin/sh\necho mine\n", encoding="utf-8")
    invocations = {event: (["/py", "runner.py"], f"/py {config_edit.MARK} cline {kind} u") for event, kind in cline.events.items()}
    result = own_files.install(cline, tmp_path, invocations)
    assert result.ok and "PreToolUse" in result.error
    assert (folder / "PreToolUse").read_text(encoding="utf-8") == "#!/bin/sh\necho mine\n"
    assert config_edit.MARK in (folder / "PostToolUse").read_text(encoding="utf-8")
    own_files.uninstall(cline, tmp_path)
    assert sorted(p.name for p in folder.iterdir()) == ["PreToolUse"]


def test_removing_clines_hooks_takes_back_only_the_empty_folders_blackbox_made(tmp_path):
    """KI-689 (Linux round L4): on a machine where Cline never made ~/Documents/Cline, the install made
    it for Blackbox's hooks and plugin, and the uninstall left it behind, empty. Only folders Blackbox
    made, and only while empty, are taken back; one the person already had, or put a file in, stays."""
    cline = hosts.BY_ID["cline"]
    invocations = {event: (["/py", "runner.py"], f"/py {config_edit.MARK} cline {kind} u") for event, kind in cline.events.items()}
    (tmp_path / "Documents").mkdir()
    assert own_files.install(cline, tmp_path, invocations).ok
    assert own_files.uninstall(cline, tmp_path).ok
    assert list((tmp_path / "Documents").iterdir()) == [], "the Cline folder Blackbox made is gone; Documents (the person's) stays"
    assert own_files.install(cline, tmp_path, invocations).ok
    (tmp_path / "Documents" / "Cline" / "notes.md").write_text("mine\n", encoding="utf-8")
    assert own_files.uninstall(cline, tmp_path).ok
    assert sorted(p.name for p in (tmp_path / "Documents" / "Cline").iterdir()) == ["notes.md"]


def test_opencodes_plugin_runs_the_runner_and_throws_on_a_block(tmp_path):
    opencode = hosts.BY_ID["opencode"]
    invocations = {event: (["/py", f"/x/{config_edit.MARK}", "opencode", kind, "u"], "") for event, kind in opencode.events.items()}
    assert own_files.install(opencode, tmp_path, invocations).ok
    text = opencode.config_path(tmp_path).read_text(encoding="utf-8")
    assert '"pre_tool"' in text and 'throw new Error' in text and "tool.execute.before" in text and "cwd: directory" in text
    assert own_files.uninstall(opencode, tmp_path).ok and not opencode.config_path(tmp_path).exists()


# ---------------------------------------------------------------- events: judged, recorded, honest

def _verdict(decision):
    finding = {"identifier": "dep:npm:evil", "category": "dependency", "severity": "critical", "title": "evil"}
    return lambda tool_name, args, **_: {"findings": [finding] if decision else [], "blocked": [], "decision": decision,
                                    "message": "Blocked by Blackbox" if decision == "block" else ""}


def test_a_blocked_call_is_answered_and_recorded_under_the_agent(monkeypatch):
    monkeypatch.setattr(events.guard, "tool_call_verdict", _verdict("block"))
    answer = agent_hooks.record_event({"agent": "claude-code", "event": "pre_tool", "session": "raw-session-1", "cwd": "/w/p",
                                       "tool_name": "terminal", "args": {"command": "npm i evil"}, "tool_call_id": "t1"})
    assert answer["decision"] == "block" and answer["findings"] == 1
    rows = [row for row in audit.read_audit(limit=50) if row.get("framework") == "claude-code"]
    call = next(row for row in rows if row["event"] == "pre_tool_call")
    assert call["detail"]["session_id"].startswith("claude-code:") and call["detail"]["decision"] == "block"
    assert "raw-session-1" not in json.dumps(rows)
    assert any(row.get("framework") == "claude-code" for row in audit.read_findings(limit=50))


def test_agent_activity_shows_the_agents_session(monkeypatch):
    monkeypatch.setattr(events.guard, "tool_call_verdict", _verdict(""))
    for event in ("session_start", "pre_tool"):
        agent_hooks.record_event({"agent": "gemini-cli", "event": event, "session": "g-1", "tool_name": "terminal",
                                  "args": {"command": "ls"}})
    sessions = audit.read_local_activity()["sessions"]
    assert any(s["agent"] == "gemini-cli" and any(e["type"] == "tool" for e in s["events"]) for s in sessions)


@pytest.mark.parametrize("body", [{"agent": "nope", "event": "pre_tool"}, {"agent": "cursor", "event": "explode"},
                                  {"agent": "cursor", "event": "pre_tool", "tool_name": "x" * 500}, []])
def test_a_malformed_event_is_refused(body):
    with pytest.raises(ValueError):
        agent_hooks.record_event(body)


def test_states_are_honest(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_hooks, "_home", lambda: tmp_path)
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".cursor").mkdir()
    monkeypatch.setattr(hosts.shutil, "which", lambda name, path=None: None)
    def state():
        return {row.id: row.state for row in agent_hooks.rows()}
    assert state() == {"codex": "available", "cursor": "available"}
    assert agent_hooks.set_protection("codex", True)["ok"] and agent_hooks.set_protection("cursor", True)["ok"]
    assert state() == {"codex": "trust-required", "cursor": "hooked"}   # nothing proven yet
    monkeypatch.setattr(events.guard, "tool_call_verdict", _verdict(""))
    agent_hooks.record_event({"agent": "cursor", "event": "pre_tool", "session": "c", "tool_name": "terminal", "args": {}})
    assert state()["cursor"] == "connected"
    assert agent_hooks.set_protection("cursor", False)["ok"]
    assert state()["cursor"] == "off" and not config_edit.installed_commands(hosts.BY_ID["cursor"], tmp_path)
    assert agent_hooks.record_event({"agent": "cursor", "event": "pre_tool", "tool_name": "terminal"})["recorded"] is False


def test_a_hook_whose_runner_is_gone_is_degraded(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_hooks, "_home", lambda: tmp_path)
    monkeypatch.setattr(hosts.shutil, "which", lambda name, path=None: None)
    (tmp_path / ".cursor").mkdir()
    config_edit.install(hosts.BY_ID["cursor"], tmp_path, {"beforeShellExecution": f"/gone/python /gone/{config_edit.MARK} cursor pre_tool u"})
    assert {row.id: row.state for row in agent_hooks.rows()}["cursor"] == "degraded"


def test_the_runner_answers_fast_when_the_dashboard_is_down(monkeypatch):
    monkeypatch.setattr("sys.stdin", _Stdin("{}"))
    started = time.monotonic()
    runner.main(["runner", "claude-code", "pre_tool", "http://127.0.0.1:9"])
    assert time.monotonic() - started < 1.0


def test_an_agent_installed_outside_the_services_path_is_found(tmp_path, monkeypatch):
    """Found on a test VM (2026-11-20): the dashboard runs with a minimal PATH, so Claude Code installed with
    npm into ~/.npm-global/bin (no ~/.claude yet — it appears on first run) was never hooked."""
    monkeypatch.setattr(agent_hooks, "_home", lambda: tmp_path)
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    tool = tmp_path / ".npm-global" / "bin" / "claude"
    tool.parent.mkdir(parents=True)
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    tool.chmod(0o755)
    assert {row.id: row.state for row in agent_hooks.rows()}.get("claude-code") == "available"


def test_blackboxs_own_launcher_is_not_taken_for_the_agent(tmp_path, monkeypatch):
    """KI-703 (Linux round L5): with Claude Code removed, Blackbox's sandbox launcher ``agent-bin/claude``
    was still on PATH and the agent showed "available — Found on this Mac" (on Linux)."""
    monkeypatch.setattr(agent_hooks, "_home", lambda: tmp_path)
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / ".hermes" / "blackbox"))
    launcher = tmp_path / ".hermes" / "blackbox" / "agent-bin" / "claude"
    launcher.parent.mkdir(parents=True)
    launcher.write_text("#!/bin/sh\n", encoding="utf-8")
    launcher.chmod(0o755)
    monkeypatch.setenv("PATH", f"{launcher.parent}:/usr/bin:/bin")
    assert {row.id: row.state for row in agent_hooks.rows()}.get("claude-code") in (None, "not-installed", "missing")
    real = tmp_path / "bin2" / "claude"
    real.parent.mkdir()
    real.write_text("#!/bin/sh\n", encoding="utf-8")
    real.chmod(0o755)
    monkeypatch.setenv("PATH", f"{launcher.parent}:{real.parent}:/usr/bin:/bin")
    row = {row.id: row for row in agent_hooks.rows()}["claude-code"]
    assert row.state == "available" and "Mac" not in row.detail


# ---------------------------------------------------------------- the Python a hook runs (E2E 2026-11-21)

def test_a_hook_names_blackboxs_launcher_never_a_versioned_hermes_environment(monkeypatch, tmp_path):
    """Hooks named Hermes's versioned environment Python; an update that pruned it would leave every
    agent's hook pointing at nothing. They now name a launcher in Blackbox's data folder."""
    import sys
    versioned = tmp_path / "installs" / "a1" / "environments" / "e1" / "venv" / "bin" / "python3"
    monkeypatch.setattr(sys, "executable", str(versioned))
    argv, _command = next(iter(agent_hooks._invocations(CLAUDE).values()))
    assert argv[0] != str(versioned) and argv[0].endswith("agent-hooks/python")


def test_the_launcher_runs_with_any_surviving_hermes_python_when_the_recorded_one_is_gone(monkeypatch, tmp_path):
    import os
    import subprocess
    import sys
    hermes = tmp_path / "hermes-home"
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    real = sys.executable
    survivor = hermes / "installs" / "a1" / "environments" / "e2" / "venv" / "bin" / "python3"
    survivor.parent.mkdir(parents=True)
    os.symlink(real, survivor)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "pruned" / "python3"))   # the one recorded is gone
    launcher = agent_hooks._python()
    done = subprocess.run([str(launcher), "-c", "print('ran')"], capture_output=True, text=True, timeout=30, check=False)
    assert done.returncode == 0 and done.stdout.strip() == "ran"
    no_path = subprocess.run([str(launcher), "-c", "print(1)"], capture_output=True, text=True, timeout=30, check=False,
                                    env={**os.environ, "PATH": "/nonexistent"})
    assert no_path.returncode == 0


# ---------------------------------------------------------------- a new agent is hooked at once (E2E 2026-11-21)

def test_a_newly_installed_agent_is_noticed_within_seconds_not_at_the_next_five_minute_sweep(monkeypatch, tmp_path):
    from plugins.blackbox.dashboard import agent_hooks_routes as routes
    monkeypatch.setattr(agent_hooks, "_home", lambda: tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path / "no-bin"))
    before = agent_hooks.present()
    (tmp_path / ".claude").mkdir()                         # Claude Code arrives
    after = agent_hooks.present()
    assert "claude-code" in after and "claude-code" not in before
    assert routes.should_sweep(after, before, since_last=routes.OBSERVE_SECONDS)       # sweep now
    assert not routes.should_sweep(after, after, since_last=routes.OBSERVE_SECONDS)    # nothing new: wait
    assert routes.should_sweep(after, after, since_last=routes.SWEEP_SECONDS)         # the full sweep still comes
    assert routes.OBSERVE_SECONDS <= 10
