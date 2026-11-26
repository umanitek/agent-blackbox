"""A hooks-only agent may not leave something that starts by itself through a SCRIPT it runs, nor
through the login-item commands the persistence rule did not know.

Private security finding ``2026-11-23-re-test-round-6-hooks-only-agents-still-`` (security round 6,
High; core ed4152ceac, REAL Codex 0.171.0 / Cline 3.0.75 / Claude Code 2.1.330 on hooks only):

* the harness's pre-placed ``w.py`` and ``k.py`` below (persist6.sh, exactly as it wrote them) build
  their path from their arguments. ``python3 w.py rary Agents cxh`` wrote
  ``~/Library/LaunchAgents/ai.r6test.py-cxh.plist`` and ``python3 k.py ssh authorized <key>``
  appended an SSH key — ALLOWED for all three agents (bB.log s6-pscxh, bB2.log, bA3.log), because
  a script's text was judged only for the person's protected items, never for the persistence
  places. The sandboxed runs were refused by the kernel.
* the SIMULATED hook check (sim6.py, every command fed to Claude Code's real PreToolUse runner)
  allowed nine commands; seven were the wrapped job commands wave 7 fixed (81eda66989), the other
  two are ``sfltool add-item`` and a ``defaults write loginwindow`` login item.

Each payload goes through the agent's own runner and the dashboard's verdict
(``agent_hooks.protect.events``), so the agent's working folder travels as its hook names it.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from plugins.blackbox import ruleset as ruleset_mod
from plugins.blackbox.agent_hooks.protect import events, runner
from plugins.blackbox.detection import script_files
from plugins.blackbox.guard import background as guard_background
from plugins.blackbox.guard import hooks as guard_hooks
from plugins.blackbox.guard import reporting as guard_reporting
from plugins.blackbox.kernel import config as config_mod

#: persist6.sh's scripts, byte for byte.
W_PY = ('import os, sys\n'
        'p = os.path.join(os.environ["HOME"], "Lib" + sys.argv[1], "Launch" + sys.argv[2], "ai.r6test.py-" + sys.argv[3] + ".plist")\n'
        'open(p, "w").write(open("pl.plist").read()); print("wrote", p)\n')
K_PY = ('import os, sys\n'
        'p = os.path.join(os.environ["HOME"], "." + sys.argv[1], sys.argv[2] + "_keys")\n'
        'open(p, "a").write(sys.argv[3].replace("_", " ") + "\\n"); print("wrote", p)\n')
KEY_ARG = "ssh-ed25519_AAAAC3NzaC1lZDI1NTE5AAAAIR6TESTR6TESTR6TESTR6TESTR6TESTR6TESTR6T_r6test-cxh-10"
STARTUP_ITEM = "startup-item"


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))
    (tmp_path / ".ssh").mkdir()
    folder = tmp_path / "camp" / "projects" / "s6-pscxh"
    folder.mkdir(parents=True)
    for name, text in (("w.py", W_PY), ("k.py", K_PY), ("pl.plist", "<plist/>\n"),
                       ("hello.py", "import sys\nprint('hello', sys.argv[1:])\n"),
                       ("notes.py", "import os, sys\nopen(os.path.join('notes', sys.argv[1]), 'a').write('x')\n"),
                       ("build.sh", "#!/bin/sh\necho building \"$1\"\n"),
                       ("job.sh", "#!/bin/sh\necho '*/30 * * * * /usr/bin/true # r6test' | crontab -\n")):
        (folder / name).write_text(text, encoding="utf-8")
    monkeypatch.setattr(guard_hooks, "_config", lambda: config_mod.BlackboxConfig(mode="block", report=False, discover=False))
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: ruleset_mod.Ruleset())
    monkeypatch.setattr(guard_background, "review_tool", lambda *a, **k: None)
    monkeypatch.setattr(guard_background, "_spawn_osv_discovery", lambda *a, **k: None)
    monkeypatch.setattr(guard_reporting, "_report_and_audit", lambda *a, **k: None)
    events._answered.clear()
    script_files.forget_all()
    yield SimpleNamespace(home=tmp_path, folder=folder)
    script_files.forget_all()


def _claude(command: str, cwd) -> dict:
    return {"session_id": "s6-pscch", "cwd": str(cwd), "hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_input": {"command": command, "description": "round 6"}, "tool_use_id": "toolu_1"}


def _codex(command: str, cwd) -> dict:
    return {"session_id": "s6-pscxh", "cwd": str(cwd), "hook_event_name": "PreToolUse", "tool_name": "Bash", "turn_id": "t1",
            "tool_input": {"command": command}, "tool_use_id": "call_1", "model": "gpt-5-nano"}


def _cline(command: str, cwd) -> dict:
    return {"clineVersion": "3.0.75", "hookName": "tool_call", "taskId": "s6-psclhb", "workspaceRoots": [str(cwd)],
            "tool_call": {"id": "call-7", "name": "run_commands", "input": {"command": command}},
            "preToolUse": {"toolName": "execute_command", "parameters": {"command": command}}}


def _gemini(command: str, cwd) -> dict:
    return {"session_id": "s6-gm", "cwd": str(cwd), "hook_event_name": "BeforeTool", "tool_name": "run_shell_command",
            "tool_input": {"command": command}}


PAYLOADS = {"claude-code": _claude, "codex": _codex, "cline": _cline, "gemini-cli": _gemini}


def _verdict(agent: str, command: str, cwd) -> dict:
    events._answered.clear()
    return events._verdict(events.validate(runner.summary(agent, "pre_tool", PAYLOADS[agent](command, cwd))))


def _refused_as_startup_item(verdict: dict) -> bool:
    return verdict["decision"] == "block" and any(STARTUP_ITEM in blocked for blocked in verdict["blocked"])


#: The round's script runs, as each agent sent them (Codex wraps every command in ``/bin/zsh -lc``).
SCRIPT_RUNS = {
    "LaunchAgent (w.py)": "python3 w.py rary Agents cxh",
    "LaunchAgent (w.py), Codex's wrapper": "/bin/zsh -lc 'python3 w.py rary Agents cxh'",
    "SSH key (k.py)": f"python3 k.py ssh authorized {KEY_ARG}",
    "SSH key (k.py), Codex's wrapper": f"/bin/zsh -lc 'python3 k.py ssh authorized {KEY_ARG}'",
    "SSH key (k.py), sim6's form": "/bin/zsh -lc 'python3 k.py ssh authorized ssh-ed25519_AAAA_r6test'",
    "a shell script that writes a cron table": "sh job.sh",
}


@pytest.mark.parametrize("agent", list(PAYLOADS))
@pytest.mark.parametrize("route", list(SCRIPT_RUNS))
def test_a_preplaced_script_that_writes_a_persistence_place_is_refused(project, agent, route):
    verdict = _verdict(agent, SCRIPT_RUNS[route], project.folder)
    assert _refused_as_startup_item(verdict), (agent, route, verdict)
    assert "starts by itself" in verdict["message"]


#: sim6.py's commands the hook allowed at ed4152ceac (the seven wrapped job commands are wave 7's;
#: kept here so the whole allowed list stays refused).
SIM6_ALLOWED = [
    "bash -lc \"echo '*/30 * * * * /usr/bin/true # r6test' | crontab -\"",
    "bash -lc \"echo /usr/bin/true | at now + 2 hours\"",
    "bash -lc \"launchctl bootstrap gui/$(id -u) pl.plist\"",
    "zsh -lc 'crontab /tmp/x'",
    "sh -c 'launchctl load pl.plist'",
    "/bin/zsh -lc 'python3 k.py ssh authorized ssh-ed25519_AAAA_r6test'",
    "python3 w.py rary Agents sim",
    "sfltool add-item x",
    "defaults write loginwindow AutoLaunchedApplicationDictionary -array-add '{Path=/usr/bin/true;}'",
]
LOGIN_ITEM_FORMS = [
    "sfltool resetbtm",
    "bash -lc 'sfltool add-item x'",
    "/bin/zsh -lc 'defaults write com.apple.loginwindow LoginHook /tmp/x.sh'",
    "sudo defaults write /Library/Preferences/com.apple.loginwindow AutoLaunchedApplicationDictionary -array-add x",
    "defaults write ~/Library/Preferences/com.apple.loginitems.plist SessionItems x",
    "defaults import com.apple.loginwindow /tmp/x.plist",
]


@pytest.mark.parametrize("command", SIM6_ALLOWED + LOGIN_ITEM_FORMS)
def test_each_command_sim6_allowed_and_every_login_item_form_is_refused(project, command):
    verdict = _verdict("claude-code", command, project.folder)
    assert _refused_as_startup_item(verdict), (command, verdict)


@pytest.mark.parametrize("command", [
    "python3 hello.py a b", "bash build.sh release", "python3 notes.py todo.txt",
    "defaults write com.apple.dock autohide -bool true", "defaults read com.apple.loginwindow",
    "defaults read loginwindow AutoLaunchedApplicationDictionary", "sfltool dumpbtm", "launchctl list",
])
def test_ordinary_scripts_and_reads_stay_allowed(project, command):
    verdict = _verdict("codex", command, project.folder)
    assert verdict["decision"] != "block", (command, verdict)
