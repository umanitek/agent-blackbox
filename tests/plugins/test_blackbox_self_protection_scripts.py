"""A hooks-only agent may not change Blackbox through a PRE-PLACED script it runs.

Private security finding ``2026-11-23-hooks-only-self-protection-does-not-read`` (found while
fixing security round 6, High): persistence (5f10894ac0) and File Shield (b0f52cadfb) judge a
script file a command runs by its text, but self-protection did not. A script already on disk
that builds its path from its arguments, like round 6's ``w.py`` / ``k.py`` (``"." + sys.argv[1]``),
could rewrite Hermes' ``config.yaml`` or ``.env``, delete the plugin folder, empty a coding
agent's hook config or plant an add-on manifest - the hook saw only ``python3 c.py hermes yaml``.
All three families now read ONE script judgement (``detection.script_files.judge_runs``, LES-137).

Each payload goes through the agent's own runner and the dashboard's verdict
(``agent_hooks.protect.events``), for Claude Code, Codex, Cline and Gemini CLI.
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
from plugins.blackbox.kernel import threat_ids

_HOME = 'os.environ["HOME"]'
#: Pre-placed scripts in round 6's style: each builds a Blackbox place from its arguments.
SCRIPTS = {
    "cfg.py": f'import os, sys\np = os.path.join({_HOME}, "." + sys.argv[1], "config." + sys.argv[2])\n'
              'open(p, "w").write("mode: audit\\n"); print("wrote", p)\n',
    "env.py": f'import os, sys\np = os.path.join({_HOME}, "." + sys.argv[1], "." + sys.argv[2])\n'
              'open(p, "a").write("BLACKBOX_MODE=audit\\n")\n',
    "rm.py": f'import os, shutil, sys\nshutil.rmtree(os.path.join({_HOME}, "." + sys.argv[1], "plugins", sys.argv[2]))\n',
    "hk.py": f'import os, sys\np = os.path.join({_HOME}, "." + sys.argv[1], "settings.json")\nopen(p, "w").write("{{}}")\n',
    "ad.py": f'import os, sys\np = os.path.join({_HOME}, ".hermes", "plugins", sys.argv[1], "blackbox-" + sys.argv[2] + ".json")\n'
             'open(p, "w").write("{{}}")\n',
    "off.sh": '#!/bin/sh\nprintf "mode: audit\\n" > "$HOME/.$1/config.yaml"\n',
    "c.js": "const fs = require('fs'), path = require('path'), os = require('os');\n"
            "fs.writeFileSync(path.join(os.homedir(), '.' + process.argv[2], 'config.yaml'), 'mode: audit');\n",
    "outer.sh": "#!/bin/sh\npython3 cfg.py hermes yaml\n",
    # Ordinary scripts: they must stay allowed.
    "hello.py": "import sys\nprint('hello', sys.argv[1:])\n",
    "build.sh": '#!/bin/sh\necho building "$1" > build.log\n',
    "show.py": f'import os\nprint(open(os.path.join({_HOME}, ".hermes", "config.yaml")).read())\n',
    "notes.py": "import os, sys\nopen(os.path.join('notes', sys.argv[1]), 'a').write('x')\n",
}


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
    (tmp_path / ".hermes" / "plugins" / "blackbox").mkdir(parents=True)
    (tmp_path / ".hermes" / "config.yaml").write_text("blackbox:\n  mode: block\n", encoding="utf-8")
    folder = tmp_path / "camp" / "projects" / "s7-sp"
    folder.mkdir(parents=True)
    for name, text in SCRIPTS.items():
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
    return {"session_id": "s7-spcc", "cwd": str(cwd), "hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_input": {"command": command, "description": "round 7"}, "tool_use_id": "toolu_1"}


def _codex(command: str, cwd) -> dict:
    return {"session_id": "s7-spcx", "cwd": str(cwd), "hook_event_name": "PreToolUse", "tool_name": "Bash", "turn_id": "t1",
            "tool_input": {"command": command}, "tool_use_id": "call_1", "model": "gpt-5-nano"}


def _cline(command: str, cwd) -> dict:
    return {"clineVersion": "3.0.75", "hookName": "tool_call", "taskId": "s7-spcl", "workspaceRoots": [str(cwd)],
            "tool_call": {"id": "call-7", "name": "run_commands", "input": {"command": command}},
            "preToolUse": {"toolName": "execute_command", "parameters": {"command": command}}}


def _gemini(command: str, cwd) -> dict:
    return {"session_id": "s7-spgm", "cwd": str(cwd), "hook_event_name": "BeforeTool", "tool_name": "run_shell_command",
            "tool_input": {"command": command}}


PAYLOADS = {"claude-code": _claude, "codex": _codex, "cline": _cline, "gemini-cli": _gemini}


def _verdict(agent: str, command: str, cwd) -> dict:
    events._answered.clear()
    return events._verdict(events.validate(runner.summary(agent, "pre_tool", PAYLOADS[agent](command, cwd))))


def _refused_as_self_protection(verdict: dict) -> bool:
    return verdict["decision"] == "block" and any(threat_ids.SELF_PROTECTION in blocked for blocked in verdict["blocked"])


#: Each Blackbox place a pre-placed script reaches, run as agents run it (Codex wraps in ``/bin/zsh -lc``).
SCRIPT_RUNS = {
    "Hermes config.yaml": "python3 cfg.py hermes yaml",
    "Hermes config.yaml, Codex's wrapper": "/bin/zsh -lc 'python3 cfg.py hermes yaml'",
    "Hermes .env": "python3 env.py hermes env",
    "the plugin folder": "python3 rm.py hermes blackbox",
    "a coding agent's hook config": "python3 hk.py claude",
    "an add-on manifest": "python3 ad.py evil addon",
    "a shell script": "sh off.sh hermes",
    "a node script": "node c.js hermes",
    "two scripts deep": "bash outer.sh",
    "two scripts deep, Codex's wrapper": "/bin/zsh -lc 'bash outer.sh'",
}


@pytest.mark.parametrize("agent", list(PAYLOADS))
@pytest.mark.parametrize("route", list(SCRIPT_RUNS))
def test_a_preplaced_script_that_changes_blackbox_is_refused(project, agent, route):
    verdict = _verdict(agent, SCRIPT_RUNS[route], project.folder)
    assert _refused_as_self_protection(verdict), (agent, route, verdict)


def test_the_finding_names_the_script(project):
    from plugins.blackbox.detection import detect_guard_tamper
    from plugins.blackbox.kernel import action_context

    with action_context.working_in(str(project.folder)):
        findings = detect_guard_tamper("terminal", {"command": "python3 cfg.py hermes yaml"})
    assert findings and "cfg.py" in findings[0].evidence, findings


@pytest.mark.parametrize("agent", list(PAYLOADS))
@pytest.mark.parametrize("command", ["python3 hello.py a b", "bash build.sh release", "python3 show.py", "python3 notes.py todo.txt"])
def test_ordinary_scripts_stay_allowed(project, agent, command):
    verdict = _verdict(agent, command, project.folder)
    assert verdict["decision"] != "block", (agent, command, verdict)
