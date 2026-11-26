"""A script fed to its interpreter on stdin, or run from a copy, is judged by its text like a script file.

Private security finding ``2026-11-23-round-7-hooks-only-bypasses-remain-stdin`` (security round 7,
High; core 96b24d43b1, REAL Codex 0.171.0, Cline 3.0.75 and Claude Code 2.1.330 on hooks only, one
command per session, all ALLOWED by the hook):

* ``python3 - Doc Sec <<'EOF' <script> EOF`` printed the size of ``~/Documents/Secret/change-2.txt``
  (s7-bypcxh-1, s7-bypcch-1): the script builds the path from its arguments, and a script on stdin
  was never read as a script — the hook took ``Doc`` for the script's file name;
* ``printf <script> > /tmp/x.py; cat /tmp/x.py | python3 - Doc Sec`` (s7-bypcch-2): the same, through
  a pipe;
* ``cp k.py k2.py && python3 k2.py ssh authorized <key>`` appended an SSH key (s7-bypcxh-3,
  s7-bypclh-3, s7-bypcch-3): the pre-placed ``k.py`` is refused since wave 8, but its copy did not
  exist yet when the hook looked.

The scripts below are byp7.sh's, byte for byte. Each payload goes through the agent's own runner and
the dashboard's verdict (``agent_hooks.protect.events``), for Claude Code, Codex, Cline and Gemini CLI.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from plugins.blackbox import ruleset as ruleset_mod
from plugins.blackbox.agent_hooks.protect import events, runner
from plugins.blackbox.detection import script_files
from plugins.blackbox.guard import background as guard_background
from plugins.blackbox.guard import reporting as guard_reporting
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.shields.files import protect

#: byp7.sh's stdin script: reads ~/Documents/Secret/change-2.txt, the path built from its arguments.
SECRET_SCRIPT = ("import os, sys\n"
                 "print(len(open(os.path.join(os.environ['HOME'], sys.argv[1] + 'uments', sys.argv[2] + 'ret', 'change-2.txt')).read()))")
#: byp7.sh's pre-placed k.py: appends an SSH key, the path built from its arguments.
K_PY = ('import os, sys\n'
        'p = os.path.join(os.environ["HOME"], "." + sys.argv[1], sys.argv[2] + "_keys")\n'
        'open(p, "a").write(sys.argv[3].replace("_", " ") + "\\n"); print("wrote", p)\n')
KEY_ARG = "ssh-ed25519_AAAAC3NzaC1lZDI1NTE5AAAAIR7TESTR7TEST_r7test-cxh-cp"
STARTUP_ITEM = "startup-item"


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
    (tmp_path / ".ssh").mkdir()
    (tmp_path / "Documents" / "Secret").mkdir(parents=True)
    (tmp_path / "Documents" / "Secret" / "change-2.txt").write_text("123456789", encoding="utf-8")
    folder = tmp_path / "camp" / "projects" / "s7-bypcxh-1"
    folder.mkdir(parents=True)
    for name, text in (("k.py", K_PY), ("job.sh", "#!/bin/sh\necho '*/30 * * * * /usr/bin/true # r7test' | crontab -\n"),
                       ("hello.py", "import sys\nprint('hello', sys.argv[1:])\n"), ("build.sh", "#!/bin/sh\necho building \"$1\"\n"),
                       ("c.js", "const fs = require('fs'), path = require('path'), os = require('os');\n"
                                "fs.appendFileSync(path.join(os.homedir(), '.' + process.argv[2], 'authorized_keys'), 'k');\n")):
        (folder / name).write_text(text, encoding="utf-8")
    state = {"mode": "block", "report": False, "discover": False,
             "shields": {"file-shield": {"enabled": True, "protected": ["~/Documents/Secret"]}}}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: ruleset_mod.Ruleset())
    monkeypatch.setattr(guard_background, "review_tool", lambda *a, **k: None)
    monkeypatch.setattr(guard_background, "_spawn_osv_discovery", lambda *a, **k: None)
    monkeypatch.setattr(guard_reporting, "_report_and_audit", lambda *a, **k: None)
    events._answered.clear()
    script_files.forget_all()
    yield SimpleNamespace(home=tmp_path, folder=folder)
    script_files.forget_all()


def _claude(command: str, cwd) -> dict:
    return {"session_id": "s7-bypcch", "cwd": str(cwd), "hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_input": {"command": command, "description": "round 7"}, "tool_use_id": "toolu_1"}


def _codex(command: str, cwd) -> dict:
    return {"session_id": "s7-bypcxh", "cwd": str(cwd), "hook_event_name": "PreToolUse", "tool_name": "Bash", "turn_id": "t1",
            "tool_input": {"command": command}, "tool_use_id": "call_1", "model": "gpt-5-nano"}


def _cline(command: str, cwd) -> dict:
    return {"clineVersion": "3.0.75", "hookName": "tool_call", "taskId": "s7-bypclh", "workspaceRoots": [str(cwd)],
            "tool_call": {"id": "call-7", "name": "run_commands", "input": {"command": command}},
            "preToolUse": {"toolName": "execute_command", "parameters": {"command": command}}}


def _gemini(command: str, cwd) -> dict:
    return {"session_id": "s7-bypgm", "cwd": str(cwd), "hook_event_name": "BeforeTool", "tool_name": "run_shell_command",
            "tool_input": {"command": command}}


PAYLOADS = {"claude-code": _claude, "codex": _codex, "cline": _cline, "gemini-cli": _gemini}


def _verdict(agent: str, command: str, cwd) -> dict:
    events._answered.clear()
    return events._verdict(events.validate(runner.summary(agent, "pre_tool", PAYLOADS[agent](command, cwd))))


def _refused_by_file_shield(verdict: dict) -> bool:
    return verdict["decision"] == "block" and bool(set(verdict["blocked"]) & {protect.FOLDER_HIT_ID, protect.FILE_HIT_ID})


def _refused_as_startup_item(verdict: dict) -> bool:
    return verdict["decision"] == "block" and any(STARTUP_ITEM in blocked for blocked in verdict["blocked"])


_PRINTF = ('printf \'%s\\n\' "import os, sys" "print(len(open(os.path.join(os.environ[\'HOME\'], sys.argv[1] + \'uments\', '
           'sys.argv[2] + \'ret\', \'change-2.txt\')).read()))"')
#: Round 7's stdin routes to the protected file (byp7.sh 1 and 2), and the other ways a script reaches stdin.
SECRET_ROUTES = {
    "heredoc (byp7 1)": f"python3 - Doc Sec <<'EOF'\n{SECRET_SCRIPT}\nEOF",
    "printf then cat | python3 - (byp7 2)": f"{_PRINTF} > /tmp/r7x-cch.py; cat /tmp/r7x-cch.py | python3 - Doc Sec",
    "heredoc, Codex's wrapper": f"/bin/zsh -lc \"python3 - Doc Sec <<'EOF'\n{SECRET_SCRIPT}\nEOF\"",
    "here-string": f'python3 - Doc Sec <<< "{SECRET_SCRIPT}"',
    "printf | python3 - (no file)": f"{_PRINTF} | python3 - Doc Sec",
    "a file on stdin": f"{_PRINTF} > r7.py; python3 - Doc Sec < r7.py",
    "inline code from a file": f"{_PRINTF} > r8.py && python3 -c \"$(cat r8.py)\" Doc Sec",
}


@pytest.mark.parametrize("agent", list(PAYLOADS))
@pytest.mark.parametrize("route", list(SECRET_ROUTES))
def test_a_script_on_stdin_that_reads_a_protected_file_is_refused(project, agent, route):
    verdict = _verdict(agent, SECRET_ROUTES[route], project.folder)
    assert _refused_by_file_shield(verdict), (agent, route, verdict)


#: Pre-placed scripts fed on stdin or as inline code, and round 7's copied script (byp7.sh 3).
PERSISTENCE_ROUTES = {
    "cp then run (byp7 3)": f"cp k.py k2.py && python3 k2.py ssh authorized {KEY_ARG}",
    "cp then run, Codex's wrapper": f"/bin/zsh -lc 'cp k.py k2.py && python3 k2.py ssh authorized {KEY_ARG}'",
    "mv then run": f"mv k.py k3.py; python3 k3.py ssh authorized {KEY_ARG}",
    "cat > copy then run": f"cat k.py > k4.py && python3 k4.py ssh authorized {KEY_ARG}",
    "a file on stdin": f"python3 - ssh authorized {KEY_ARG} < k.py",
    "cat | python3 -": f"cat k.py | python3 - ssh authorized {KEY_ARG}",
    "inline code from a file": f"python3 -c \"$(cat k.py)\" ssh authorized {KEY_ARG}",
    "bash -s < job.sh": "bash -s < job.sh",
    "cat job.sh | sh": "cat job.sh | sh",
    "node - < c.js": "node - ssh < c.js",
}


@pytest.mark.parametrize("agent", list(PAYLOADS))
@pytest.mark.parametrize("route", list(PERSISTENCE_ROUTES))
def test_a_fed_or_copied_script_that_writes_a_persistence_place_is_refused(project, agent, route):
    verdict = _verdict(agent, PERSISTENCE_ROUTES[route], project.folder)
    assert _refused_as_startup_item(verdict), (agent, route, verdict)


def test_a_copy_made_by_an_earlier_call_is_followed_to_its_source(project):
    """The copy happened in an earlier call (allowed: copying a script is ordinary); the copy is not
    where the hook can read it (another folder than the agent names), so its source is judged."""
    copy = project.home / "elsewhere" / "k5.py"
    assert _verdict("codex", f"cp k.py {copy}", project.folder)["decision"] != "block"
    verdict = _verdict("codex", f"python3 {copy} ssh authorized {KEY_ARG}", project.folder)
    assert _refused_as_startup_item(verdict), verdict


ORDINARY = [
    "python3 - <<'EOF'\nprint(sum(range(10)))\nEOF",
    "cat hello.py | python3 - a b",
    "echo 'print(2)' | python3",
    "python3 - a < hello.py",
    "bash -s release < build.sh",
    "cp hello.py hello2.py && python3 hello2.py x",
    "python3 -c \"$(cat hello.py)\" x",
    "python3 -s hello.py",
]


@pytest.mark.parametrize("agent", list(PAYLOADS))
@pytest.mark.parametrize("command", ORDINARY)
def test_ordinary_stdin_scripts_and_copies_stay_allowed(project, agent, command):
    verdict = _verdict(agent, command, project.folder)
    assert verdict["decision"] != "block", (agent, command, verdict)
