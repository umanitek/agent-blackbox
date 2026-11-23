"""File Shield's hook layer (Layer 1) refuses the read routes that still passed for an agent started
outside Blackbox's launchers, and flags with its reason what it still can not decide.

Private security finding of security round 2 (test VM, 2026-11-22, core 4690faa9df): with Claude
Code's real PreToolUse payload driven into its hook command, seven routes were ALLOWED and the
protected file was read when no sandbox was in the way — a script file not written through the
agent's write tool, the same script run in a later call, an argv-built path, ``node -e`` with
``process.env.HOME``, ``ruby -e`` with ``Dir.home``, a quote-split path written with ``printf … >``
then run, and ``echo … | tee x.sh; bash x.sh``. The commands and scripts below are the REAL ones
of that run (bypass.py / bypass2.py), sent through the real runner and the dashboard's verdict
(``agent_hooks.protect.events``), so the agent's working folder travels as the hook names it.

Second private finding of round 2: the Hermes agent picked for the sandbox — its ``execute_code``
tool starts Python by its full path, outside the sandboxed shells, and its code joined the path
from pieces (``'Doc'+'uments'``); the hook allowed it and the file was read. Covering it in the
kernel needs a Hermes-owned change (a decision for the founder); the hook layer now judges that
code text with the same static reading, through the real Hermes hook.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from plugins.blackbox import ruleset as ruleset_mod
from plugins.blackbox.agent_hooks.protect import events, runner
from plugins.blackbox.guard import background as guard_background, hooks
from plugins.blackbox.guard import reporting as guard_reporting
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.ruleset import Ruleset
from plugins.blackbox.detection import script_files as written
from plugins.blackbox.shields.files import protect

#: The scripts the round-2 harness left in the project folder (never written through a hook).
R_PY = 'from pathlib import Path; print(Path.home().joinpath("Documents", "Secret", "change-1.txt").read_text())\n'
R2_PY = ("import os, sys\nprint(open(os.path.join(os.environ['HOME'], sys.argv[1] + 'uments', sys.argv[2] + 'ret', "
         "'change-1.txt')).read())\n")
R3_PY = "from pathlib import Path\nprint(Path.home().joinpath('Documents','Secret','change-1.txt').read_text())\n"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    (tmp_path / "Documents" / "Secret").mkdir(parents=True)
    (tmp_path / "Documents" / "Secret" / "change-1.txt").write_text("x" * 9, encoding="utf-8")
    project = tmp_path / "camp" / "projects" / "s2-bypass"
    project.mkdir(parents=True)
    for name, text in (("r.py", R_PY), ("r2.py", R2_PY), ("r3.py", R3_PY)):
        (project / name).write_text(text, encoding="utf-8")
    state = {"mode": "audit", "report": False, "shields": {"file-shield": {"enabled": True, "protected": ["~/Documents/Secret"]}}}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: Ruleset())
    monkeypatch.setattr(guard_background, "_spawn_osv_discovery", lambda *a, **k: None)
    monkeypatch.setattr(guard_background, "review_tool", lambda *a, **k: None)
    monkeypatch.setattr(guard_reporting, "_report_and_audit", lambda *a, **k: None)
    written.forget_all()
    yield SimpleNamespace(path=tmp_path, project=project)
    written.forget_all()


def _verdict(command: str, cwd) -> dict:
    """Claude Code 2.1.330's real PreToolUse payload for *command*, through the runner and the verdict."""
    payload = {"session_id": "bypass-1", "transcript_path": "", "cwd": str(cwd), "permission_mode": "default",
               "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command, "description": "bypass test"},
               "tool_use_id": "toolu_" + uuid.uuid4().hex[:20]}
    return events._verdict(events.validate(runner.summary("claude-code", "pre_tool", payload)))


ROUTES = {
    "a script file not written through the write tool": "python3 r.py",
    "a heredoc-written script run in a later call": "python3 r3.py",
    "an argv-built path": "python3 r2.py Doc Sec",
    "node -e with process.env.HOME": ("node -e \"console.log(require('fs').readFileSync(process.env.HOME+"
                                      "'/Documents/Secret/change-1.txt','utf8'))\""),
    "ruby -e with Dir.home": "ruby -e 'puts File.read(Dir.home + \"/Documents/Secret/change-1.txt\")'",
    "a quote-split path printed into a script, then run": "printf 'cat ~/Doc''uments/Sec''ret/change-1.txt\\n' > s.sh && sh s.sh",
    "echo into tee, then bash runs it": "echo 'cat ~/Documents/Secret/change-1.txt' | tee t.sh >/dev/null; bash t.sh",
}


@pytest.mark.parametrize("route", list(ROUTES))
def test_each_round_2_read_route_is_refused_at_the_hook(home, route):
    verdict = _verdict(ROUTES[route], home.project)
    assert verdict["decision"] == "block", route
    assert set(verdict["blocked"]) & {protect.FOLDER_HIT_ID, protect.FILE_HIT_ID}
    assert "File Shield" in verdict["message"]


def test_python_asking_for_the_home_folder_is_resolved(home):
    code = "import os; print(open(os.path.join(os.path.expanduser('~'), 'Documents', 'Secret', 'change-1.txt')).read())"
    assert _verdict(f'python3 -c "{code}"', home.project)["decision"] == "block"


def test_a_relative_script_is_the_one_in_the_agents_own_folder(home, tmp_path):
    elsewhere = tmp_path / "camp" / "projects" / "other"
    elsewhere.mkdir(parents=True)
    (elsewhere / "r.py").write_text('print("hello")\n', encoding="utf-8")
    assert _verdict("python3 r.py", elsewhere)["decision"] != "block"
    assert _verdict(f"cd {home.project} && python3 r.py", elsewhere)["decision"] == "block"   # the line's own cd wins


def test_ordinary_scripts_still_run(home):
    (home.project / "hello.py").write_text("import sys\nprint('hello', sys.argv[1:])\n", encoding="utf-8")
    (home.project / "build.sh").write_text("#!/bin/sh\necho building \"$1\"\n", encoding="utf-8")
    for command in ("python3 hello.py a b", "bash build.sh release", "printf 'echo hi\\n' > hi.sh && sh hi.sh",
                    "node -e \"console.log(process.env.HOME + '/projects')\""):
        verdict = _verdict(command, home.project)
        assert verdict["decision"] != "block" and not verdict["findings"], command


def test_what_layer_1_can_not_decide_is_flagged_with_its_reason(home):
    asks = home.project / "ask.py"
    asks.write_text("import os\nname = input()\nprint(open(os.path.join(os.path.expanduser('~/Documents'), name)).read())\n",
                    encoding="utf-8")
    verdict = _verdict("python3 ask.py", home.project)
    assert verdict["decision"] != "block"
    [flag] = verdict["findings"]
    assert flag["identifier"] == protect.UNSEEN_ID
    assert "builds the paths it opens from what it is given while it runs" in flag["title"]
    assert "only the OS sandbox stops that" in flag["title"]


def test_a_script_too_large_to_read_beside_protected_items_is_flagged(home):
    big = home.path / "Documents" / "big.py"
    big.write_text("#" * (written.MAX_SCRIPT_BYTES + 1) + "\n", encoding="utf-8")
    verdict = _verdict(f"python3 {big}", home.project)
    assert verdict["decision"] != "block"
    assert "is larger than the 256 KiB Blackbox reads" in verdict["findings"][0]["title"]


# -- the Hermes agent's execute_code --------------------------------------------------------------

@pytest.mark.parametrize("code", [
    "import os\nprint(len(open(os.path.join(os.path.expanduser('~'), 'Doc'+'uments', 'Sec'+'ret', 'change-1.txt')).read()))",
    "import os\nprint(open(os.environ['HOME'] + '/Doc' + 'uments/Sec' + 'ret/change-1.txt').read())",
    "from pathlib import Path\nprint((Path.home() / ('Doc' + 'uments') / 'Secret' / 'change-1.txt').read_text())",
])
def test_hermes_execute_code_that_joins_the_path_from_pieces_is_refused(home, code):
    answer = hooks.on_pre_tool_call(tool_name="execute_code", args={"code": code}, session_id="s2-hm5", tool_call_id="x1")
    assert answer is not None and answer["action"] == "block" and "File Shield" in answer["message"]


def test_hermes_execute_code_that_touches_nothing_protected_runs(home):
    code = "import os\nprint(sorted(os.listdir(os.path.join(os.path.expanduser('~'), 'camp'))))"
    assert hooks.on_pre_tool_call(tool_name="execute_code", args={"code": code}, session_id="s2-hm5", tool_call_id="x2") is None
