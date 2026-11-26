"""A protected path spelled with escaped separators or a static decode in inline code is read as the
path it spells, for every agent's hook.

Private security finding ``2026-11-23-hooks-only-protected-folder-read-through`` (security round 7,
core 96b24d43b1, High, hooks only): REAL Codex 0.171.0 (gpt-5-nano) wrote the node route as
``process.env.HOME+'\\/Documents\\/Secret/change-1.txt'`` — the hook ALLOWED it and the protected
file's size was printed (the plain ``/`` spelling is refused). Simulated through each runner's real
PreToolUse hook, node ``\\/`` and python / ruby ``\\x2f`` were allowed on Claude Code, Codex and
Gemini CLI (9/9). Root cause: the static reading of inline code (``detection.paths.shell_scripts.
_resolved``) joined ``"~" + '\\/Documents…'`` but kept the escape, so no check saw the path.

The fix decodes every string literal and the common static spellings of a path before any path
judgement (escapes ``\\/ \\x2f \\u002f \\u{2f} \\057``, ``os.sep`` / ``path.sep`` / ``chr(47)`` /
``String.fromCharCode(47)``, separator joins, ``bytes.fromhex``, ``codecs.decode`` incl. rot13,
base64 / hex decodes of a literal). Forms computable only at run time stay the OS sandbox's job
(see the module doc of ``shell_scripts``).
"""

from __future__ import annotations

import base64
import codecs
from types import SimpleNamespace

import pytest

from plugins.blackbox import ruleset as ruleset_mod
from plugins.blackbox.agent_hooks.protect import events, runner
from plugins.blackbox.detection import script_files
from plugins.blackbox.guard import background as guard_background
from plugins.blackbox.guard import reporting as guard_reporting
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.ruleset import Ruleset
from plugins.blackbox.shields.files import protect

TAIL = "/Documents/Secret/change-1.txt"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    (tmp_path / "Documents" / "Secret").mkdir(parents=True)
    (tmp_path / "Documents" / "Secret" / "change-1.txt").write_text("x" * 9, encoding="utf-8")
    project = tmp_path / "camp" / "projects" / "s7-sim"
    project.mkdir(parents=True)
    state = {"mode": "audit", "report": False, "shields": {"file-shield": {"enabled": True, "protected": ["~/Documents/Secret"]}}}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: Ruleset())
    monkeypatch.setattr(guard_background, "_spawn_osv_discovery", lambda *a, **k: None)
    monkeypatch.setattr(guard_background, "review_tool", lambda *a, **k: None)
    monkeypatch.setattr(guard_reporting, "_report_and_audit", lambda *a, **k: None)
    script_files.forget_all()
    yield SimpleNamespace(path=tmp_path, project=project)
    script_files.forget_all()


def _claude(command: str, cwd) -> dict:
    return {"session_id": "r7-esc-claude-code", "cwd": str(cwd), "hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_input": {"command": command}, "tool_use_id": "toolu_1"}


def _codex(command: str, cwd) -> dict:
    return {"session_id": "s7-cxrh", "cwd": str(cwd), "hook_event_name": "PreToolUse", "tool_name": "Bash", "turn_id": "t1",
            "tool_input": {"command": command}, "tool_use_id": "call_1", "model": "gpt-5-nano"}


def _cline(command: str, cwd) -> dict:
    return {"clineVersion": "3.0.75", "hookName": "tool_call", "taskId": "r7-esc-cline", "workspaceRoots": [str(cwd)],
            "tool_call": {"id": "call-7", "name": "run_commands", "input": {"command": command}},
            "preToolUse": {"toolName": "execute_command", "parameters": {"command": command}}}


def _gemini(command: str, cwd) -> dict:
    return {"session_id": "r7-esc-gemini-cli", "cwd": str(cwd), "hook_event_name": "BeforeTool", "tool_name": "run_shell_command",
            "tool_input": {"command": command}}


PAYLOADS = {"claude-code": _claude, "codex": _codex, "cline": _cline, "gemini-cli": _gemini}


def _verdict(agent: str, command: str, cwd) -> dict:
    events._answered.clear()
    return events._verdict(events.validate(runner.summary(agent, "pre_tool", PAYLOADS[agent](command, cwd))))


#: Round 7's REAL and simulated payloads (raw/bR.log, raw/sim-escaped.txt) and the other static spellings.
#: ``{home}`` is filled with the test's home folder (a base64 / hex of a whole absolute path).
ESCAPED = {
    "node \\/ (REAL Codex, as typed)": r"""node -e "console.log(require('fs').readFileSync(process.env.HOME+'\/Documents\/Secret/change-1.txt','utf8'))" | wc -c""",
    "node \\/ (REAL Codex, as run: zsh -lc)": r"""/bin/zsh -lc "node -e \"console.log(require('fs').readFileSync(process.env.HOME+'\\/Documents\\/Secret/change-1.txt','utf8'))\" | wc -c" """,
    "python \\x2f": r"""python3 -c "print(len(open(__import__('os').environ['HOME']+'\x2fDocuments\x2fSecret/change-1.txt').read()))" | wc -c""",
    "ruby \\x2f": r"""ruby -e 'puts File.read(Dir.home + "\x2fDocuments\x2fSecret/change-1.txt")' | wc -c""",
    "python octal \\057": r"""python3 -c "import os; print(open(os.environ['HOME'] + '\057Documents\057Secret\057change-1.txt').read())" """,
    "node \\u002f": r"""node -e "console.log(require('fs').readFileSync(require('os').homedir() + '/Documents/Secret/change-1.txt', 'utf8'))" """,
    "node \\u{2f}": r"""node -e "console.log(require('fs').readFileSync(process.env.HOME + '\u{2f}Documents\u{2f}Secret/change-1.txt', 'utf8'))" """,
    "python os.sep +": r"""python3 -c "import os; print(open(os.environ['HOME'] + os.sep + 'Documents' + os.sep + 'Secret' + os.sep + 'change-1.txt').read())" """,
    "python os.sep.join": r"""python3 -c "import os; print(open(os.sep.join([os.environ['HOME'], 'Documents', 'Secret', 'change-1.txt'])).read())" """,
    "node path.sep join": r"""node -e "const p=require('path'); console.log(require('fs').readFileSync([process.env.HOME, 'Documents', 'Secret', 'change-1.txt'].join(p.sep), 'utf8'))" """,
    "python chr(47)": r"""python3 -c "import os; print(open(os.environ['HOME']+chr(47)+'Documents'+chr(47)+'Secret'+chr(47)+'change-1.txt').read())" """,
    "node String.fromCharCode(47)": r"""node -e "const s=String.fromCharCode(47); console.log(require('fs').readFileSync(process.env.HOME+String.fromCharCode(47)+'Documents'+String.fromCharCode(47)+'Secret/change-1.txt','utf8'))" """,
    "python bytes.fromhex": "python3 -c \"import os; print(open(os.environ['HOME'] + bytes.fromhex('" + TAIL.encode().hex() + "').decode()).read())\"",
    "python codecs rot13": "python3 -c \"import os, codecs; print(open(os.environ['HOME'] + codecs.decode('" + codecs.encode(TAIL, "rot13") + "', 'rot13')).read())\"",
    "python base64 of the whole path": "python3 -c \"import base64; print(open(base64.b64decode('{b64}').decode()).read())\"",
    "node Buffer base64 of the whole path": "node -e \"console.log(require('fs').readFileSync(Buffer.from('{b64}', 'base64').toString(), 'utf8'))\"",
    "node atob of the tail": "node -e \"console.log(require('fs').readFileSync(process.env.HOME + atob('" + base64.b64encode(TAIL.encode()).decode() + "'), 'utf8'))\"",
    "python hex of the whole path": "python3 -c \"import binascii; print(open(binascii.unhexlify('{hex}').decode()).read())\"",
}


def _filled(command: str, home_path) -> str:
    whole = f"{home_path}{TAIL}".encode()
    return command.replace("{b64}", base64.b64encode(whole).decode()).replace("{hex}", whole.hex())


@pytest.mark.parametrize("agent", list(PAYLOADS))
@pytest.mark.parametrize("route", list(ESCAPED))
def test_an_escaped_or_decoded_protected_path_in_inline_code_is_refused(home, agent, route):
    verdict = _verdict(agent, _filled(ESCAPED[route], home.path), home.project)
    assert verdict["decision"] == "block", (agent, route, verdict)
    assert set(verdict["blocked"]) & {protect.FOLDER_HIT_ID, protect.FILE_HIT_ID}
    assert "File Shield" in verdict["message"]


ORDINARY = (
    r"""python3 -c "print('a\x2fb')" """,
    r"""node -e "console.log(process.env.HOME + '/projects')" """,
    r"""python3 -c "import base64; print(base64.b64decode('aGVsbG8=').decode())" """,
    r"""python3 -c "import os; print(os.sep.join(['a', 'b']))" """,
    r"""ruby -e 'puts "build\x2fout"' """,
)


@pytest.mark.parametrize("agent", list(PAYLOADS))
@pytest.mark.parametrize("command", ORDINARY)
def test_ordinary_escaped_code_still_runs(home, agent, command):
    verdict = _verdict(agent, command, home.project)
    assert verdict["decision"] != "block" and not verdict["findings"], (agent, command, verdict)
