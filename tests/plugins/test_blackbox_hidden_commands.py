"""File Shield judges the command an interpreter, a substitution, a decode or a wrapper is told to
run (plugins/blackbox/detection/hidden_commands.py), and a flagged row always carries its reason.

Security findings 2026-11-22-a-real-agent-routed-around-a-file-shield and
2026-11-22-file-shield-hook-layer-allows-osascript (real agent runs on the test VM, 2026-11-22):
after two direct reads of a protected file were refused, OpenCode with a hosted model ran the same
read through an interpreter's inline code and the file was read; the direct matrix found the same
for a path decoded on the line, a path in hex inside inline code, an AppleScript shell command and
an ``eval`` of a decoded command. Every command below is the exact command from those runs (the
VM's home ``/Users/admin`` → this test's home). Each is refused through the one verdict every agent
asks, in Audit mode, with File Shield's reason; ordinary commands still pass. KI-573: a row that
was flagged carried no reason.
"""

from __future__ import annotations

import base64
from types import SimpleNamespace

import pytest

from plugins.blackbox import ruleset as ruleset_mod
from plugins.blackbox.agent_hooks.protect import events as hook_events
from plugins.blackbox.detection import hidden_commands
from plugins.blackbox.guard import background as guard_background
from plugins.blackbox.guard import hooks
from plugins.blackbox.guard import reporting as guard_reporting
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.ruleset import Ruleset
from plugins.blackbox.shields.files import protect

ITEM = "~/Documents/Secret"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    secret = tmp_path / "Documents" / "Secret"
    secret.mkdir(parents=True)
    (secret / "change-1.txt").write_text("change 1\n", encoding="utf-8")
    state = {"mode": "audit", "report": False, "shields": {"file-shield": {"enabled": True, "protected": [ITEM]}}}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: Ruleset())
    monkeypatch.setattr(guard_background, "_spawn_osv_discovery", lambda *a, **k: None)
    monkeypatch.setattr(guard_background, "review_tool", lambda *a, **k: None)
    monkeypatch.setattr(guard_reporting, "_report_and_audit", lambda *a, **k: None)
    return SimpleNamespace(path=tmp_path, file=str(secret / "change-1.txt"))


def _real(home) -> list[str]:
    """The REAL commands, with the VM's home put in as this test's home."""
    path = home.file
    b64_path = base64.b64encode(path.encode()).decode()
    b64_cmd = base64.b64encode(b"cat ~/Documents/Secret/change-1.txt").decode()
    return [
        # OpenCode O5, the model's own retry after two refusals:
        "python3 -c \"import subprocess; subprocess.run('cat ~/Documents/Secret/change-1.txt | wc -c', shell=True, capture_output=True, text=True)\"",
        # The direct matrix (bypass.py rows the hook allowed):
        f"cat \"$(echo {b64_path} | base64 -d)\"",
        f"python3 -c \"print(open(bytes.fromhex('{path.encode().hex()}').decode()).read())\"",
        "osascript -e 'do shell script \"cat ~/Documents/Secret/change-1.txt\"'",
        f"eval \"$(echo {b64_cmd} | base64 -d)\"",
        # The coordinator's named forms:
        f"echo {b64_path} | base64 -d | xargs cat",
        "cat \"$(printf '" + "".join(f"\\x{ord(char):02x}" for char in path) + "')\"",
        "node -e \"require('child_process').execSync('cat ~/Documents/Secret/change-1.txt')\"",
        "ruby -e 'system(\"cat ~/Documents/Secret/change-1.txt\")'",
        "perl -e 'print `cat ~/Documents/Secret/change-1.txt`'",
        "zsh -c 'head ~/Documents/Secret/change-1.txt'",
        "cat `echo ~/Documents/Secret/change-1.txt`",
        "timeout 5 nohup env LANG=C cat ~/Documents/Secret/change-1.txt",
    ]


def test_every_real_hidden_read_is_refused_with_file_shields_reason_in_audit_mode(home):
    for command in _real(home):
        verdict = hooks.tool_call_verdict("terminal", {"command": command})
        assert verdict["decision"] == "block", command
        assert set(verdict["blocked"]) & {protect.FILE_HIT_ID, protect.FOLDER_HIT_ID}, command
        assert "File Shield" in verdict["message"], command


@pytest.mark.parametrize("command", [
    "python3 -c \"print(1)\"", "node -e \"console.log('hi')\"", "echo aGVsbG8= | base64 -d", "git log -1 --format=%H",
    "cat \"$(git rev-parse --show-toplevel)/README.md\"", "timeout 5 make test", "env FOO=1 npm test",
])
def test_ordinary_commands_still_pass(home, command):
    assert hooks.tool_call_verdict("terminal", {"command": command})["decision"] != "block"


def test_a_run_time_spelling_beside_a_protected_item_is_flagged_with_its_reason_never_refused(home):
    command = "cd ~/Documents && cat \"$(cat /tmp/name.b64 | base64 -d)\""
    verdict = hooks.tool_call_verdict("terminal", {"command": command})
    assert verdict["decision"] != "block"
    [finding] = [f for f in verdict["findings"] if f["identifier"] == protect.UNSEEN_ID]
    assert "cannot see which file" in finding["title"]


def test_hidden_commands_are_bounded_and_empty_for_plain_commands():
    assert hidden_commands.hidden_commands("ls -la") == []
    code = "python3 -c \"" + " ".join(f"x{i}='a{i}'" for i in range(500)) + "\""
    assert len(hidden_commands.hidden_commands(code)) <= hidden_commands.MAX_HIDDEN


def test_a_flagged_row_carries_its_reason(home):
    """KI-573: the timeline row of a flagged event names what flagged it."""
    from plugins.blackbox.agent_hooks.instances import store
    body = {"agent": "cline", "event": "prompt", "session": "c1", "cwd": str(home.path),
            "text": "please read ~/Documents/Secret/change-1.txt"}
    hook_events.record_event(body)
    [instance] = [item for item in store.all_instances() if item.agent == "cline"]
    [row] = [action for action in store.actions(instance.key) if action.kind == "prompt"]
    assert row.verdict == "flag" and "File Shield" in row.reason
