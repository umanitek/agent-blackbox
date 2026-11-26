"""A coding agent's hook event that the dashboard did not record is never lost: the runner records it
itself where it may write Blackbox's data folder, and otherwise spools it for the dashboard, which
replays it (``agent_hooks.protect.judge_here.keep``, ``agent_hooks.protect.spool``).

Linux round L8 (BB-LINUX-PENDING-e6e905, Medium): with the dashboard stopped, a SANDBOXED agent's
refusal left no audit row, finding or session — Blackbox's data folder is read-only inside the
sandbox, and below Linux 6.12 the detached recorder died with the sandbox's PID namespace. A
hooks-only agent's refusal was recorded. Here the sandbox's read-only folder is a folder this
test makes read-only; the PID-namespace death is the runner never forking a recorder there.
"""

from __future__ import annotations

import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from plugins.blackbox import audit
from plugins.blackbox import ruleset as ruleset_mod
from plugins.blackbox.agent_hooks import tracking
from plugins.blackbox.agent_hooks.observe import platform as observe_platform
from plugins.blackbox.agent_hooks.protect import events, judge_here, runner, spool
from plugins.blackbox.guard import background as guard_background
from plugins.blackbox.guard import hooks as guard_hooks
from plugins.blackbox.guard import reporting as guard_reporting
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.ruleset import Ruleset

LISTED = "npm:easy-day-js@1.11.21"
LISTED_ID = "dep:npm:easy-day-js@1.11.21"
RULES = {LISTED: {"identifier": LISTED_ID, "severity": "critical", "kind": "malware",
                  "name": "SafeDep malicious package: npm/easy-day-js@1.11.21", "source": "public"}}
DOWN = "http://127.0.0.1:9"   # nothing listens on the discard port
INSTALL = {"session_id": "l8-sbx", "cwd": "/tmp", "hook_event_name": "PreToolUse", "tool_name": "Bash",
           "tool_input": {"command": "npm install easy-day-js@1.11.21"}, "tool_use_id": "c1"}


@pytest.fixture
def machine(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))
    (tmp_path / "bb").mkdir()
    rules = Ruleset()
    rules.dependency = dict(RULES)
    monkeypatch.setattr(guard_hooks, "_config", lambda: config_mod.BlackboxConfig(mode="block", report=False, discover=False))
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: rules)
    monkeypatch.setattr(guard_background, "review_tool", lambda *a, **k: None)
    monkeypatch.setattr(guard_reporting, "_report_and_audit", lambda *a, **k: None)
    monkeypatch.setattr(judge_here, "JOURNAL_SOCKET", str(tmp_path / "no-journal"))
    events._answered.clear()
    return tmp_path


def _hook(monkeypatch, capsys, event: str, payload: dict) -> dict:
    monkeypatch.setattr(runner.sys, "stdin", type("In", (), {"buffer": type("B", (), {"read": lambda self, n: json.dumps(payload).encode()})()})())
    runner.main(["runner.py", "claude-code", event, DOWN])
    out = capsys.readouterr().out
    return json.loads(out) if out.strip() else {}


def _refused(answer: dict) -> bool:
    return answer.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"


def _listed_rows() -> list[dict]:
    return [row for row in audit.read_findings(limit=50) if row.get("identifier") == LISTED_ID]


def _spooled() -> list[Path]:
    return sorted(spool.folder().glob("*.json")) if spool.folder().is_dir() else []


def _read_only(folder: Path):
    folder.chmod(stat.S_IRUSR | stat.S_IXUSR)


@pytest.mark.skipif(sys.platform == "win32" or os.geteuid() == 0, reason="a read-only folder needs a POSIX user that is not root")
def test_a_refusal_in_the_sandbox_with_the_dashboard_stopped_is_recorded_when_it_returns(machine, monkeypatch, capsys):
    _read_only(machine / "bb")   # as inside the sandbox: Blackbox's data folder is read-only (EROFS)
    try:
        answer = _hook(monkeypatch, capsys, "pre_tool", INSTALL)
        assert _refused(answer), answer
        files = _spooled()
        assert len(files) == 1 and stat.S_IMODE(files[0].stat().st_mode) == 0o600
        assert json.loads(files[0].read_text(encoding="utf-8"))["decided"] == "block"
    finally:
        (machine / "bb").chmod(0o700)
    events._answered.clear()                        # the dashboard is another process: it never saw the call
    assert spool.replay() == 1                      # the dashboard is back: its observer look replays it
    rows = _listed_rows()
    assert rows and rows[0]["framework"] == "claude-code"
    calls = [row for row in audit.read_audit(limit=50) if row.get("event") == "pre_tool_call"]
    assert calls and calls[0]["detail"]["decision"] == "block"
    assert _spooled() == [] and spool.replay() == 0   # each event once


def test_a_session_start_with_the_dashboard_stopped_is_spooled_and_its_session_kept(machine, monkeypatch, capsys):
    _hook(monkeypatch, capsys, "session_start", {"session_id": "l8-s", "cwd": "/w/app", "hook_event_name": "SessionStart"})
    files = _spooled()
    assert len(files) == 1 and json.loads(files[0].read_text(encoding="utf-8"))["body"]["text"] == ""   # the person's words never kept
    assert spool.replay() == 1
    sessions = events.read_state()["agents"]["claude-code"]["sessions"]
    assert any(row["folder"] == "app" for row in sessions.values())


def test_a_spooled_file_is_judged_again_never_trusted(machine):
    """A forged file says the listed install was allowed: Blackbox's own checks still find it, and
    as the agent was (said to be) allowed, the row says the stop came too late — the action ran."""
    spool.folder().mkdir(parents=True)
    body = {"agent": "claude-code", "event": "pre_tool", "session": "f", "tool_name": "Bash",
            "args": {"command": "npm install easy-day-js@1.11.21"}, "tool_call_id": "f1"}
    (spool.folder() / "1-2-0123abcd.json").write_text(json.dumps({"body": body, "decided": "allow"}), encoding="utf-8")
    assert spool.replay() == 1
    call = next(row for row in audit.read_audit(limit=50) if row.get("event") == "pre_tool_call")
    assert call["detail"]["decision"] == "too-late" and _listed_rows()


@pytest.mark.skipif(sys.platform == "win32", reason="symbolic links")
def test_the_replay_never_follows_a_link_nor_touches_a_file_it_did_not_write(machine):
    outside = machine / "project"
    outside.mkdir()
    keep = outside / "1-2-0123abcd.json"
    keep.write_text(json.dumps({"body": {"agent": "claude-code", "event": "session_start"}}), encoding="utf-8")
    spool.folder().parent.mkdir(parents=True)
    spool.folder().symlink_to(outside)               # the folder swapped for a link to the person's files
    assert spool.replay() == 0 and keep.exists()
    spool.folder().unlink()
    spool.folder().mkdir()
    (spool.folder() / "notes.json").write_text("{}", encoding="utf-8")
    (spool.folder() / "1-2-89abcdef.json").symlink_to(keep)
    assert spool.replay() == 0 and keep.exists() and (spool.folder() / "notes.json").exists()


def test_a_refusal_whose_spooled_record_was_removed_is_reported(machine, monkeypatch):
    mark = {"BLACKBOX_SPOOL_ID": "1-2-0123abcd", "BLACKBOX_AGENT": "claude-code", "BLACKBOX_EVENT": "pre_tool", "BLACKBOX_TOOL": "Bash"}
    monkeypatch.setattr(observe_platform, "journal_marks", lambda tag, cursor: [mark])
    assert spool.replay() == 0 and not [row for row in audit.read_findings(limit=20) if row.get("identifier") == spool.REMOVED_ID]
    Path(spool._cursor_path()).write_text("s=1", encoding="utf-8")   # after the first look (which only sets the place)
    spool.replay()
    removed = [row for row in audit.read_findings(limit=20) if row.get("identifier") == spool.REMOVED_ID]
    assert removed and removed[0]["severity"] == "high" and removed[0]["framework"] == "claude-code"


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="unix sockets")
def test_a_refusal_leaves_a_journal_mark_without_its_arguments(machine, monkeypatch, capsys):
    folder = tempfile.mkdtemp(prefix="bbj", dir="/tmp")   # a unix socket path must be short
    path = os.path.join(folder, "s")
    journal = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    journal.bind(path)
    try:
        monkeypatch.setattr(judge_here, "JOURNAL_SOCKET", path)
        _read_only(machine / "bb")
        try:
            assert _refused(_hook(monkeypatch, capsys, "pre_tool", INSTALL))
        finally:
            (machine / "bb").chmod(0o700)
        journal.settimeout(2)
        line = journal.recv(65536).decode("utf-8")
    finally:
        journal.close()
        os.unlink(path)
        os.rmdir(folder)
    fields = dict(item.split("=", 1) for item in line.strip().split("\n"))
    assert fields["SYSLOG_IDENTIFIER"] == judge_here.JOURNAL_TAG and fields["BLACKBOX_AGENT"] == "claude-code"
    assert fields["BLACKBOX_SPOOL_ID"] == _spooled()[0].stem and "easy-day-js" not in line   # the call itself stays out


def test_the_observer_look_replays_the_spool(machine, monkeypatch):
    seen = []
    monkeypatch.setattr(spool, "replay", lambda: seen.append(1) or 0)
    tracking.observe_now()
    assert seen


# --- the installed runner copy, as an agent runs it --------------------------------------------

STUCK_EVENTS = '''
import threading
def judge(body):
    threading.Event().wait(600)   # a judgement that never finishes in time (an overloaded machine)
def bookkeep(judged):
    pass
'''


def test_a_call_refused_because_it_could_not_be_checked_in_time_is_spooled_and_recorded(machine):
    """The refusal no judgement backs ("could not check this action in time") had no record at all."""
    from plugins.blackbox import agent_hooks
    plugin = machine / "fake-plugin"
    (plugin / "agent_hooks" / "protect").mkdir(parents=True)
    for package in (plugin / "agent_hooks", plugin / "agent_hooks" / "protect"):
        (package / "__init__.py").write_text("", encoding="utf-8")
    (plugin / "agent_hooks" / "protect" / "events.py").write_text(STUCK_EVENTS, encoding="utf-8")
    script = Path(agent_hooks._runner())
    (script.parent / judge_here.JUDGE_HERE_FILE).write_text(json.dumps(
        {"plugin": str(plugin), "blackbox_home": str(machine / "bb"), judge_here.SPOOL_KEY: str(spool.folder())}), encoding="utf-8")
    done = subprocess.run([sys.executable, str(script), "claude-code", "pre_tool", DOWN], input=json.dumps(INSTALL),
                          capture_output=True, text=True, timeout=60, check=False)
    assert "could not check this action in time" in done.stdout
    files = _spooled()
    assert len(files) == 1 and json.loads(files[0].read_text(encoding="utf-8"))["late"] is True
    assert spool.replay() == 1
    call = next(row for row in audit.read_audit(limit=50) if row.get("event") == "pre_tool_call")
    assert call["detail"]["decision"] == "block"
