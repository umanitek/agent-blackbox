"""Sandbox permissions — opening links and apps through Blackbox (``open-links`` / ``open-apps``)
(plugins/blackbox/shields/files/sandbox/brokered/, platform/macos/opener.py, shims.open_shim;
design "Sandbox permissions" 2026-11-23, build step 13, local-only).

Contracts (red on the base ed4152ceac: inside the sandbox ``open https://…`` failed with
LaunchServices' -54 — a ``gh auth login --web`` sign-in could not finish — and there was no way to
open a file in an app):
* a link is opened only when it is one http/https address with a host and no user name, the
  threat graph does not list it (and could be asked), and ``open-links`` allows it;
  ``file://`` and every other scheme are refused;
* a file is opened only in an installed app that does not run commands or drive other apps
  (never Terminal, iTerm, Script Editor, Automator, Shortcuts), only an existing file that is
  neither protected nor Blackbox's own, and only when ``open-apps`` allows it (ask by default);
* the ``open`` stand-in sends a link, ``open -a App file`` or a folder to the broker and refuses
  every other form;
* LaunchServices stays closed in the profile (``(deny lsopen)`` is in the never-list);
* (wave 9, KI-632's pattern for every broker) each door answers a JOB at once; the link's threat
  check and the opening run in it, failing closed (the job's ``refused``).
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading

import pytest

from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.shields.files import mode as files_mode
from plugins.blackbox.shields.files.sandbox import brokered, platform as sandbox_platform
from plugins.blackbox.shields.files.sandbox.brokered import open_apps, open_links
from plugins.blackbox.shields.files.sandbox.permissions import requests
from plugins.blackbox.shields.files.sandbox.platform.macos import opener, shims
from plugins.blackbox.shields.shield_api import ShieldApiError, ShieldContext
from tests.waiting import wait_until

MAC = pytest.mark.skipif(sys.platform != "darwin", reason="the open stand-in is macOS's")


@pytest.fixture(autouse=True)
def setting(monkeypatch, tmp_path):
    real = tmp_path.resolve()
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.setenv("BLACKBOX_HOME", str(real / "bb"))
    (real / "bb").mkdir()
    (real / "shop").mkdir()
    (real / "shop" / "a.pdf").write_text("pdf", encoding="utf-8")
    (real / "Vault").mkdir()
    (real / "Vault" / "s.pdf").write_text("s", encoding="utf-8")
    for app in ("Preview", "Terminal"):
        (real / "Applications" / f"{app}.app").mkdir(parents=True)
    monkeypatch.setattr(opener, "APP_FOLDERS", ("{home}/Applications",))
    state: dict = {"shields": {"file-shield": {"enabled": True, "protected": ["~/Vault"]}}}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)
    opened: list = []
    monkeypatch.setattr(sandbox_platform, "open_url", lambda url: opened.append(("url", url)) or 0)
    monkeypatch.setattr(sandbox_platform, "open_with", lambda app, files: opened.append((os.path.basename(app), files)) or 0)
    requests.reset()
    yield state, opened, real
    requests.reset()


def _context(block=""):
    return ShieldContext(network_indicators=lambda: None, ask_assistant=lambda message: None,
                         tool_call_verdict=lambda tool, args: {"decision": "block" if block and block in args["command"] else "",
                                                               "findings": []})


def _ended(started: dict) -> dict:
    """The action-job read once the job a door started has ended."""
    def ended():
        state = brokered.API_READS["action-job"](_context(), {"job": started["job"], "from": "0"})
        return state if state["done"] else None
    return wait_until(ended, what="the brokered action ended")


@pytest.mark.parametrize("argv", [["file:///etc/passwd"], ["javascript:alert(1)"], ["https://user:pw@example.com/"],
                                  ["https://"], ["https://a.example", "https://b.example"], ["https://x.example/\n"]])
def test_only_one_plain_web_link_is_opened(argv):
    with pytest.raises(ShieldApiError):
        open_links.parse(argv)


def test_a_link_is_opened_when_allowed_and_unlisted(setting):
    state, opened, _ = setting
    done = _ended(brokered.API_WRITES["open-link"](_context(), {"argv": ["https://github.com/login/device"], "pid": 4242}))
    assert done["exit"] == 0 and done["lines"] == ["Opened in your browser."] and opened == [("url", "https://github.com/login/device")]
    listed = _ended(brokered.API_WRITES["open-link"](_context(block="evil.example"), {"argv": ["https://evil.example/x"]}))
    assert listed["refused"] == open_links.LISTED and listed["exit"] == 1
    unknown = ShieldContext(network_indicators=lambda: None, ask_assistant=lambda message: None)
    asked_nothing = _ended(brokered.API_WRITES["open-link"](unknown, {"argv": ["https://github.com/"]}))
    assert asked_nothing["refused"] == open_links.LISTED   # the verdict can not be asked: refused (fail closed)
    state["agent_sandbox"] = {"permissions": [{"permission": "open-links", "mode": "block"}]}
    with pytest.raises(ShieldApiError) as blocked:
        brokered.API_WRITES["open-link"](_context(), {"argv": ["https://github.com/"]})
    assert blocked.value.status == 403 and len(opened) == 1


def test_a_link_is_answered_at_once_while_its_threat_check_is_slow(setting):
    """KI-632's pattern (wave 9): the threat check asks the graph's store, slow during the first
    sync; the door answers with the job before the check ends, and the link opens once it clears."""
    _, opened, _ = setting
    graph_answers = threading.Event()

    def slow_verdict(tool, args):
        assert graph_answers.wait(30)
        return {"decision": "", "findings": []}
    slow = ShieldContext(network_indicators=lambda: None, ask_assistant=lambda message: None, tool_call_verdict=slow_verdict)
    try:
        started = brokered.API_WRITES["open-link"](slow, {"argv": ["https://github.com/login/device"]})
        assert not brokered.API_READS["action-job"](slow, {"job": started["job"], "from": "0"})["done"] and opened == []
    finally:
        graph_answers.set()
    assert _ended(started)["exit"] == 0 and opened == [("url", "https://github.com/login/device")]


def test_a_check_that_fails_refuses_and_a_failing_open_is_told(setting, monkeypatch):
    _, opened, _ = setting
    def broken(tool, args):
        raise RuntimeError("store down")
    failing = ShieldContext(network_indicators=lambda: None, ask_assistant=lambda message: None, tool_call_verdict=broken)
    assert _ended(brokered.API_WRITES["open-link"](failing, {"argv": ["https://github.com/"]}))["refused"] and opened == []
    def cannot(url):
        raise OSError("no browser")
    monkeypatch.setattr(sandbox_platform, "open_url", cannot)
    done = _ended(brokered.API_WRITES["open-link"](_context(), {"argv": ["https://github.com/"]}))
    assert done["exit"] == 1 and "no browser" in done["lines"][0]


def test_a_file_opens_only_in_a_safe_app_and_never_a_kept_one(setting):
    state, opened, home = setting
    state["agent_sandbox"] = {"permissions": [{"permission": "open-apps", "mode": "allow"}]}
    done = _ended(brokered.API_WRITES["open-app"](_context(), {"argv": ["-a", "Preview", "a.pdf"], "cwd": str(home / "shop")}))
    assert done["lines"] == ["Opened in Preview."] and opened == [("Preview.app", [str(home / "shop" / "a.pdf")])]
    for argv, status in ((["-a", "Terminal", "a.pdf"], 403), (["-a", "Nope", "a.pdf"], 403), (["-a", "Preview", "../Vault/s.pdf"], 403),
                         (["-a", "Preview", str(home / "bb")], 403), (["-a", "Preview", "missing.pdf"], 400), (["a.pdf"], 400)):
        with pytest.raises(ShieldApiError) as refused:
            brokered.API_WRITES["open-app"](_context(), {"argv": argv, "cwd": str(home / "shop")})
        assert refused.value.status == status, argv
    assert len(opened) == 1


def test_an_action_job_gives_no_install_notice(setting):
    from plugins.blackbox.shields.files.sandbox import packages
    _ended(brokered.API_WRITES["open-link"](_context(), {"argv": ["https://github.com/"]}))
    assert packages.alerts() == []


def test_opening_an_app_asks_by_default(setting):
    _, opened, home = setting
    with pytest.raises(ShieldApiError) as waiting:
        brokered.API_WRITES["open-app"](_context(), {"argv": ["-a", "Preview", "a.pdf"], "cwd": str(home / "shop")})
    assert waiting.value.status == brokered.WAITING and requests.pending()[0].permission == "open-apps" and opened == []


def test_a_driver_app_is_never_found(setting):
    assert opener.find_app("Terminal") == "" and opener.find_app("Preview").endswith("Preview.app")


@MAC
@pytest.mark.parametrize("argv, routed", [
    (["https://github.com/login/device"], "open-link"), (["-a", "Preview", "a.pdf"], "open-app"), (["."], "open-app"),
    (["x.command"], "refused"), (["-R", "a.pdf"], "refused"), (["https://a", "https://b"], "refused"),
])
def test_the_open_stand_in_sends_only_what_blackbox_opens(tmp_path, argv, routed):
    python = tmp_path / "fake-python"
    python.write_text('#!/bin/sh\necho "broker $*"\n', encoding="utf-8")
    python.chmod(0o755)
    shim = tmp_path / "open"
    shim.write_text(shims.open_shim(str(tmp_path), str(python), "http://127.0.0.1:9700"), encoding="utf-8")
    shim.chmod(0o755)
    done = subprocess.run([str(shim), *argv], capture_output=True, text=True, timeout=30, cwd=str(tmp_path), check=False)
    if routed == "refused":
        assert done.returncode == 126 and "refused this (open)" in done.stderr
    else:
        assert f"--action {routed}" in done.stdout


@MAC
def test_launchservices_stays_in_the_never_list(setting):
    from plugins.blackbox.shields.files import sandbox
    from plugins.blackbox.shields.files.sandbox.platform.macos import profile as macos_profile
    text = sandbox.profiles.render_signed(sandbox.policy(files_mode.current()))
    assert "(deny lsopen)" in text.split(macos_profile.NEVER_MARK)[1]
