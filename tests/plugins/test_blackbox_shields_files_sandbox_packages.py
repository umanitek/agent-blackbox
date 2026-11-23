"""KI-593: Homebrew for sandboxed agents — Blackbox installs for them (founder decision, 2026-11-23).

Inside the agent sandbox ``brew install`` fails (Homebrew sandboxes its own installs; two sandboxes
can not nest). The ``brew`` shim on the sandboxed PATH sends install-type commands to Blackbox's
broker, which validates them, checks each name against the threat rules and runs a FIXED argv with
a clean environment. Contracts (real proof comes on the VM):

* validation refuses every injection form: taps, URLs, paths, build flags, valued flags, env;
* the argv Blackbox runs is fixed: Homebrew's own path, the verb, the validated names;
* a package a threat rule lists is refused, and so is every name when the verdict can't be asked;
* "ask me each time" holds each request for the person's approval; loosening the setting waits too;
* "off" refuses; an unreachable broker tells the agent to run brew in its own terminal.
"""

from __future__ import annotations

import io
import subprocess
import sys
import threading

import pytest

from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.kernel import settings as kernel_settings
from plugins.blackbox.shields.files.sandbox import packages
from plugins.blackbox.shields.files.sandbox.packages import client, jobs, request
from plugins.blackbox.shields.files.sandbox.platform import macos
from plugins.blackbox.shields.shield_api import ShieldApiError, ShieldContext


@pytest.fixture(autouse=True)
def setting(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    state: dict = {}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)
    jobs.reset()
    yield state
    jobs.reset()


def _context(verdict=lambda tool, args: {"decision": "", "findings": []}):
    return ShieldContext(network_indicators=lambda: None, ask_assistant=lambda message: None, tool_call_verdict=verdict)


@pytest.mark.parametrize("argv", [
    ["install", "someone/tap/evil"], ["install", "https://example.invalid/x.rb"], ["install", "./x.rb"],
    ["install", "/tmp/x.rb"], ["install", "--HEAD", "wget"], ["install", "--build-from-source", "wget"],
    ["install", "-s", "wget"], ["install", "--force", "wget"], ["install", "--appdir=/Applications", "x"],
    ["install", "Wget"], ["install", "wget;rm"], ["install", "$(id)"], ["install", "x" * 101],
    ["tap", "someone/tap"], ["install"], ["install", "--cask", "--formula", "x"], ["install", *(["a"] * 21)],
])
def test_every_injection_form_is_refused(argv):
    with pytest.raises(request.Refused):
        request.parse(argv)


def test_a_request_may_carry_nothing_but_the_brew_words():
    with pytest.raises(ShieldApiError):
        packages.API_WRITES["brew"](_context(), {"argv": ["install", "tree"], "env": {"HOMEBREW_PREFIX": "/x"}})


def test_official_taps_and_versions_are_names_and_the_argv_is_fixed():
    parsed = request.parse(["install", "--cask", "homebrew/cask/firefox", "python@3.12", "-q"])
    assert jobs.argv("/opt/homebrew/bin/brew", parsed) == ["/opt/homebrew/bin/brew", "install", "--cask", "--quiet",
                                                           "firefox", "python@3.12"]
    assert request.parse(["rm", "tree"]).verb == "uninstall"


def test_the_environment_is_clean(monkeypatch):
    monkeypatch.setenv("HOMEBREW_TAP_URL", "https://example.invalid")
    monkeypatch.setenv("DYLD_INSERT_LIBRARIES", "/x.dylib")
    env = jobs.clean_environment("/opt/homebrew/bin/brew")
    assert not {"HOMEBREW_TAP_URL", "DYLD_INSERT_LIBRARIES"} & set(env) and env["PATH"].startswith("/opt/homebrew/bin:")


def test_a_package_a_threat_rule_lists_is_refused(monkeypatch):
    monkeypatch.setattr(jobs, "brew_path", lambda: "/opt/homebrew/bin/brew")
    listed = lambda tool, args: {"decision": "", "findings": [{"source": "public"}]} if "evil-pkg" in args["command"] else {"findings": []}
    with pytest.raises(ShieldApiError) as refused:
        packages.API_WRITES["brew"](_context(listed), {"argv": ["install", "tree", "evil-pkg"]})
    assert "evil-pkg" in refused.value.message and "tree" not in refused.value.message
    with pytest.raises(ShieldApiError):   # the verdict can not be asked: fail closed
        packages.API_WRITES["brew"](_context(None), {"argv": ["install", "tree"]})


def test_an_allowed_install_runs_the_fixed_argv_and_streams_its_output(monkeypatch):
    ran, finished = [], threading.Event()

    def spawn(command, env, cwd):
        ran.append(command)
        return subprocess.Popen([sys.executable, "-c", "print('==> Pouring tree'); print('done')"],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    monkeypatch.setattr(jobs.platform, "spawn_brew", spawn)
    monkeypatch.setattr(jobs, "brew_path", lambda: "/opt/homebrew/bin/brew")
    monkeypatch.setattr(packages, "_record", lambda job: finished.set())
    started = packages.API_WRITES["brew"](_context(), {"argv": ["install", "tree"]})
    assert finished.wait(30)
    state = packages.API_READS["brew-job"](_context(), {"job": started["job"], "from": "0"})
    assert ran == [["/opt/homebrew/bin/brew", "install", "tree"]]
    assert state == {"lines": ["==> Pouring tree", "done"], "next": 2, "done": True, "exit": 0}
    assert any("installed tree" in row["text"] for row in packages.alerts())


def test_off_refuses_and_ask_holds_every_request_for_the_person(setting):
    setting["agent_packages"] = {"installs": "off"}
    with pytest.raises(ShieldApiError) as refused:
        packages.API_WRITES["brew"](_context(), {"argv": ["install", "tree"]})
    assert refused.value.status == 403
    setting["agent_packages"] = {"installs": "ask"}
    assert packages.weakening({"argv": ["install", "tree"]}) == ["Let an AI agent run `brew install tree` outside its sandbox (Homebrew)"]
    setting["agent_packages"] = {"installs": "allow"}
    assert packages.weakening({"argv": ["install", "tree"]}) == []


def test_loosening_the_setting_waits_for_the_person(setting):
    setting["agent_packages"] = {"installs": "ask"}
    assert packages.setting_weakening({"installs": "allow"})
    assert packages.setting_weakening({"installs": "off"}) == []
    errors: list = []
    assert kernel_settings.SECTION_VALIDATORS["agent_packages"]({"installs": "sometimes"}, errors) == {} and errors


def test_an_unreachable_broker_says_to_run_brew_in_your_own_terminal(capsys):
    assert client.main(["brew-client.py", "http://127.0.0.1:9", "install", "tree"]) == 1
    assert "Blackbox couldn't install this; run `brew install tree` in your own terminal." in capsys.readouterr().err


def test_the_shim_sends_installs_to_blackbox_and_runs_reads_as_they_are(tmp_path):
    shim = macos.brew_shim(str(tmp_path), "/usr/bin/python3", "http://127.0.0.1:9700")
    install = shim.split("case")[1].split("esac")[0]
    assert "install|upgrade|reinstall|uninstall" in install and "brew-client.py" in install
    assert 'exec "$real" "$@"' in shim.split("esac")[1]


@pytest.mark.skipif(sys.platform != "darwin", reason="the brew shim is macOS's")
def test_the_shim_and_its_client_land_in_the_sandbox_tools_folder_only(tmp_path):
    tools = tmp_path / "agent-bin" / macos.TOOLS_FOLDER
    tools.mkdir(parents=True)
    packages.install_shim(tools, "http://127.0.0.1:9700")
    assert (tools / "brew").stat().st_mode & 0o111 and (tools / packages.CLIENT_NAME).is_file()
    assert not (tmp_path / "agent-bin" / "brew").exists()   # the person's own PATH keeps the real brew


@pytest.mark.skipif(sys.platform != "darwin", reason="the brew shim is macOS's")
@pytest.mark.parametrize("argv, refused", [
    (["tap", "someone/evil-tap"], True), (["untap", "homebrew/cask"], True), (["link", "jq"], True), (["unlink", "jq"], True),
    (["pin", "jq"], True), (["services", "start", "postgresql"], True), (["autoremove"], True), (["cleanup"], True),
    (["tap"], False), (["list"], False), (["info", "jq"], False), (["--prefix"], False), ([], False),
])
def test_the_shim_refuses_every_command_that_changes_homebrew_and_runs_reads(tmp_path, argv, refused):
    """Security round 4: ``brew tap someone/evil-tap`` from inside the sandbox began cloning into the
    Taps folder; everything but a read or a brokered install is refused with the reason."""
    tools, real = tmp_path / "tools", tmp_path / "real"
    tools.mkdir()
    real.mkdir()
    (real / "brew").write_text("#!/bin/sh\necho REAL-BREW \"$@\"\n", encoding="utf-8")
    (real / "brew").chmod(0o755)
    (tools / "brew").write_text(macos.brew_shim(str(tools), "/usr/bin/python3", "http://127.0.0.1:9"), encoding="utf-8")
    (tools / "brew").chmod(0o755)
    done = subprocess.run([str(tools / "brew"), *argv], capture_output=True, text=True, timeout=10, check=False,
                          env={"PATH": f"{tools}:{real}:/usr/bin:/bin"})
    if refused:
        assert done.returncode == 126 and "Blackbox's sandbox refused this (brew" in done.stderr and "REAL-BREW" not in done.stdout
    else:
        assert done.returncode == 0 and done.stdout.startswith("REAL-BREW"), done.stderr
