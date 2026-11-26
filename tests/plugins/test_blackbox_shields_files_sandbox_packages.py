"""KI-593: Homebrew for sandboxed agents — Blackbox installs for them (founder decision, 2026-11-23).

Inside the agent sandbox ``brew install`` fails (Homebrew sandboxes its own installs; two sandboxes
can not nest). The ``brew`` shim on the sandboxed PATH sends install-type commands to Blackbox's
broker, which validates them, checks each name against the threat rules and runs a FIXED argv with
a clean environment. Contracts (real proof comes on the VM):

* validation refuses every injection form: taps, URLs, paths, build flags, valued flags, env;
* the argv Blackbox runs is fixed: Homebrew's own path, the verb, the validated names;
* a package a threat rule lists is refused, and so is every name when the verdict can't be asked
  (the job's refusal: the request is answered at once and checked in its job, KI-632);
* "ask" asks the person (the ``homebrew`` sandbox permission); loosening the setting waits too;
* "off" refuses; an unreachable broker tells the agent to run brew in its own terminal;
* the notice follows what Homebrew did: a package it says it left as it was is not "installed" (KI-639).

KI-632 (security round 6, clean VM): during the first threat-graph sync the broker held the agent's
request while it asked the graph's busy store, the client gave up after 10 s and said only "Blackbox
couldn't install this". Now the request is answered at once, a busy dashboard's reads are asked
again for a bounded time, and a give-up says why.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.kernel import settings as kernel_settings
from plugins.blackbox.shields.files.sandbox import packages
from plugins.blackbox.shields.files.sandbox.packages import client, jobs, request
from plugins.blackbox.shields.files.sandbox.platform import macos
from plugins.blackbox.shields.shield_api import ShieldApiError, ShieldContext
from tests.waiting import wait_until


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


def test_the_persons_own_harmless_homebrew_preferences_are_kept(monkeypatch, tmp_path):
    """KI-613 (round 5, bb-r5-clean): the person's ~/.zprofile sets HOMEBREW_NO_AUTO_UPDATE=1 and
    HOMEBREW_NO_INSTALL_CLEANUP=1; the broker's clean environment dropped them, so Homebrew
    auto-updated and ran cleanup. Kept now — only the allow-listed "turn it off" ones, only the
    person's (their startup files or the dashboard's own environment), never one that changes
    where packages come from."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("HOMEBREW_NO_ANALYTICS", raising=False)
    (tmp_path / ".zprofile").write_text('eval "$(/opt/homebrew/bin/brew shellenv)"\nexport HOMEBREW_NO_AUTO_UPDATE=1\n'
                                        "export HOMEBREW_NO_INSTALL_CLEANUP='1'  # keep old versions\n"
                                        "export HOMEBREW_NO_INSTALL_FROM_API=1\nexport HOMEBREW_NO_AUTO_UPDATE=$(evil)\n",
                                        encoding="utf-8")
    monkeypatch.setenv("HOMEBREW_NO_ANALYTICS", "1")
    monkeypatch.setenv("HOMEBREW_NO_GITHUB_API", "$(touch /tmp/x)")
    env = jobs.clean_environment("/opt/homebrew/bin/brew")
    assert env["HOMEBREW_NO_AUTO_UPDATE"] == "1" and env["HOMEBREW_NO_INSTALL_CLEANUP"] == "1" and env["HOMEBREW_NO_ANALYTICS"] == "1"
    assert "HOMEBREW_NO_INSTALL_FROM_API" not in env and "HOMEBREW_NO_GITHUB_API" not in env
    assert env["HOMEBREW_NO_ENV_HINTS"] == "1" and env["HOME"] == str(tmp_path)


def _ended(started: dict) -> dict:
    """The brew-job read once the job has ended."""
    def ended():
        state = packages.API_READS["brew-job"](_context(), {"job": started["job"], "from": "0"})
        return state if state["done"] else None
    return wait_until(ended, what="the job ended")


def test_a_package_a_threat_rule_lists_is_refused(monkeypatch):
    ran = []
    monkeypatch.setattr(jobs, "brew_path", lambda: "/opt/homebrew/bin/brew")
    monkeypatch.setattr(jobs.platform, "spawn_brew", lambda command, env, cwd: ran.append(command))
    listed = lambda tool, args: {"decision": "", "findings": [{"source": "public"}]} if "evil-pkg" in args["command"] else {"findings": []}
    state = _ended(packages.API_WRITES["brew"](_context(listed), {"argv": ["install", "tree", "evil-pkg"]}))
    assert "evil-pkg" in state["refused"] and "tree" not in state["refused"] and state["exit"] == 1
    state = _ended(packages.API_WRITES["brew"](_context(None), {"argv": ["install", "tree"]}))   # can not be asked: fail closed
    assert state["refused"] and state["exit"] == 1
    assert ran == [] and packages.alerts() == []   # nothing ran, so no "installed" notice


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


def test_off_refuses_and_ask_puts_the_question_to_the_person(setting, monkeypatch):
    """Sandbox permissions step 9: "ask" is the homebrew permission's three answers, not one 428 per install."""
    from plugins.blackbox.shields.files.sandbox.permissions import requests
    monkeypatch.setattr(jobs, "brew_path", lambda: "/opt/homebrew/bin/brew")
    monkeypatch.setattr(jobs, "start", lambda request, brew, **_: type("Job", (), {"id": "j1"})())
    requests.reset()
    setting["agent_packages"] = {"installs": "off"}
    with pytest.raises(ShieldApiError) as refused:
        packages.API_WRITES["brew"](_context(), {"argv": ["install", "tree"]})
    assert refused.value.status == 403
    setting["agent_packages"] = {"installs": "ask"}
    with pytest.raises(ShieldApiError) as waiting:
        packages.API_WRITES["brew"](_context(), {"argv": ["install", "tree"]})
    assert waiting.value.status == packages.WAITING
    [asked] = requests.pending()
    assert (asked.permission, asked.what) == ("homebrew", "brew install tree")
    setting["agent_sandbox"] = {"permissions": [{"permission": "homebrew", "mode": "allow"}]}
    assert packages.API_WRITES["brew"](_context(), {"argv": ["install", "tree"]})["job"] == "j1"
    requests.reset()


def test_loosening_the_setting_waits_for_the_person(setting):
    setting["agent_packages"] = {"installs": "ask"}
    assert packages.setting_weakening({"installs": "allow"})
    assert packages.setting_weakening({"installs": "off"}) == []
    errors: list = []
    assert kernel_settings.SECTION_VALIDATORS["agent_packages"]({"installs": "sometimes"}, errors) == {} and errors


def test_an_unreachable_broker_says_to_run_brew_in_your_own_terminal(capsys):
    assert client.main(["brew-client.py", "http://127.0.0.1:9", "install", "tree"]) == 1
    said = capsys.readouterr().err
    assert "Blackbox couldn't install this: Blackbox is not answering" in said and "Nothing was installed" in said
    assert "run `brew install tree` in your own terminal." in said


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


def test_the_install_notice_and_audit_row_name_the_agent_that_asked(monkeypatch, tmp_path):
    """KI-605 (round 4, s4-br1): "Blackbox installed hello with Homebrew for an AI agent." named no
    agent, session or project; the client now sends its parent's pid and the broker asks the agent
    tracker whose process that is (by ancestry, never guessed)."""
    from plugins.blackbox import audit
    from plugins.blackbox.shields.shield_api import InstanceRef
    finished = threading.Event()
    monkeypatch.setattr(jobs.platform, "spawn_brew", lambda command, env, cwd: subprocess.Popen(
        [sys.executable, "-c", "print('ok')"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True))
    monkeypatch.setattr(jobs, "brew_path", lambda: "/opt/homebrew/bin/brew")
    real_record = packages._record
    monkeypatch.setattr(packages, "_record", lambda job: (real_record(job), finished.set()))
    asked = []
    context = ShieldContext(network_indicators=lambda: None, ask_assistant=lambda message: None,
                            tool_call_verdict=lambda tool, args: {"decision": "", "findings": []},
                            owner_of_pid=lambda pid: asked.append(pid) or InstanceRef("claude-code", "claude-code:ab12", "", "s4-br1"))
    packages.API_WRITES["brew"](context, {"argv": ["install", "hello"], "pid": 4242})
    assert finished.wait(30) and asked == [4242]
    assert any(row["text"] == "Blackbox installed hello with Homebrew for Claude Code in s4-br1." and row["agent"] == "claude-code"
               for row in packages.alerts())
    [row] = [row for row in audit.read_audit(limit=50) if row.get("event") == "package_install"]
    assert row["detail"]["session_id"] == "claude-code:ab12" and row["workspace"] == "s4-br1"
    unknown = ShieldContext(network_indicators=lambda: None, ask_assistant=lambda message: None,
                            tool_call_verdict=lambda tool, args: {"decision": "", "findings": []}, owner_of_pid=lambda pid: None)
    assert packages._asker(unknown, {"argv": ["install", "x"], "pid": 1}) is None


def test_the_broker_answers_at_once_while_the_threat_check_is_slow(monkeypatch):
    """KI-632: the threat check asks the graph's store, slow during the first sync. The request is
    answered with its job before the check ends; the job runs once the check clears it."""
    graph_answers, answered, finished = threading.Event(), threading.Event(), threading.Event()

    def slow_verdict(tool, args):
        assert graph_answers.wait(30)
        return {"decision": "", "findings": []}
    monkeypatch.setattr(jobs.platform, "spawn_brew", lambda command, env, cwd: subprocess.Popen(
        [sys.executable, "-c", "print('==> Pouring hello')"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True))
    monkeypatch.setattr(jobs, "brew_path", lambda: "/opt/homebrew/bin/brew")
    monkeypatch.setattr(packages, "_record", lambda job: finished.set())
    started: dict = {}
    threading.Thread(target=lambda: (started.update(packages.API_WRITES["brew"](_context(slow_verdict), {"argv": ["install", "hello"]})),
                                     answered.set()), daemon=True).start()
    try:
        assert answered.wait(10), "the request waited for the threat check"
        assert not packages.API_READS["brew-job"](_context(), {"job": started["job"], "from": "0"})["done"]
    finally:
        graph_answers.set()
    assert finished.wait(30)
    assert _ended(started)["lines"] == ["==> Pouring hello"]


class _Dashboard:
    """A loopback stand-in for Blackbox's dashboard. *slow*: the request kinds ("session", "job")
    whose FIRST request gets no answer until the client asks again (a busy dashboard, then an
    answering one); *silent*: nothing is ever answered; *job*: what the job read answers."""

    def __init__(self, slow=(), silent=False, job=None):
        self.slow, self.silent, self.job = set(slow), silent, job or {}
        self.asked: dict = {}
        self.again = {kind: threading.Event() for kind in ("session", "brew", "job")}
        self.closing = threading.Event()
        dashboard = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                dashboard.answer(self, "session" if self.path == "/api/session" else "job")

            def do_POST(self):
                self.rfile.read(int(self.headers.get("content-length") or 0))
                dashboard.answer(self, "brew")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def answer(self, handler, kind):
        nth = self.asked[kind] = self.asked.get(kind, 0) + 1
        if nth > 1:
            self.again[kind].set()
        if self.silent:
            self.closing.wait(30)
            return
        if nth == 1 and kind in self.slow:
            self.again[kind].wait(30)   # busy: answers only after the client gave up on it and asked again
        body = {"session": {"token": "t"}, "brew": {"job": "j1", "command": "brew install hello"}, "job": self.job}[kind]
        try:
            data = json.dumps(body).encode()
            handler.send_response(200)
            handler.send_header("content-type", "application/json")
            handler.send_header("content-length", str(len(data)))
            handler.end_headers()
            handler.wfile.write(data)
        except OSError:
            pass   # the client gave up on this one already

    def close(self):
        self.closing.set()
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def dashboard(monkeypatch):
    monkeypatch.setattr(client, "ANSWER_SECONDS", 0.3)
    monkeypatch.setattr(client, "POLL_SECONDS", 0)
    made = []
    yield lambda **kwargs: made.append(_Dashboard(**kwargs)) or made[-1]
    for each in made:
        each.close()


def test_a_busy_dashboard_is_asked_again_and_the_install_goes_through(dashboard, capsys):
    """KI-632, round 6: during the first sync the dashboard answered late; the client gave up after
    10 s. Now a read with no answer is asked again, and the install goes through."""
    busy = dashboard(slow=("session", "job"), job={"lines": ["==> Pouring hello"], "next": 1, "done": True, "exit": 0})
    assert client.main(["brew-client.py", busy.url, "install", "hello"]) == 0
    assert "==> Pouring hello" in capsys.readouterr().out
    assert busy.asked == {"session": 2, "brew": 1, "job": 2}   # the install itself was asked for once


def test_a_dashboard_that_never_answers_is_given_up_on_with_the_reason(dashboard, monkeypatch, capsys):
    monkeypatch.setattr(client, "BUSY_SECONDS", 1)
    silent = dashboard(silent=True)
    assert client.main(["brew-client.py", silent.url, "install", "hello"]) == 1
    said = capsys.readouterr().err
    assert "it was busy and did not answer within 1 s" in said and "Nothing was installed" in said
    assert "try again in a minute, or run `brew install hello` in your own terminal" in said
    assert "brew" not in silent.asked   # nothing was asked to run


def test_a_refusal_in_the_job_is_told_to_the_agent(dashboard, capsys):
    refusing = dashboard(job={"lines": [], "next": 0, "done": True, "exit": 1,
                              "refused": "evil-pkg: a threat rule lists this package, so Blackbox will not install it"})
    assert client.main(["brew-client.py", refusing.url, "install", "evil-pkg"]) == 1
    assert ("Blackbox's sandbox refused this (brew install evil-pkg): evil-pkg: a threat rule lists this package"
            in capsys.readouterr().err)


def test_a_brokered_action_waits_on_a_busy_dashboard_and_follows_its_job(dashboard, capsys):
    """Wave 9 (KI-632's pattern for every broker): ``open`` / ``osascript`` used one 10 s request;
    now the session read is asked again while busy, the action asked for once, its job followed."""
    busy = dashboard(slow=("session", "job"), job={"lines": ["Opened in your browser."], "next": 1, "done": True, "exit": 0})
    assert client.main(["brew-client.py", busy.url, "--action", "open-link", "https://github.com/login/device"]) == 0
    assert "Opened in your browser." in capsys.readouterr().out
    assert busy.asked == {"session": 2, "brew": 1, "job": 2}


def test_a_brokered_action_given_up_on_says_why_and_that_nothing_was_done(dashboard, monkeypatch, capsys):
    monkeypatch.setattr(client, "BUSY_SECONDS", 1)
    silent = dashboard(silent=True)
    assert client.main(["brew-client.py", silent.url, "--action", "open-link", "https://github.com/"]) == 1
    said = capsys.readouterr().err
    assert "Blackbox couldn't do this: it was busy and did not answer within 1 s" in said and "Nothing was done" in said
    assert "run `open https://github.com/` in your own terminal" in said and "brew" not in silent.asked


def test_a_brokered_actions_refusal_in_the_job_is_told(dashboard, capsys):
    refusing = dashboard(job={"lines": [], "next": 0, "done": True, "exit": 1, "refused": "a threat rule lists this address"})
    assert client.main(["brew-client.py", refusing.url, "--action", "open-link", "https://evil.example/"]) == 1
    assert "Blackbox's sandbox refused this (open https://evil.example/): a threat rule lists this address" in capsys.readouterr().err


@pytest.mark.parametrize("argv, line, left", [
    (["install", "tree"], "Warning: tree 2.3.2 is already installed", "tree"),            # round 6, word for word
    (["install", "tree"], "Warning: tree 2.3.2 is already installed and up-to-date.", "tree"),
    (["install", "tree"], "Warning: tree 2.3.2 is already installed, it's just not linked.", "tree"),
    (["upgrade", "tree"], "Warning: tree 2.3.2 already installed", "tree"),
    (["install", "--cask", "firefox"], "Warning: Cask 'firefox' is already installed.", "firefox"),
    (["upgrade", "--cask", "firefox"], "Warning: Not upgrading firefox, the latest version is already installed", "firefox"),
    (["install", "tree"], "==> Pouring tree--2.3.2.arm64_sequoia.bottle.tar.gz", ""),
    (["install", "tree"], "Warning: wget 1.25.0 is already installed", ""),                 # not a name it asked for
    (["reinstall", "tree"], "Warning: tree 2.3.2 is already installed", ""),               # a reinstall always changes it
])
def test_homebrews_own_words_say_which_package_it_left_as_it_was(argv, line, left):
    assert request.parse(argv).unchanged(line) == left


def _run_printing(monkeypatch, argv, *lines):
    """Runs a brokered brew whose output is *lines* (exit 0); answers the job once recorded."""
    finished = threading.Event()
    script = "".join(f"print({line!r});" for line in lines)
    monkeypatch.setattr(jobs.platform, "spawn_brew", lambda command, env, cwd: subprocess.Popen(
        [sys.executable, "-c", script], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True))
    monkeypatch.setattr(jobs, "brew_path", lambda: "/opt/homebrew/bin/brew")
    real_record = packages._record
    monkeypatch.setattr(packages, "_record", lambda job: (real_record(job), finished.set()))
    started = packages.API_WRITES["brew"](_context(), {"argv": argv})
    assert finished.wait(30)
    return started


def test_a_second_install_of_a_package_already_there_sends_no_installed_notice(monkeypatch):
    """KI-639 (round 6, s6-br13): the second `brew install tree` printed "Warning: tree 2.3.2 is
    already installed", yet a second "Blackbox installed tree with Homebrew …" notice was sent."""
    from plugins.blackbox import audit
    _run_printing(monkeypatch, ["install", "tree"], "==> Pouring tree--2.3.2.arm64_sequoia.bottle.tar.gz")
    _run_printing(monkeypatch, ["install", "tree"], "Warning: tree 2.3.2 is already installed")
    assert [row["text"] for row in packages.alerts()] == ["Blackbox installed tree with Homebrew for an AI agent."]
    rows = [row["detail"] for row in audit.read_audit(limit=50) if row.get("event") == "package_install"]
    assert sorted(row.get("unchanged", []) for row in rows) == [[], ["tree"]]   # the no-op run is still recorded


def test_the_notice_names_only_what_homebrew_installed(monkeypatch):
    _run_printing(monkeypatch, ["install", "tree", "hello"], "Warning: tree 2.3.2 is already installed",
                  "==> Pouring hello--2.12.2.arm64_sequoia.bottle.tar.gz")
    assert [row["text"] for row in packages.alerts()] == ["Blackbox installed hello with Homebrew for an AI agent."]
