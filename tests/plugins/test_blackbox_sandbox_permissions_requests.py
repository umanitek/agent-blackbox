"""Sandbox permissions — requests, the person's answer and allow-once grants
(plugins/blackbox/shields/files/sandbox/permissions/{requests,answers,grants}.py, profiles.write_once,
platform/macos/launchers.pick_profile; design "Sandbox permissions" 2026-11-23, build step 8, local-only).

Contracts (red on the base ed4152ceac: no requests, no permission-answer, no once profiles):
* a refusal the agent's hook saw opens ONE request when its permission is on "ask" (none on
  block), with the agent and instance Blackbox attributed; de-duplicated per (instance,
  permission), cooled down after "Keep blocked", bounded, its words capped;
* through the REAL approval gate: Allow once and Always wait for the person (server-built words),
  Keep blocked is applied at once; AppleScript is never offered "always";
* Always writes the rule for this agent in this project (F3);
* a broker's once grant is used exactly once, and not after it expires;
* a profile's once grant: the agent's next launch alone runs in it — of two launches at once
  exactly one — never a launch inside the sandbox, and not once it is older than 30 minutes;
* an open request is a File Shield alert naming the agent and the permission only.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest

from plugins.blackbox import approvals
from plugins.blackbox.agent_hooks.protect import sandbox_errors
from plugins.blackbox.dashboard.shields_routes import api_routes
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.kernel import settings as kernel_settings
from plugins.blackbox.shields.files import alerts, api, mode as files_mode, sandbox
from plugins.blackbox.shields.files.sandbox import permissions, profiles
from plugins.blackbox.shields.files.sandbox.permissions import Scope, grants, requests
from plugins.blackbox.shields.files.sandbox.platform.macos import profile as macos_profile

REAL = pytest.mark.skipif(sys.platform != "darwin" or not os.access(macos_profile.SANDBOX_EXEC, os.X_OK),
                          reason="a real Seatbelt sandbox needs macOS")


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    real = tmp_path.resolve()
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.setenv("BLACKBOX_HOME", str(real / "bb"))
    (real / "shop").mkdir()
    requests.reset()
    grants.reset()
    yield real
    requests.reset()


@pytest.fixture
def entry(monkeypatch):
    state: dict = {"shields": {"file-shield": {"enabled": True, "protected": [], "sandboxed": ["claude-code"]}}}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)

    def persist(updates):
        state.update(updates)
        return True

    monkeypatch.setattr(kernel_settings, "_persist", persist)
    return state


def _seen(kind, home, instance="s-1", agent="claude-code"):
    sandbox_errors.on_sandbox_refusal(api_routes._ask_on_refusal)
    sandbox_errors.emit([sandbox_errors.Refusal(kind)], agent, instance, str(home / "shop"), 4242)


def test_a_refusal_opens_one_request_only_while_its_permission_asks(entry, home):
    _seen(sandbox_errors.OPEN_APP, home)                       # open-apps: ask by default
    _seen(sandbox_errors.OPEN_APP, home)                       # the same instance again: no second
    [request] = requests.pending()
    assert (request.permission, request.agent, request.instance, request.project) == ("open-apps", "claude-code", "s-1", "~/shop")
    _seen(sandbox_errors.APP_DRIVER, home)                   # applescript: block by default
    assert [each.permission for each in requests.pending()] == ["open-apps"]


def test_requests_are_bounded_and_cooled_down(home):
    for index in range(requests.MAX_PER_MINUTE + 3):
        requests.raise_request("docker", "codex", f"s-{index}", "", "x" * 500, now=1000.0)
    assert len(requests.pending()) == requests.MAX_PER_MINUTE
    assert all(len(each.what) == requests.MAX_WHAT_CHARS for each in requests.pending())
    first = requests.pending()[0]
    requests.take(first.id)
    requests.keep_blocked(first, now=1000.0)
    assert requests.raise_request("docker", "codex", first.instance, "", "", now=1100.0) is None
    assert requests.raise_request("docker", "codex", first.instance, "", "", now=1000.0 + requests.COOLDOWN_SECONDS + 61) is not None


def _gate(body):
    return approvals.reasons("/api/shields/file-shield/api/permission-answer", body, approvals.Current())


def test_once_and_always_wait_for_the_person_and_keep_blocked_does_not(entry, home):
    _seen(sandbox_errors.OPEN_APP, home)
    [request] = requests.pending()
    assert _gate({"id": request.id, "choice": "once"}) == ['Let Claude Code in ~/shop use Opening files in apps once ("Opening files in apps")']
    assert _gate({"id": request.id, "choice": "always"})[0].endswith("from now on (\"Opening files in apps\")")
    assert _gate({"id": request.id, "choice": "keep-blocked"}) == []
    api.API.writes["permission-answer"](None, {"id": request.id, "choice": "keep-blocked"})
    assert requests.pending() == []
    _seen(sandbox_errors.OPEN_APP, home)
    assert requests.pending() == []                             # cooled down


def test_always_writes_the_rule_for_this_agent_in_this_project(entry, home):
    _seen(sandbox_errors.OPEN_APP, home)
    [request] = requests.pending()
    answer = api.API.writes["permission-answer"](None, {"id": request.id, "choice": "always"})
    assert answer["choice"] == "always" and answer["requests"] == []
    assert entry["agent_sandbox"]["permissions"] == [{"permission": "open-apps", "mode": "allow", "agent": "claude-code",
                                                      "project": "~/shop"}]


def test_applescript_is_never_offered_always(home):
    request = requests.raise_request("applescript", "codex", "s-9", "", "")
    assert permissions.answers.choices(request) == ["once", "keep-blocked"]


def test_a_broker_grant_is_used_once_and_not_after_it_expires():
    scope = Scope(agent="codex")
    grants.grant(permissions.model.OnceGrant("homebrew", scope, "d1", time.time() + grants.ONCE_SECONDS))
    assert grants.use("homebrew", scope, "d1") is True and grants.use("homebrew", scope, "d1") is False
    grants.grant(permissions.model.OnceGrant("homebrew", scope, "d2", time.time() + 1))
    assert grants.use("homebrew", scope, "d2", now=time.time() + 5) is False
    assert grants.use("homebrew", Scope(agent="claude-code"), "d1") is False


def test_an_open_request_is_an_alert_naming_the_agent_and_permission_only(entry, home):
    _seen(sandbox_errors.OPEN_APP, home)
    [alert] = [row for row in alerts.alerts() if row["kind"] == "permission-request"]
    assert alert["text"].startswith("Claude Code wants to use Opening files in apps.") and "shop" not in alert["text"]


def test_a_request_from_an_unknown_agent_reads_an_agent_in_the_project():
    """The Waiting list's words for a request whose agent Blackbox could not name (a refusal seen
    with no agent, security round 7's harness runs): "An agent in <project> wants to use …", as
    the companion app's dialog says — never a sentence that starts with a blank."""
    request = requests.raise_request("docker", "", "", "s7-dock1", "Docker")
    row = permissions.answers.row(request)
    assert row["text"] == "An agent in s7-dock1 wants to use Docker." and row["agent_name"] == "An agent"
    assert permissions.answers.weakening({"id": request.id, "choice": "once"}) == ["Let An agent in s7-dock1 use Docker once (\"Docker\")"]
    [alert] = [each for each in alerts.alerts() if each["kind"] == "permission-request"]
    assert alert["text"].startswith("An agent wants to use Docker.") and "s7-dock1" not in alert["text"]
    named = requests.raise_request("docker", "claude-code", "s-2", "shop", "Docker")
    assert permissions.answers.row(named)["text"] == "Claude Code in shop wants to use Docker."


def _launcher_env(home):
    fake = home / "fakebin"
    fake.mkdir(exist_ok=True)
    agent = fake / "claude"
    agent.write_text("#!/bin/sh\necho \"profile=${BLACKBOX_SANDBOX_PROFILE:-none}\"\nsleep 0.3\n", encoding="utf-8")
    agent.chmod(0o755)
    env = {**os.environ, "PATH": f"{sandbox.launcher_dir()}:{fake}:/usr/bin:/bin"}
    env.pop("BLACKBOX_AGENT_SANDBOX", None)
    env.pop("BLACKBOX_SANDBOX_PROFILE", None)
    return env


@REAL
def test_a_profile_grant_is_taken_by_exactly_one_launch(entry, home):
    sandbox.sync(files_mode.build(enabled=True, sandboxed=("claude-code",)))
    request = requests.raise_request("docker", "claude-code", "s-1", "~/shop", "Docker")
    once = profiles.write_once(sandbox.policy(files_mode.current()), request, permissions.current())
    assert once.name == "claude-code.once.sb" and once.is_file()
    env = _launcher_env(home)
    inside = subprocess.run([macos_profile.SANDBOX_EXEC, "-f", str(sandbox.profile_path()), "claude"], capture_output=True,
                            text=True, timeout=30, env=env, cwd=str(home / "shop"), check=False)   # the canary proves it
    assert "profile=none" in inside.stdout and once.is_file()     # inside a sandbox: nothing taken
    launches = [subprocess.Popen(["claude"], stdout=subprocess.PIPE, text=True, env=env, cwd=str(home / "shop")) for _ in range(2)]
    outputs = [launch.communicate(timeout=30)[0] for launch in launches]
    assert sum(".run." in output for output in outputs) == 1 and not once.exists()
    later = subprocess.run(["claude"], capture_output=True, text=True, timeout=30, env=env, cwd=str(home / "shop"), check=False)
    assert f"profile={sandbox.layout.agent_profile('claude-code')}" in later.stdout


@REAL
def test_an_old_profile_grant_is_not_used(entry, home):
    sandbox.sync(files_mode.build(enabled=True, sandboxed=("claude-code",)))
    request = requests.raise_request("docker", "claude-code", "s-1", "", "Docker")
    once = profiles.write_once(sandbox.policy(files_mode.current()), request, permissions.current())
    old = time.time() - 31 * 60
    os.utime(once, (old, old))
    done = subprocess.run(["claude"], capture_output=True, text=True, timeout=30, env=_launcher_env(home), cwd=str(home), check=False)
    assert f"profile={sandbox.layout.agent_profile('claude-code')}" in done.stdout
