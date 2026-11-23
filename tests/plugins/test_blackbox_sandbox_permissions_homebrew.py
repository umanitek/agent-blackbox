"""Sandbox permissions — Homebrew installs decided by the ``homebrew`` permission
(plugins/blackbox/shields/files/sandbox/packages; design "Sandbox permissions" 2026-11-23, build
step 9, local-only).

Contracts (red on the base ed4152ceac: "ask" held every install as one 428 approval, with no
per-agent or per-project rule and no Allow once / Always / Keep blocked):
* on "ask" the broker opens ONE request for the agent that asked and answers 423 while it waits;
* Allow once runs that exact request once — the next install asks again;
* Keep blocked refuses the retry (403);
* Always allows this agent in this project, and only there;
* a rule for one agent leaves another agent's install to its own rule.
"""

from __future__ import annotations

import pytest

from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.kernel import settings as kernel_settings
from plugins.blackbox.shields.files.sandbox import packages, permissions
from plugins.blackbox.shields.files.sandbox.packages import jobs
from plugins.blackbox.shields.files.sandbox.permissions import grants, requests
from plugins.blackbox.shields.shield_api import InstanceRef, ShieldApiError, ShieldContext


@pytest.fixture(autouse=True)
def setting(monkeypatch, tmp_path):
    real = tmp_path.resolve()
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.setenv("BLACKBOX_HOME", str(real / "bb"))
    for folder in ("shop", "other"):
        (real / folder).mkdir()
    state: dict = {"agent_sandbox": {"permissions": [{"permission": "homebrew", "mode": "ask"}]}}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)
    monkeypatch.setattr(kernel_settings, "_persist", lambda updates: state.update(updates) or True)
    monkeypatch.setattr(jobs, "brew_path", lambda: "/opt/homebrew/bin/brew")
    monkeypatch.setattr(jobs, "start", lambda request, brew, done, owner: type("Job", (), {"id": "job-1"})())
    requests.reset()
    grants.reset()
    yield state
    requests.reset()


def _context(agent="claude-code"):
    return ShieldContext(network_indicators=lambda: None, ask_assistant=lambda message: None,
                         tool_call_verdict=lambda tool, args: {"decision": "", "findings": []},
                         owner_of_pid=lambda pid: InstanceRef(agent, f"{agent}:s1", "", "shop"))


def _brew(tmp_path, folder="shop", argv=("install", "tree"), agent="claude-code"):
    return packages.API_WRITES["brew"](_context(agent), {"argv": list(argv), "pid": 4242, "cwd": str(tmp_path.resolve() / folder)})


def _status(call) -> int:
    try:
        call()
    except ShieldApiError as error:
        return error.status
    return 200


def _answer(choice):
    [request] = requests.pending()
    return permissions.answers.answer({"id": request.id, "choice": choice}, once_profile=lambda request: None)


def test_ask_opens_one_request_and_waits(tmp_path):
    assert _status(lambda: _brew(tmp_path)) == packages.WAITING
    assert _status(lambda: _brew(tmp_path)) == packages.WAITING
    [request] = requests.pending()
    assert (request.agent, request.instance, request.project, request.what) == ("claude-code", "claude-code:s1", "~/shop",
                                                                                  "brew install tree")


def test_allow_once_runs_that_request_once(tmp_path):
    _status(lambda: _brew(tmp_path))
    _answer("once")
    assert _brew(tmp_path)["job"] == "job-1"
    assert _status(lambda: _brew(tmp_path)) == packages.WAITING          # the next install asks again


def test_a_once_grant_does_not_run_a_different_request(tmp_path):
    _status(lambda: _brew(tmp_path))
    _answer("once")
    assert _status(lambda: _brew(tmp_path, argv=("install", "wget"))) == packages.WAITING


def test_keep_blocked_refuses_the_retry(tmp_path):
    _status(lambda: _brew(tmp_path))
    _answer("keep-blocked")
    assert _status(lambda: _brew(tmp_path)) == 403


def test_always_allows_this_agent_in_this_project_only(tmp_path, setting):
    _status(lambda: _brew(tmp_path))
    _answer("always")
    assert {"permission": "homebrew", "mode": "allow", "agent": "claude-code", "project": "~/shop"} in setting["agent_sandbox"]["permissions"]
    assert _brew(tmp_path)["job"] == "job-1"
    assert _status(lambda: _brew(tmp_path, folder="other")) == packages.WAITING
    assert _status(lambda: _brew(tmp_path, agent="codex")) == packages.WAITING
