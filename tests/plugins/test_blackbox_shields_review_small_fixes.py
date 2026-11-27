"""Shields — three small review fixes (independent review 2026-11-26, finding 11):
brokered/stop.py, files/mode.py, network/protect/enforcement.py.

Contracts (red on the base 30b94edf83):
* a process the person was asked to stop is stopped only while it is the same process (same
  program, same start time): its number may go to another program before they answer;
* ``/private/tmp`` and ``/private/var`` (where macOS's ``/tmp`` and ``/var`` resolve) are too broad
  to protect, like ``/tmp`` and ``/var``;
* loading a block list builds the enforcement plan once, not once more on the next ask.
"""

from __future__ import annotations

import os

import pytest

from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.shields.files import mode as files_mode, sandbox
from plugins.blackbox.shields.files.sandbox import permissions, platform as sandbox_platform
from plugins.blackbox.shields.files.sandbox.brokered import stop
from plugins.blackbox.shields.files.sandbox.permissions import requests
from plugins.blackbox.shields.network import mode as network_mode
from plugins.blackbox.shields.network.protect import blocklists, enforcement


@pytest.fixture(autouse=True)
def setting(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    state: dict = {}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)
    requests.reset()
    yield state
    requests.reset()


def test_a_process_whose_number_was_reused_is_never_stopped(monkeypatch):
    now = {"facts": sandbox_platform.ProcessFacts(os.getuid(), "/opt/homebrew/bin/node", "node server.js", "Thu Nov 26 09:00:00 2026")}
    monkeypatch.setattr(sandbox_platform, "describe", lambda pid: now["facts"])
    stopped: list = []
    monkeypatch.setattr(sandbox_platform, "terminate", lambda pid: stopped.append(pid) or True)
    assert stop.on_refused(4242, "claude-code", "s-1", "/tmp") == "asked"
    [request] = requests.pending()
    now["facts"] = sandbox_platform.ProcessFacts(os.getuid(), "/usr/local/bin/editor", "editor notes.md", "Thu Nov 26 09:05:00 2026")
    permissions.answers.answer({"id": request.id, "choice": "once"}, act=sandbox.act_on)
    assert stopped == []


@pytest.mark.parametrize("place", ["/private/tmp", "/private/var", "/tmp", "/var"])
def test_the_resolved_system_folders_are_too_broad_to_protect(place):
    assert files_mode.canonical_item(place) is None


def test_loading_a_block_list_builds_the_plan_once(monkeypatch):
    loaded = {"ads": 0.0}
    builds: list = []
    monkeypatch.setattr(blocklists, "version", lambda pack_id: loaded.get(pack_id, 0.0))

    def build(mode, indicators, cut, syncing):
        loaded["ads"] = 1.0   # building loads the chosen list (its version changes)
        builds.append(1)
        return {"version": f"v{len(builds)}"}
    monkeypatch.setattr(enforcement, "_build_plan", build)
    monkeypatch.setitem(enforcement._plan_cache, "key", None)
    mode = network_mode.build(enabled=True, protections=(network_mode.DNS,))
    mode = network_mode.ShieldMode(enabled=True, options={**mode.options, network_mode.OPT_LISTS: ("ads",)})
    enforcement.plan(mode, None)
    enforcement.plan(mode, None)
    assert len(builds) == 1
