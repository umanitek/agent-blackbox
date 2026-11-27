"""Shields — one bad stored entry drops itself, never the whole list or section
(plugins/blackbox/shields/setting_lists.py, files/mode.py, network/mode.py,
files/sandbox/permissions/section.py; independent review 2026-11-26, findings 4 and 5).

Contracts (red on the base 30b94edf83):
* File Shield: an invalid item beside a good one leaves the good one protected; an unknown agent
  id in ``sandboxed`` leaves every known agent in the sandbox;
* Network Shield: one bad ``block`` entry leaves the others blocked; a duplicate in
  ``protections`` folds, it never turns the protections off;
* sandbox permissions: one bad row leaves every other rule and folder rule in force (``docker:
  block``, ``~/other: read``), the more protective of two rules for one scope wins, and the
  problems are named for the card (``problems``), never silently.
"""

from __future__ import annotations

import pytest

from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.shields.files import mode as files_mode
from plugins.blackbox.shields.files.sandbox import permissions
from plugins.blackbox.shields.network import mode as network_mode


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    real = tmp_path.resolve()
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.setenv("BLACKBOX_HOME", str(real / "bb"))
    (real / "Taxes").mkdir()
    (real / "other").mkdir()
    return real


def _files(**section):
    return files_mode.from_entry({"shields": {"file-shield": {"enabled": True, **section}}})


def test_file_shield_keeps_every_good_item_and_agent():
    mode = _files(protected=["~/Taxes", "Documents/x"], sandboxed=["claude-code", "no-such-agent", "windsurf", "codex"])
    assert files_mode.protected(mode) == ("~/Taxes",)
    assert mode.options[files_mode.OPT_SANDBOXED] == ("claude-code", "codex")
    assert len(mode.problems) == 3 and mode.as_json()["problems"] == list(mode.problems)
    assert "Documents/x" not in " ".join(mode.problems)   # named by position, never by the person's path


def test_network_shield_keeps_every_good_entry_and_folds_duplicates():
    mode = network_mode.from_entry({"shields": {"network-shield": {
        "enabled": True, "block": ["evil.example", "not a host", "bad.example"],
        "protections": ["dns", "firewall", "cut", "ssh-lockdown", "lockdown", "dns"]}}})
    assert network_mode.option(mode, network_mode.OPT_BLOCK) == ("evil.example", "bad.example")
    assert network_mode.protections(mode) == ("dns", "firewall", "cut", "ssh-lockdown", "lockdown")
    assert len(mode.problems) == 1


def test_a_clean_setting_has_no_problems_and_shows_none():
    mode = _files(protected=["~/Taxes"])
    assert mode.problems == () and "problems" not in mode.as_json()


def test_one_bad_permission_row_drops_alone(monkeypatch):
    entry = {"agent_sandbox": {
        "permissions": [{"permission": "docker", "mode": "block"}, {"permission": "no-such", "mode": "allow"},
                        {"permission": "global-installs", "mode": "allow", "agent": "codex"},
                        {"permission": "global-installs", "mode": "block", "agent": "codex"}],
        "folders": [{"path": "~/other", "access": "read"}, {"path": "relative/x", "access": "none"}]}}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: entry)
    settings = permissions.current()
    docker = permissions.BY_ID["docker"]
    assert settings.mode(docker) == permissions.Mode.BLOCK
    assert settings.mode(permissions.BY_ID["global-installs"], "codex") == permissions.Mode.BLOCK   # the more protective
    assert [(each.path, each.access) for each in settings.folders] == [("~/other", permissions.Access.READ)]
    view = permissions.view()
    assert len(view["problems"]) == 3, view["problems"]   # the bad rule, the bad folder, the duplicate
