"""The agent sandbox by default (founder direction 2026-11-22; gated by the founder 2026-11-23).

Contracts:
* GATED: the default is off (``SANDBOX_DEFAULT == "off"``) until the system-level VM test passes;
  while off, install / upgrade / attach change nothing;
* switched on, every detected agent is picked and File Shield engaged — except an agent the person
  took out (``sandbox_declined``), and a File Shield the person turned off: their choice is kept;
* taking an agent out is remembered by every settings write (and still asks first — the approval
  test lives in test_blackbox_shields_files_sandbox.py);
* the dashboard's line says what the sandbox does; a folder sweep's refusal says what to do (KI-592);
* ``blackbox attach`` (the installer runs it on install and upgrade) applies the default.
"""

from __future__ import annotations

import argparse

import pytest

from plugins.blackbox import cli, shields
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.shields.files import mode as files_mode, protect
from plugins.blackbox.shields.files.sandbox import defaults

LINE = ("Agents run inside Blackbox's sandbox: they can't use sudo, change their own hook settings or your shell "
        "startup files, or reach protected items. Turn off per agent if a tool you need doesn't work.")


@pytest.fixture
def entry(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    state: dict = {"mode": "audit"}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)
    written: list = []

    def write(payload, validators=()):
        section = payload["shields"]["file-shield"]
        _, stored, errors = validators[0](payload)
        assert not errors
        state.setdefault("shields", {})["file-shield"] = stored
        written.append(section)
        return {"ok": True}
    monkeypatch.setattr(defaults, "write_settings", write)
    monkeypatch.setattr(defaults.platform, "unavailable", lambda: None)
    monkeypatch.setattr(defaults, "detected", lambda home=None: ("claude-code", "gemini-cli", "hermes"))
    monkeypatch.setattr(shields.files.sandbox, "sync", lambda mode=None: {})
    return state, written


def test_the_default_is_gated_off_until_the_system_level_test_passes(entry):
    state, written = entry
    assert defaults.SANDBOX_DEFAULT == "off"
    assert shields.apply_sandbox_default() == [] and written == [] and "shields" not in state


def test_switched_on_every_detected_agent_is_picked_and_file_shield_engaged(entry):
    state, _ = entry
    assert defaults.apply("on") == ["claude-code", "gemini-cli", "hermes"]
    section = state["shields"]["file-shield"]
    assert section["enabled"] is True and section["sandboxed"] == ["claude-code", "gemini-cli", "hermes"]
    assert defaults.apply("on") == []                       # an upgrade later: nothing new


def test_an_agent_the_person_took_out_is_never_picked_again(entry):
    state, _ = entry
    state["shields"] = {"file-shield": {"enabled": True, "protected": [], "sandboxed": ["claude-code", "gemini-cli"]}}
    _, stored, errors = files_mode.validate({"shields": {"file-shield": {"sandboxed": ["claude-code"]}}})
    assert not errors and stored["sandbox_declined"] == ["gemini-cli"]
    state["shields"]["file-shield"] = stored
    assert defaults.apply("on") == ["hermes"]
    assert state["shields"]["file-shield"]["sandboxed"] == ["claude-code", "hermes"]
    _, again, _ = files_mode.validate({"shields": {"file-shield": {"sandboxed": ["claude-code", "hermes", "gemini-cli"]}}})
    assert again["sandbox_declined"] == []                  # put back by the person: their choice again


def test_a_file_shield_the_person_turned_off_stays_off(entry):
    state, written = entry
    state["shields"] = {"file-shield": {"enabled": False, "protected": [], "sandboxed": []}}
    assert defaults.apply("on") == [] and written == []


def test_the_dashboard_says_what_the_sandbox_does():
    [field] = [field for field in files_mode.fields() if field.key == files_mode.OPT_SANDBOXED]
    assert field.help.startswith(LINE)


def test_a_folder_sweep_refusal_says_what_to_do_instead():
    assert protect.sweep_advice("~/Documents", "~/Documents/Secret", "folder").startswith(
        "~/Documents contains a protected folder; exclude it or work on a subfolder")
    assert protect.sweep_advice("~/Documents/Secret/x.txt", "~/Documents/Secret", "folder") == ""


def test_attach_applies_the_default(monkeypatch):
    calls = []
    monkeypatch.setattr(cli.attach, "cmd_attach", lambda args: 0)
    monkeypatch.setattr(cli.shields, "apply_sandbox_default", lambda: calls.append("default") or [])
    assert cli._cmd_attach(argparse.Namespace()) == 0 and calls == ["default"]
