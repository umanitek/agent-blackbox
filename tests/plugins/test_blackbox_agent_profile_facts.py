"""The facts a profile and the history state, from the agent-tracking campaign's notes
(2026-11-22): the quiet limit is the person's setting; every catalogued program's signer is
checked (an app with no command included) and an agent with no program says so; a mode or flag
that skips the person's permission prompts is a risk note; a moved home's sessions folder is that
home's; and the prompt-text sentence is grammatical.
"""

from __future__ import annotations

import dataclasses
import json
import plistlib
import time

import pytest

from plugins.blackbox.agent_hooks import observe, profile_detail, profiles, prompt_text, versions
from plugins.blackbox.agent_hooks.instances import store, views
from plugins.blackbox.agent_hooks.instances.model import Instance
from plugins.blackbox.kernel import agent_hosts as hosts, code_signing, settings


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    store.reset()
    vendor = code_signing.Signer(kind="developer_id", signer="Vendor", team="T1", verified=True)
    monkeypatch.setattr(code_signing, "describe", lambda path, run=None: vendor)
    # The profile asks without waiting (KI-584); a check that has finished answers at once.
    monkeypatch.setattr(code_signing, "describe_soon", lambda path, run=None: vendor)
    yield
    store.reset()


# ---------------------------------------------------------------- the quiet limit is a setting

def test_the_quiet_limit_is_the_persons_setting_and_defaults_to_thirty_minutes():
    assert store.quiet_seconds() == 30 * 60
    assert settings.write_settings({"agent_activity": {"quiet_minutes": 5}})["ok"]
    store.reset()
    now = time.time()
    store.replace_all([Instance(key="codex:a", agent="codex", kind="session", started=now - 900, last=now - 6 * 60),
                       Instance(key="codex:b", agent="codex", kind="session", started=now - 900, last=now - 4 * 60)])
    assert views.close_stale(alive=None) == 1
    assert store.get("codex:a").end_reason == "quiet" and store.get("codex:b").ended is None


@pytest.mark.parametrize("bad", [0, 1441, True, "10"])
def test_a_quiet_limit_out_of_range_is_refused(bad):
    result = settings.write_settings({"agent_activity": {"quiet_minutes": bad}})
    assert not result["ok"] and any("quiet_minutes" in error for error in result["errors"])


# ---------------------------------------------------------------- every catalogued program's signer

def _profile(monkeypatch, tmp_path, agent, program):
    monkeypatch.setattr(versions, "installed", lambda home=None: {agent: versions.Installed(program, "1.0")} if program else {})
    host = hosts.BY_ID[agent]
    folder, _default = profiles.homes(host, tmp_path)[0]
    folder.mkdir(parents=True, exist_ok=True)
    return profile_detail.read(agent, str(folder), user_home=tmp_path)


@pytest.mark.parametrize("agent", [host.id for host in hosts.HOSTS])
def test_every_catalogued_agents_program_has_its_signer_checked(agent, monkeypatch, tmp_path):
    detail = _profile(monkeypatch, tmp_path, agent, "/opt/vendor/bin/agent")
    assert detail.signer is not None and detail.signature.startswith("Signed by Vendor")
    nothing = _profile(monkeypatch, tmp_path, agent, "")
    assert nothing.signer is None and nothing.signature == profile_detail.NO_PROGRAM and "not checked" not in nothing.signature


def test_an_app_with_no_command_is_found_by_its_bundle_so_its_signer_can_be_checked(tmp_path):
    app = tmp_path / "Cursor.app"
    (app / "Contents" / "MacOS").mkdir(parents=True)
    (app / "Contents" / "MacOS" / "Cursor").write_bytes(b"\xcf\xfa\xed\xfe")
    with open(app / "Contents" / "Info.plist", "wb") as handle:
        plistlib.dump({"CFBundleExecutable": "Cursor", "CFBundleShortVersionString": "3.31.15"}, handle)
    cursor = dataclasses.replace(hosts.BY_ID["cursor"], signs=(str(app),))
    assert versions._bundle(cursor) == versions.Installed(str(app / "Contents" / "MacOS" / "Cursor"), "3.31.15")


# ---------------------------------------------------------------- modes that skip permission prompts

@pytest.mark.parametrize("agent, relative, text, setting", [
    ("claude-code", "settings.json", {"permissions": {"defaultMode": "acceptEdits"}}, "permissions.defaultMode = acceptEdits"),
    ("claude-code", "settings.json", {"permissions": {"defaultMode": "bypassPermissions"}}, "permissions.defaultMode = bypassPermissions"),
    ("codex", "config.toml", 'approval_policy = "never"\n', "approval_policy = never"),
    ("codex", "config.toml", 'sandbox_mode = "danger-full-access"\n', "sandbox_mode = danger-full-access"),
    ("gemini-cli", ".gemini/settings.json", {"general": {"defaultApprovalMode": "yolo"}}, "general.defaultApprovalMode = yolo"),
])
def test_a_setting_that_skips_permission_prompts_is_a_risk_note(agent, relative, text, setting, monkeypatch, tmp_path):
    monkeypatch.setattr(versions, "installed", lambda home=None: {})
    folder, _default = profiles.homes(hosts.BY_ID[agent], tmp_path)[0]
    path = folder / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text if isinstance(text, str) else json.dumps(text), encoding="utf-8")
    risks = profile_detail.read(agent, str(folder), user_home=tmp_path).risks
    assert any(setting in risk and "without asking you" in risk for risk in risks), risks
    path.write_text("{}" if relative.endswith(".json") else "", encoding="utf-8")
    assert not any("permission prompts" in risk for risk in profile_detail.read(agent, str(folder), user_home=tmp_path).risks)


@pytest.mark.parametrize("agent, command, flag", [
    ("claude-code", "/opt/homebrew/bin/claude --dangerously-skip-permissions", "--dangerously-skip-permissions"),
    ("claude-code", "/opt/homebrew/bin/claude --permission-mode bypassPermissions", "--permission-mode bypassPermissions"),
    ("codex", "/opt/homebrew/bin/codex --full-auto", "--full-auto"),
    ("codex", "/opt/homebrew/bin/codex exec --yolo fix", "--yolo"),
    ("gemini-cli", "/usr/local/bin/node /usr/local/bin/gemini --approval-mode=yolo", "--approval-mode yolo"),
    ("copilot-cli", "/usr/local/bin/copilot --allow-all-tools", "--allow-all-tools"),
])
def test_a_running_agent_started_with_a_flag_that_skips_prompts_is_a_risk_note(agent, command, flag, monkeypatch, tmp_path):
    monkeypatch.setattr(versions, "installed", lambda home=None: {})
    monkeypatch.setattr(observe.platform, "process_variable", lambda pid, name: "")
    monkeypatch.setattr(observe.platform, "process_environment", lambda pid: "")
    running = observe.running({50: observe.Proc(50, 1, 0.0, command)})
    assert running and running[0].skips_prompts == (flag,)
    folder, _default = profiles.homes(hosts.BY_ID[agent], tmp_path)[0]
    folder.mkdir(parents=True, exist_ok=True)
    risks = profile_detail.read(agent, str(folder), user_home=tmp_path, running=running).risks
    assert any(flag in risk and "skips permission prompts" in risk for risk in risks), risks
    plain = observe.running({50: observe.Proc(50, 1, 0.0, command.split(" --")[0])})
    assert plain[0].skips_prompts == ()


# ---------------------------------------------------------------- a moved home's sessions folder

def test_a_moved_homes_sessions_folder_is_that_homes_even_before_its_first_session(monkeypatch, tmp_path):
    monkeypatch.setattr(versions, "installed", lambda home=None: {})
    moved = tmp_path / "claude-work"
    moved.mkdir()
    assert profiles.remember("claude-code", str(moved))
    detail = profile_detail.read("claude-code", str(moved.resolve()), user_home=tmp_path)
    assert detail.sessions_path == str(moved.resolve() / "projects") and detail.sessions_exist is False
    (moved / "projects").mkdir()
    assert profile_detail.read("claude-code", str(moved.resolve()), user_home=tmp_path).sessions_exist is True


# ---------------------------------------------------------------- wording

@pytest.mark.parametrize("stored, words", [(1, "1 earlier entry still holds text"), (2, "2 earlier entries still hold text")])
def test_the_prompt_text_sentence_agrees_with_its_number(stored, words, monkeypatch):
    monkeypatch.setattr(store, "count_text", lambda: stored)
    assert words in prompt_text.status().statement
