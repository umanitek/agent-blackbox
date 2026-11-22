"""Every agent gets Blackbox's hook time limit in ITS OWN unit, and a limit the agent would read
wrongly is found and rewritten (KI-570, security finding 2026-11-22-gemini-cli-runs-unprotected).

The real Gemini CLI 0.70.0 printed "Hook execution error: Hook timed out after 10ms" for every
Blackbox hook: Blackbox wrote ``"timeout": 10`` (seconds, as Claude Code reads it) and Gemini reads
``timeout`` in milliseconds, so it failed open and ran unprotected. The sources for each unit:
code.claude.com/docs/en/hooks ("timeout: Seconds"), developers.openai.com/codex/hooks ("timeout is in
seconds"; SessionEnd up to 3 s), geminicli.com/docs/hooks/reference ("timeout: milliseconds"),
docs.github.com copilot hooks (``timeoutSec``). Devin documents no time-limit field, so none is
written and Devin's default applies.
"""

from __future__ import annotations

import json

import pytest

from plugins.blackbox import agent_hooks
from plugins.blackbox.agent_hooks import profile_detail, profiles
from plugins.blackbox.agent_hooks.protect import config_edit, own_files
from plugins.blackbox.kernel import agent_hosts as hosts

RUNNER = "/Users/admin/.hermes/blackbox/agent-hooks/python /Users/admin/.hermes/blackbox/agent-hooks/runner.py"
#: What Blackbox wrote into the REAL ~/.gemini/settings.json on the test VM (one event shown).
STOCK_GEMINI = {"hooks": {"BeforeTool": [{"matcher": ".*", "hooks": [
    {"type": "command", "command": f"{RUNNER} gemini-cli pre_tool http://127.0.0.1:9700", "timeout": 10}]}]}}


def _seconds(host, raw):
    return host.hook_timeout.seconds(raw)


@pytest.mark.parametrize("agent, key, raw", [
    ("claude-code", "timeout", 10),
    ("codex", "timeout", 10),
    ("gemini-cli", "timeout", 10000),
    ("devin", None, None),
])
def test_each_nested_agent_gets_ten_seconds_in_its_own_unit(tmp_path, agent, key, raw):
    host = hosts.BY_ID[agent]
    event = next(name for name, kind in host.events.items() if kind == "pre_tool")
    assert config_edit.install(host, tmp_path, {event: f"{RUNNER} {agent} pre_tool u"}).ok
    hook = json.loads(host.config_path(tmp_path).read_text(encoding="utf-8"))["hooks"][event][0]["hooks"][0]
    if key is None:
        assert not any(name.startswith("timeout") for name in hook)   # undocumented: the agent's own default
    else:
        assert hook[key] == raw and _seconds(host, hook[key]) == hosts.HOOK_WAIT_SECONDS


def test_codex_session_end_stays_inside_codexs_three_second_cap(tmp_path):
    codex = hosts.BY_ID["codex"]
    config_edit.install(codex, tmp_path, {"SessionEnd": f"{RUNNER} codex stop u", "PreToolUse": f"{RUNNER} codex pre_tool u"})
    hooks = json.loads(codex.config_path(tmp_path).read_text(encoding="utf-8"))["hooks"]
    assert hooks["SessionEnd"][0]["hooks"][0]["timeout"] == 3 and hooks["PreToolUse"][0]["hooks"][0]["timeout"] == 10
    assert config_edit.invalid_entries(codex, tmp_path) == []


def test_copilot_reads_timeoutsec_in_seconds(tmp_path):
    copilot = hosts.BY_ID["copilot-cli"]
    own_files.install(copilot, tmp_path, {"preToolUse": (["/py"], f"{RUNNER} copilot-cli pre_tool u")})
    hook = json.loads(copilot.config_path(tmp_path).read_text(encoding="utf-8"))["hooks"]["preToolUse"][0]
    assert hook["timeoutSec"] == hosts.HOOK_WAIT_SECONDS and "timeout" not in hook


def test_the_stock_gemini_entry_is_reported_as_cut_off_after_ten_milliseconds(tmp_path):
    gemini = hosts.BY_ID["gemini-cli"]
    path = gemini.config_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(STOCK_GEMINI), encoding="utf-8")
    [reason] = config_edit.invalid_entries(gemini, tmp_path)
    assert "milliseconds" in reason and "0.01 s" in reason


def test_a_hook_named_in_geminis_off_list_is_reported(tmp_path):
    gemini = hosts.BY_ID["gemini-cli"]
    path = gemini.config_path(tmp_path)
    path.parent.mkdir(parents=True)
    command = STOCK_GEMINI["hooks"]["BeforeTool"][0]["hooks"][0]["command"]
    fixed = json.loads(json.dumps(STOCK_GEMINI))
    fixed["hooks"]["BeforeTool"][0]["hooks"][0]["timeout"] = 10000
    path.write_text(json.dumps({**fixed, "hooksConfig": {"disabled": [command]}}), encoding="utf-8")
    assert any("hooksConfig.disabled" in reason for reason in config_edit.invalid_entries(gemini, tmp_path))


def test_the_sweep_rewrites_a_wrong_unit_and_the_agent_row_is_degraded_until_then(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_hooks, "_home", lambda: tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(hosts.shutil, "which", lambda name, path=None: None)
    monkeypatch.setattr(agent_hooks, "load_blackbox_config", lambda: type("C", (), {"auto_attach": True, "dashboard_port": 9700})())
    gemini = hosts.BY_ID["gemini-cli"]
    # The CURRENT commands (so only the unit is wrong), each with the stock 10 written as seconds.
    wanted = {event: command for event, (_argv, command) in agent_hooks._invocations(gemini).items()}
    config_edit.install(gemini, tmp_path, wanted)
    path = gemini.config_path(tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    for groups in data["hooks"].values():
        groups[0]["hooks"][0]["timeout"] = 10
    path.write_text(json.dumps(data), encoding="utf-8")
    row = {row.id: row for row in agent_hooks.rows()}["gemini-cli"]
    assert row.state == "degraded" and "milliseconds" in row.detail
    agent_hooks.sweep()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert {groups[0]["hooks"][0]["timeout"] for groups in data["hooks"].values()} == {10000}
    assert config_edit.invalid_entries(gemini, tmp_path) == []


def test_the_profile_names_the_unloadable_hook_as_a_risk(tmp_path):
    gemini = hosts.BY_ID["gemini-cli"]
    path = gemini.config_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(STOCK_GEMINI), encoding="utf-8")
    problems = profiles.problems(gemini, tmp_path, (), path)
    assert [problem.kind for problem in problems] == ["hook-invalid"]
    scope = profile_detail._settings(gemini, path, "user")
    assert scope.unloadable and any("does not protect" in risk for risk in profile_detail._risks(
        profile_detail.ProfileDetail("gemini-cli", "Gemini CLI", str(tmp_path), "", settings=[scope])))
