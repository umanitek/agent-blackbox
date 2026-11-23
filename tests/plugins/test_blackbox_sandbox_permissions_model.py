"""Sandbox permissions — the catalogue, the config section, precedence and the loosening judge
(plugins/blackbox/shields/files/sandbox/permissions; design "Sandbox permissions" 2026-11-23,
founder decisions F1–F9, local-only).

Contracts (red on the base ed4152ceac: no ``agent_sandbox`` section, no permissions package):
* the most specific scope wins in both directions (agent+project > project > agent > everywhere,
  a longer project over a shorter one), the catalogue default otherwise (F6);
* a rule's mode must be one its permission allows (AppleScript never "allow", F5); a permission
  whose OS check is not proven is refused ("not controllable yet"); ports only on local-ports;
* a project or folder is accepted only in its ONE canonical spelling (LES-105), never too broad,
  never one of Blackbox's own places; limits and uniqueness hold;
* Homebrew's older ``agent_packages.installs`` is read until a Homebrew rule exists (off → block);
* the judge: a mode moving up, a port added, a folder rule removed or widened is a loosening; the
  opposite is not; an unreadable current setting makes any change a loosening — and the approval
  gate asks through ``approvals.SECTION_JUDGES`` for a ``/api/settings`` write.
"""

from __future__ import annotations

import pytest

from plugins.blackbox import approvals, shields
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.kernel import settings as kernel_settings
from plugins.blackbox.shields.files.sandbox import permissions
from plugins.blackbox.shields.files.sandbox.permissions import Mode, Rule, Scope, Settings, catalogue, judge, section


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    real = tmp_path.resolve()
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.setenv("BLACKBOX_HOME", str(real / ".hermes" / "blackbox"))
    monkeypatch.setenv("HERMES_HOME", str(real / ".hermes"))
    for folder in ("work/shop/api", "work/other", "clients"):
        (real / folder).mkdir(parents=True)
    return real


@pytest.fixture
def entry(monkeypatch):
    state: dict = {}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)
    return state


DOCKER = catalogue.BY_ID["docker"]


def _settings(*rules: Rule) -> Settings:
    return Settings(rules=rules)


@pytest.mark.parametrize("agent, folder, expected", [
    ("claude-code", "shop/api", Mode.ALLOW),     # agent+project
    ("codex", "shop/api", Mode.BLOCK),           # project
    ("claude-code", "other", Mode.ASK),          # agent
    ("codex", "other", Mode.ALLOW),              # everywhere
])
def test_the_most_specific_scope_wins_both_ways(home, agent, folder, expected):
    shop = "~/work/shop"
    rules = _settings(Rule("docker", Mode.ALLOW), Rule("docker", Mode.ASK, Scope(agent="claude-code")),
                      Rule("docker", Mode.BLOCK, Scope(project=shop)),
                      Rule("docker", Mode.ALLOW, Scope(agent="claude-code", project=shop)))
    where = str(home / "work" / (folder if folder != "shop/api" else "shop/api"))
    assert rules.mode(DOCKER, agent, where) is expected


def test_a_narrower_project_wins_and_no_rule_means_the_catalogue_default(home):
    rules = _settings(Rule("docker", Mode.ALLOW, Scope(project="~/work")), Rule("docker", Mode.BLOCK, Scope(project="~/work/shop")))
    assert rules.mode(DOCKER, "codex", str(home / "work" / "shop" / "api")) is Mode.BLOCK
    assert rules.mode(DOCKER, "codex", str(home / "work" / "other")) is Mode.ALLOW
    assert Settings().mode(DOCKER, "codex", str(home)) is DOCKER.default is Mode.ASK
    assert rules.mode(DOCKER, "codex", str(home / "workshop")) is Mode.ASK   # a sibling sharing a prefix is not inside


def _validate(rows=(), folders=()) -> tuple[dict, list[str]]:
    errors: list[str] = []
    return section.validate_section({"permissions": list(rows), "folders": list(folders)}, errors), errors


def test_a_valid_section_is_kept_as_given(home):
    clean, errors = _validate([{"permission": "docker", "mode": "allow", "agent": "claude-code", "project": "~/work/shop"},
                               {"permission": "local-ports", "mode": "block", "ports": [5432, 3000]}],
                              [{"path": "~/clients", "access": "none"}])
    assert errors == []
    assert clean["permissions"][1] == {"permission": "local-ports", "mode": "block", "ports": [3000, 5432]}
    assert clean["folders"] == [{"path": "~/clients", "access": "none"}]


@pytest.mark.parametrize("row, words", [
    ({"permission": "applescript", "mode": "allow"}, "can be set to block, ask"),
    ({"permission": "camera-mic", "mode": "block"}, "not controllable yet"),
    ({"permission": "keychain", "mode": "block"}, "not controllable yet"),
    ({"permission": "docker", "mode": "allow", "ports": [22]}, "only local-ports takes ports"),
    ({"permission": "local-ports", "mode": "block", "ports": [70000]}, "ports are at most"),
    ({"permission": "local-ports", "mode": "block", "ports": list(range(1, 40))}, "ports are at most"),
    ({"permission": "nope", "mode": "allow"}, "unknown permission"),
    ({"permission": "docker", "mode": "allow", "agent": "robot"}, "unknown agent"),
    ({"permission": "docker", "mode": "allow", "project": "~/work/shop/"}, "name the project folder as ~/work/shop"),
    ({"permission": "docker", "mode": "allow", "project": "~/work/../work/shop"}, "name the project folder as ~/work/shop"),
    ({"permission": "docker", "mode": "allow", "project": "~"}, "one folder under"),
    ({"permission": "docker", "mode": "allow", "secret": 1}, "a rule has permission"),
])
def test_a_bad_rule_is_refused_with_the_reason(home, row, words):
    clean, errors = _validate([row])
    assert clean == {} and any(words in error for error in errors), errors


def test_folder_rules_limits_and_uniqueness(home):
    assert "Blackbox's own places" in " ".join(_validate(folders=[{"path": "~/.hermes", "access": "read"}])[1])
    assert "access is none or read" in " ".join(_validate(folders=[{"path": "~/clients", "access": "write"}])[1])
    twice = [{"permission": "docker", "mode": "allow"}, {"permission": "docker", "mode": "block"}]
    assert "one rule per permission" in " ".join(_validate(twice)[1])
    many = [{"permission": "docker", "mode": "allow", "project": f"/p{index}"} for index in range(section.MAX_RULES + 1)]
    assert "at most 200 rules" in " ".join(_validate(many)[1])


def test_homebrew_reads_the_older_setting_until_a_rule_exists(entry):
    entry["agent_packages"] = {"installs": "off"}
    assert permissions.decide("homebrew", "claude-code", "/tmp") is Mode.BLOCK
    entry["agent_sandbox"] = {"permissions": [{"permission": "homebrew", "mode": "ask"}]}
    assert permissions.decide("homebrew", "claude-code", "/tmp") is Mode.ASK
    entry.clear()
    assert permissions.decide("homebrew") is Mode.ALLOW   # the catalogue default, as before


def test_the_judge_finds_each_loosening_and_nothing_else(home):
    shop = Scope(agent="claude-code", project="~/work/shop")
    blocked = _settings(Rule("docker", Mode.BLOCK, shop))
    assert judge.loosened(blocked, _settings(Rule("docker", Mode.ALLOW, shop))) == \
        ["Let Claude Code in ~/work/shop use Docker (without asking; was: block)"]
    assert judge.loosened(_settings(Rule("docker", Mode.ALLOW, shop)), blocked) == []      # tightening
    assert judge.loosened(blocked, Settings()) != []                                      # cleared block falls back to ask
    assert judge.loosened(_settings(Rule("docker", Mode.ALLOW)), Settings()) == []        # cleared allow falls back to ask
    ports = _settings(Rule("local-ports", Mode.BLOCK, ports=(5432,)))
    assert "reach port 3000" in judge.loosened(ports, _settings(Rule("local-ports", Mode.BLOCK, ports=(3000, 5432))))[0]
    kept = Settings(folders=(permissions.FolderRule("~/clients", permissions.Access.NONE),))
    assert judge.loosened(kept, Settings()) == ["Stop keeping ~/clients from every AI agent"]
    assert judge.loosened(kept, Settings(folders=(permissions.FolderRule("~/clients", permissions.Access.READ),))) == \
        ["Let every AI agent read ~/clients"]
    assert judge.loosened(Settings(), kept) == []
    assert judge.loosened(None, Settings()) == [judge.UNREADABLE]


def test_a_settings_write_that_loosens_waits_for_the_person(entry):
    approvals.SECTION_JUDGES[shields.AGENT_SANDBOX] = shields.agent_sandbox_weakening
    body = {"agent_sandbox": {"permissions": [{"permission": "docker", "mode": "allow"}]}}
    assert any("use Docker" in reason for reason in approvals.reasons("/api/settings", body, approvals.Current()))
    stricter = {"agent_sandbox": {"permissions": [{"permission": "docker", "mode": "block"}]}}
    assert not any("Docker" in reason for reason in approvals.reasons("/api/settings", stricter, approvals.Current()))
    entry["agent_sandbox"] = "garbage"
    assert judge.UNREADABLE in approvals.reasons("/api/settings", stricter, approvals.Current())
    assert kernel_settings.SECTION_VALIDATORS[section.SECTION] is section.validate_section


def test_every_never_and_catalogue_entry_is_well_formed():
    ids = [each.id for each in catalogue.PERMISSIONS]
    assert len(ids) == len(set(ids)) and all(each.default in each.modes for each in catalogue.PERMISSIONS)
    assert all(not each.controllable for each in catalogue.PERMISSIONS if each.note == catalogue.UNPROVEN)
    assert Mode.ALLOW not in catalogue.BY_ID["applescript"].modes
