"""Tamper counts: every refused attempt to switch Blackbox off or get around it is counted.

Contracts (2026-11-24): a refusal of self-protection is counted per category, with when and which
agent, whichever route recorded it (the Hermes hook, another agent's hooks, the operating system's
sandbox); a finding that only flagged is never counted; a refused write to a startup place counts
under its own category; the counts survive a restart (they are on disk); and an agent trying to
reset them is itself refused by self-protection.
"""

from __future__ import annotations

import pytest

from plugins.blackbox import audit
from plugins.blackbox.detection.paths.guard_settings import detect_guard_tamper
from plugins.blackbox.kernel import threat_ids
from plugins.blackbox.kernel.persistence_places import STARTUP_ITEM

SELF = {"identifier": threat_ids.fileaccess_identifier("terminal", threat_ids.SELF_PROTECTION),
        "matched": threat_ids.SELF_PROTECTION, "severity": "critical", "title": "Blackbox's own settings"}
STARTUP = {"identifier": "persistence:startup-item", "matched": STARTUP_ITEM, "severity": "high",
           "title": "a login item"}


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "blackbox"))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))


def test_a_refusal_counts_and_a_flag_does_not():
    audit.record(event="pre_tool_call", findings=[SELF], detail={"decision": "flag"})
    assert audit.tamper_counts() == {}
    audit.record(event="pre_tool_call", findings=[SELF], detail={"decision": "block", "blocked": [SELF["identifier"]]})
    counted = audit.tamper_counts()["self-protection"]
    assert counted["count"] == 1 and counted["last_agent"] == "hermes" and counted["last_at"] > 0


def test_every_route_counts_under_its_own_agent_and_category():
    audit.record_for("codex", event="pre_tool_call", findings=[SELF],
                     detail={"decision": "block", "blocked": [SELF["identifier"]]})
    audit.record_for("claude-code", event="pre_tool_call", findings=[STARTUP],
                     detail={"decision": "block", "blocked": [STARTUP["identifier"]]})
    audit.record_for(audit.SANDBOX_RECORDER, event="sandbox_deny", findings=[SELF])   # the kernel refused it
    counts = audit.tamper_counts()
    assert counts["self-protection"]["last_agent"] == "codex"
    assert counts["startup-item"]["count"] == 1 and counts["startup-item"]["last_agent"] == "claude-code"
    assert counts["self-protection-kernel"]["count"] == 1


def test_the_counts_are_kept_on_disk_and_an_agent_can_not_reset_them():
    for _ in range(3):
        audit.record(event="pre_tool_call", findings=[SELF], detail={"blocked": [SELF["identifier"]]})
    from plugins.blackbox.audit import tamper
    assert tamper._path().is_file() and audit.tamper_counts()["self-protection"]["count"] == 3
    refused = detect_guard_tamper("terminal", {"command": f"rm {tamper._path()}"})
    assert refused and refused[0].matched == threat_ids.SELF_PROTECTION


def test_another_agents_refused_hook_call_counts(monkeypatch, tmp_path):
    """The real route: a Codex hook asks Blackbox about a call that stops Blackbox, is refused,
    and the refusal is counted under Codex (this route did not say which findings blocked)."""
    from plugins.blackbox import agent_hooks
    from plugins.blackbox.agent_hooks import observe
    from plugins.blackbox.agent_hooks.protect import events, runner
    monkeypatch.setattr(observe.platform, "process_table", lambda: "")
    monkeypatch.setattr(agent_hooks, "_home", lambda: tmp_path)
    answer = events.record_event(runner.summary("codex", "pre_tool", {
        "session_id": "s1", "cwd": str(tmp_path), "tool_name": "Bash",
        "tool_input": {"command": "launchctl bootout gui/501/ai.umanitek.blackbox-dashboard"}}))
    assert "block" in str(answer)
    assert audit.tamper_counts()["self-protection"]["last_agent"] == "codex"
