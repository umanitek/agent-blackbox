"""Tamper counts: every refused attempt to switch Blackbox off or get around it is counted.

Contracts (2026-11-24): a refusal of self-protection is counted per category, with when and which
agent, whichever route recorded it (the Hermes hook, another agent's hooks, the operating system's
sandbox); a finding that only flagged is never counted; a refused write to a startup place counts
under its own category; the counts survive a restart (they are on disk); and an agent trying to
reset them is itself refused by self-protection. Where the helper does not report the sandbox's
refusals (Linux), a refusal an agent's hook read from a tool's output is counted instead (KI-693).
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


def _seen(monkeypatch, tmp_path, *, helper_reports: bool):
    """files.on_refusal with this machine's helper reporting (macOS) or not (Linux), one file kept
    closed for Blackbox, and the sandbox's own answer to a refusal left out."""
    from plugins.blackbox.shields import files
    hook = tmp_path / "home" / ".claude" / "settings.json"
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setattr(files.sandbox, "HELPER_REPORTS_REFUSALS", helper_reports)
    monkeypatch.setattr(files.sandbox, "self_protected_files", lambda _mode: (str(hook),))
    monkeypatch.setattr(files.sandbox, "on_refusal", lambda *_a, **_k: None)
    return files.on_refusal, hook


def test_a_kernel_refusal_seen_in_a_tool_output_counts_where_the_helper_does_not_report_it(monkeypatch, tmp_path):
    """KI-693: on Linux a sandboxed Codex's 5 kernel refusals left the counts and the log unchanged."""
    on_refusal, hook = _seen(monkeypatch, tmp_path, helper_reports=False)
    on_refusal("file", str(hook), "codex", "s1", str(tmp_path))
    on_refusal("file", str(hook.parent), "codex", "s1", str(tmp_path))          # the pinned folder above it
    on_refusal("persistence", str(tmp_path / "home/.config/systemd/user/x.service"), "codex", "s1", str(tmp_path))
    counts = audit.tamper_counts()
    assert counts["self-protection-kernel"]["count"] == 2 and counts["self-protection-kernel"]["last_agent"] == audit.SANDBOX_RECORDER
    assert counts["startup-item"]["count"] == 1
    assert audit.protection_log.verify().seq == 3 and audit.protection_log.verify().state == "ok"


def test_a_seen_refusal_of_anything_else_or_on_a_reporting_helper_is_not_counted(monkeypatch, tmp_path):
    """The person's own files and their home are not Blackbox's; on macOS the helper's denial log
    already counted the refusal (:func:`changes.record`), so the hook's reading never counts twice."""
    on_refusal, hook = _seen(monkeypatch, tmp_path, helper_reports=False)
    on_refusal("file", str(tmp_path / "home" / "notes.txt"), "codex", "s1", str(tmp_path))
    on_refusal("file", str(tmp_path / "home"), "codex", "s1", str(tmp_path))
    on_refusal("signal", "4242", "codex", "s1", str(tmp_path))
    assert audit.tamper_counts() == {}
    on_refusal, hook = _seen(monkeypatch, tmp_path, helper_reports=True)
    on_refusal("file", str(hook), "codex", "s1", str(tmp_path))
    assert audit.tamper_counts() == {}


def test_the_seen_refusal_kinds_are_the_hooks_own_words():
    """Drift guard: the kinds :func:`changes.record_seen_refusal` keys on are the ones the agents'
    hooks read from a tool's output (``agent_hooks.protect.sandbox_errors``)."""
    from plugins.blackbox.agent_hooks.protect import sandbox_errors
    from plugins.blackbox.shields.files import changes
    assert (changes.SEEN_FILE, changes.SEEN_STARTUP_FILE, changes.SEEN_PERSISTENCE) == (
        sandbox_errors.FILE, sandbox_errors.STARTUP, sandbox_errors.PERSISTENCE)


def test_only_the_macos_helper_reports_the_sandboxs_refusals():
    """LES-160: the per-OS answer is explicit on every OS, never a silent default."""
    from plugins.blackbox.shields.files.sandbox.platform import macos, unsupported
    from plugins.blackbox.shields.files.sandbox.platform import linux
    assert macos.HELPER_REPORTS_REFUSALS is True
    assert linux.HELPER_REPORTS_REFUSALS is False and unsupported.HELPER_REPORTS_REFUSALS is False
