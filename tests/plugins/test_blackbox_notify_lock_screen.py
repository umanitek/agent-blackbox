"""What a lock screen shows names the AGENT and what happened, never a protected item, and Blackbox
protecting itself is said as that (KI-PENDING-c4249e, agents campaign pass 3, 2026-11-22: the
refused ``rm -rf ~/.hermes/plugins/blackbox`` read "reached for a sensitive file", and the File
Shield notice "File Shield stopped an AI agent reaching Secret." named the protected folder — which
can itself be private — and not the agent).
"""

from __future__ import annotations

from plugins.blackbox.kernel import threat_ids
from plugins.blackbox.notify import wording
from plugins.blackbox.shields.files import alerts
from plugins.blackbox.shields.files.protect import FOLDER_HIT_ID


def _self_protection(title: str) -> dict:
    return {"identifier": threat_ids.fileaccess_identifier("terminal", threat_ids.SELF_PROTECTION), "category": "fileaccess",
            "severity": "critical", "title": title, "evidence": "rm -rf ~/.hermes/plugins/blackbox", "framework": "claude-code",
            "workspace": "/w/app", "source": "custom", "decision": "block", "ts": 1.0, "tool_call_id": "t1"}


def test_removing_blackbox_is_worded_as_self_protection():
    notice = wording.finding(_self_protection("Change to Blackbox's own settings"))
    assert notice.title == "Blackbox stopped Claude Code"
    assert "tried to change, remove or switch off Blackbox" in notice.body and "Blackbox protects itself" in notice.body
    assert "sensitive file" not in notice.body and ".hermes" not in notice.body
    keys = wording.finding(_self_protection("Would read Blackbox's key files"))
    assert "tried to read Blackbox's own keys" in keys.body


def test_a_file_shield_refusal_names_the_agent_and_never_the_protected_folder(monkeypatch):
    monkeypatch.setattr(alerts.audit, "read_findings", lambda limit: [
        {"identifier": FOLDER_HIT_ID, "framework": "gemini-cli", "ts": 5.0, "fields": {"item": "~/Documents/Secret"}}])
    for source in (alerts.changes, alerts.sandbox, alerts.watched):
        monkeypatch.setattr(source, "recent" if source is not alerts.sandbox else "restorations",
                            (lambda limit=0: []) if source is not alerts.sandbox else (list))
    hit, = alerts.shield_alerts()
    assert hit.title == "File Shield stopped Gemini CLI" and hit.agent == "gemini-cli"
    assert "Secret" not in hit.title and "Secret" not in hit.text
    assert "Gemini CLI" in hit.text and "Secret" in hit.detail      # the name only with "show details"
