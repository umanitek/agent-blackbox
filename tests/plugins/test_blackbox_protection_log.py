"""The protection log: a hash-chained record of every refusal that shows what was done to it.

Contracts (2026-11-24): each refused tamper attempt is an entry, chained to the one before; the
check says ``ok`` for an untouched log and names the first bad entry when one is edited, removed or
put in between; a log put back to an older copy is ``rewound``; one replaced with another of the
same length is ``drift``; a log made unreadable (a link put in its place) is ``broken`` and is never
quietly replaced by a fresh one; a long log keeps its newest entries and still checks; entries hold
no command or path; and an agent's attempt to edit the log is refused by self-protection.
"""

from __future__ import annotations

import json

import pytest

from plugins.blackbox import audit
from plugins.blackbox.audit import protection_log
from plugins.blackbox.detection.paths.guard_settings import detect_guard_tamper
from plugins.blackbox.kernel import threat_ids

SELF = {"identifier": threat_ids.fileaccess_identifier("terminal", threat_ids.SELF_PROTECTION),
        "matched": threat_ids.SELF_PROTECTION, "severity": "critical", "title": "Blackbox's own settings"}


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "blackbox"))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))


def _lines() -> list[str]:
    return protection_log._log().read_text(encoding="utf-8").splitlines()


def _write(lines: list[str]) -> None:
    protection_log._log().write_text("\n".join(lines) + "\n", encoding="utf-8")


def _three() -> None:
    for agent in ("codex", "claude-code", "cursor"):
        protection_log.append("tamper", "self-protection", agent=agent)


def test_a_refusal_is_logged_chained_and_holds_no_command():
    assert protection_log.head().state == "empty"
    audit.record_for("codex", event="pre_tool_call", findings=[{**SELF, "evidence": "rm -rf ~/.blackbox"}],
                     detail={"blocked": [SELF["identifier"]], "args": {"command": "rm -rf ~/.blackbox"}})
    found = protection_log.verify()
    assert (found.seq, found.state) == (1, "ok")
    entry = json.loads(_lines()[0])
    assert entry["agent"] == "codex" and entry["what"] == "self-protection" and entry["prev"] == protection_log.GENESIS
    assert ".blackbox" not in _lines()[0]


@pytest.mark.parametrize("damage", ["edit", "remove", "insert"])
def test_an_entry_edited_removed_or_put_in_between_breaks_the_chain_at_that_entry(damage):
    _three()
    lines = _lines()
    if damage == "edit":
        lines[1] = lines[1].replace("claude-code", "nobody")
    elif damage == "remove":
        del lines[1]
    else:
        lines.insert(1, lines[0])
    _write(lines)
    found = protection_log.verify()
    assert (found.state, found.first_bad) == ("broken", 2)


def test_a_log_put_back_to_an_older_copy_is_rewound_and_one_swapped_for_another_is_drift():
    _three()
    _write(_lines()[:2])
    assert protection_log.verify().state == "rewound"
    _three()
    head = json.loads(protection_log._head_file().read_text(encoding="utf-8"))
    head["hash"] = "f" * 64   # as if the log had been swapped for another one of the same length
    protection_log._head_file().write_text(json.dumps(head), encoding="utf-8")
    assert protection_log.verify().state == "drift"


def test_an_unreadable_log_is_broken_and_never_replaced_with_a_fresh_one(tmp_path):
    _three()
    other = tmp_path / "elsewhere.jsonl"
    other.write_text("", encoding="utf-8")
    protection_log._log().unlink()
    protection_log._log().symlink_to(other)
    assert protection_log.verify().state == "broken"
    with pytest.raises(OSError):
        protection_log.append("tamper", "self-protection", agent="codex")
    assert protection_log._log().is_symlink()


def test_a_long_log_keeps_its_newest_entries_and_still_checks(monkeypatch):
    monkeypatch.setattr(protection_log, "MAX_ENTRIES", 5)
    for _ in range(12):
        protection_log.append("tamper", "startup-item", agent="codex")
    found = protection_log.verify()
    assert (found.seq, found.state) == (12, "ok") and len(_lines()) == 5


def test_an_agent_can_not_edit_the_log():
    refused = detect_guard_tamper("terminal", {"command": f"sed -i '' 1d {protection_log._log()}"})
    assert refused and refused[0].matched == threat_ids.SELF_PROTECTION
