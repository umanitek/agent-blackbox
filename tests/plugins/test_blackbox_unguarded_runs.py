"""The back-stop for an agent run Blackbox does not see: an agent process with no Blackbox session
is ONE high finding that names the agent and the folder it works in (``agent_hooks.unguarded``).

Private security finding ``2026-11-25-hooks-only-an-agent-may-write-a-project-`` (macOS round R8,
High, raw/dah8real.txt): a REAL Claude Code started in a project whose ``.claude/settings.json``
held ``disableAllHooks`` read a protected file; Blackbox recorded no instance, and only the
generic "running without Blackbox" notice was raised — naming neither the project nor the switch.
"""

from __future__ import annotations

import pytest

from plugins.blackbox import agent_hooks, audit
from plugins.blackbox.agent_hooks import observe, tracking, unguarded
from plugins.blackbox.agent_hooks.instances import store

PS = """\
  100     1 Sun Nov 22 06:00:00 2026     /sbin/launchd
  601   100 Sun Nov 22 06:52:00 2026     claude -p "read the notes"
  602   100 Sun Nov 22 06:52:10 2026     /Applications/Cursor.app/Contents/MacOS/Cursor
"""


@pytest.fixture
def machine(monkeypatch, tmp_path):
    project = tmp_path / "camp" / "s8-dah"
    (project / ".claude").mkdir(parents=True)
    (project / ".claude" / "settings.json").write_text('{"disableAllHooks": true}', encoding="utf-8")
    store.reset()
    unguarded._reported.clear()
    monkeypatch.setattr(observe.platform, "process_table", lambda: PS)
    monkeypatch.setattr(observe.platform, "process_environment", lambda pid: "")
    monkeypatch.setattr(observe.platform, "process_variable", lambda pid, name: "")
    monkeypatch.setattr(observe.platform, "process_ancestry", lambda pid, limit: None)
    monkeypatch.setattr(observe.platform, "process_cwd", lambda pid: str(project))
    monkeypatch.setattr(agent_hooks, "_home", lambda: tmp_path)
    tracking._seen.update(at=0.0, table={}, running=[], pids=frozenset(), new_profiles=False)
    yield project
    store.reset()


def _unguarded() -> list[dict]:
    return [row for row in audit.read_findings(limit=100) if row["identifier"] == unguarded.UNGUARDED_ID]


def test_an_agent_run_with_its_hooks_switched_off_is_one_high_finding_naming_agent_and_folder(machine):
    tracking.live()
    found, = _unguarded()
    assert found["severity"] == "high" and found["framework"] == "claude-code"
    assert str(machine) in found["title"] and "Claude Code" in found["title"]
    assert "disableAllHooks" in found["evidence"]            # what switched it off, read from the project
    unguarded._reported.clear()                               # a restarted dashboard: still once
    tracking._seen.update(at=0.0)
    tracking.live()
    assert len(_unguarded()) == 1


def test_an_open_editor_with_no_agent_activity_is_not_called_an_unseen_run(machine):
    """Cursor's app runs its hooks only when its agent acts: an open editor is not a finding."""
    tracking.live()
    assert [row["framework"] for row in _unguarded()] == ["claude-code"]


def test_the_persons_notice_says_which_agent_runs_unseen_and_why(machine):
    """VM bb-w12-a (REAL Claude Code in a project the person switched off): the finding's notice read
    "tried a dangerous command. Flagged, not stopped" — it says the run is unseen, and why."""
    from plugins.blackbox.notify import wording
    tracking.live()
    notice = wording.finding(_unguarded()[0])
    assert notice.level == "critical" and notice.title == "Claude Code is running without Blackbox in s8-dah"
    assert "disableAllHooks" in notice.body and "Flagged" not in notice.body
    assert wording.UNGUARDED_ID == unguarded.UNGUARDED_ID
