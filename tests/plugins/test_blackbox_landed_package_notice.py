"""A listed package that LANDED says how to remove it and that its install scripts may have run,
and a Hermes notice names the project the agent works in (KI-603).

Security round 4 (REAL, Hermes gpt-5-nano s4-hmdC, core b1406e6191): after ``npm install express``
landed the listed ms@2.1.3, the alert read only "Installed — Malicious package …: ms@2.1.3 in
package-lock.json via express → debug → ms@2.1.3": the finding's advice (the removal command and the
install-scripts warning, KI-595) was dropped when the finding was recorded, and the notice said
"Your Hermes agent in .hermes" — the Hermes home, not the project folder — on every Hermes notice.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from plugins.blackbox import audit, guard, ruleset as ruleset_mod
from plugins.blackbox.detection.manifests import checks, registry, verdicts
from plugins.blackbox.guard import background as guard_background, hooks, report_queue
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.notify import wording
from plugins.blackbox.ruleset import Ruleset

LOCK = {"lockfileVersion": 3, "packages": {
    "": {"dependencies": {"express": "4.21.2"}},
    "node_modules/express": {"version": "4.21.2", "dependencies": {"debug": "2.6.9"}},
    "node_modules/debug": {"version": "2.6.9", "dependencies": {"ms": "2.1.3"}},
    "node_modules/ms": {"version": "2.1.3"}}}


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
    folder = tmp_path / "camp" / "projects" / "s4-hmdC"
    folder.mkdir(parents=True)
    monkeypatch.setenv("TERMINAL_CWD", str(folder))   # where the Hermes agent works
    rules = Ruleset()
    rules.dependency = {"npm:ms@2.1.3": {"identifier": "dep:npm:ms@2.1.3-r4test", "severity": "critical", "kind": "malware",
                                         "name": "Malicious package (round-4 TEST rule)", "source": "public"}}
    monkeypatch.setattr(hooks, "_config", lambda: config_mod.BlackboxConfig(mode="block", report=False, discover=False))
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: rules)
    monkeypatch.setattr(guard_background, "review_tool", lambda *a, **k: None)
    monkeypatch.setattr(report_queue.REPORTS, "submit", lambda job: None)   # nothing leaves this machine
    for cache in (registry.PARSED, verdicts.VERDICTS, checks.SNAPSHOTS):
        cache.clear()
    return folder


def _landed_row() -> dict:
    [row] = [row for row in audit.read_findings(limit=50) if row.get("event") == "post_install_dependencies"]
    return row


def test_the_hermes_after_install_alert_names_the_removal_the_warning_and_the_project(project):
    args = {"command": "npm install express"}
    assert guard.on_pre_tool_call(tool_name="terminal", args=args, session_id="s", tool_call_id="t") is None
    (project / "package-lock.json").write_text(json.dumps(LOCK), encoding="utf-8")
    guard.on_post_tool_call(tool_name="terminal", args=args, result="added 69 packages", session_id="s", tool_call_id="t")
    row = _landed_row()
    assert "npm uninstall express" in row["advice"] and "install scripts may already have run" in row["advice"]
    notice = wording.finding(row)
    assert notice is not None and notice.level == "critical" and notice.project == "s4-hmdC"
    assert "npm uninstall express" in notice.body and "install scripts may already have run" in notice.body
    assert ".hermes" not in notice.body


def test_a_coding_agents_landed_package_notice_says_the_same(project):
    from plugins.blackbox.agent_hooks.protect import events, runner
    events._answered.clear()
    shell = {"session_id": "s", "cwd": str(project), "tool_name": "Bash", "tool_input": {"command": "npm install express"},
             "tool_use_id": "t-landed"}
    events.record_event(runner.summary("claude-code", "pre_tool", shell))
    (project / "package-lock.json").write_text(json.dumps(LOCK), encoding="utf-8")
    events.record_event(runner.summary("claude-code", "post_tool", {**shell, "tool_response": {"stdout": "added"}}))
    notice = wording.finding(_landed_row())
    assert notice is not None and notice.project == "s4-hmdC" and "npm uninstall express" in notice.body
    assert notice.title == "Claude Code installed a package on the threat list"


def test_a_hermes_notice_names_the_project_folder_not_the_hermes_home(project):
    guard.on_pre_tool_call(tool_name="read_file", args={"path": str(Path.home() / ".ssh" / "id_rsa")}, session_id="s")
    rows = [row for row in audit.read_findings(limit=50) if row.get("event") == "pre_tool_call"]
    assert rows, "reading a private key is a finding"
    assert wording.finding(rows[0]).project == "s4-hmdC"
    shutil.rmtree(project)
