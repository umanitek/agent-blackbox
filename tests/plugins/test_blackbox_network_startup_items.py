"""The persistence watch: every new startup item or PATH program is shown plainly, critical when an
AI agent wrote it, quiet when the person's own tools did, and never a flood.

Founder direction (2026-11-23, after security round 4's finding
``2026-11-23-agent-sandbox-launchagents-opt-homebrew-``): watch, not only block, every place
something starts from by itself or runs later — launchd jobs, login items, cron/at, the shell
startup files, OpenSSH's login files, Homebrew's and the person's program folders — for an entry
from ANY process, attribute it to an agent instance when Blackbox's records say so, and budget
per source so a ``brew upgrade`` is one line. The helper's scan is proven by its own unit tests
(helper ``observe/run_later.rs``); here, the report it sends and the alerts a person sees.
"""

from __future__ import annotations

import time

import pytest

from plugins.blackbox import audit
from plugins.blackbox.shields.network.monitor import system_report
from plugins.blackbox.shields.network.respond import startup_items, system_alerts


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    return tmp_path


def _event(kind_of_item: str, path: str, ts: float, kind: str = "persistence-new", program: str = "", label: str = "") -> dict:
    return {"kind": kind, "item_kind": kind_of_item, "id": path, "label": label or path.rsplit("/", 1)[-1], "program": program, "ts": ts}


def _agent_call(home, command: str, ts: float, agent: str = "claude-code") -> dict:
    return {"ts": ts, "event": "pre_tool_call", "framework": agent, "workspace": str(home / "camp" / "s4-own"),
            "detail": {"session_id": f"{agent}:abc", "tool_name": "terminal", "args": {"command": command}}}


def test_a_launch_agent_an_ai_agent_wrote_is_critical_and_names_the_agent_and_project(home):
    now = time.time()
    plist = f"{home}/Library/LaunchAgents/com.evil.plist"
    rows = [_agent_call(home, "cat > ~/Library/LaunchAgents/com.evil.plist <<'EOF'\n<plist/>\nEOF", now - 3)]
    [alert] = startup_items.startup_alerts([_event("user-agent", plist, now, program="/tmp/payload", label="com.evil")], rows)
    assert alert["severity"] == "critical" and alert["agent"] == "claude-code" and alert["session"] == "claude-code:abc"
    assert alert["text"] == ("New startup item: Launch agent (your account) “com.evil” — starts payload — written by Claude Code "
                             "in s4-own.")


def test_a_program_the_persons_own_tools_put_on_the_path_is_informational(home):
    now = time.time()
    [alert] = startup_items.startup_alerts([_event("path-program", "/opt/homebrew/bin/jq", now, program="/opt/homebrew/Cellar/jq/1.8/bin/jq")], [])
    assert alert["severity"] == "info" and "agent" not in alert
    assert alert["text"] == "New program on your PATH: “jq” in /opt/homebrew/bin (points to /opt/homebrew/Cellar/jq/1.8/bin/jq)."


def test_an_agent_dropping_a_program_in_a_path_folder_is_critical(home):
    now = time.time()
    rows = [_agent_call(home, f"cp ./git {home}/.local/bin/git && chmod +x $HOME/.local/bin/git", now - 30, agent="codex")]
    [alert] = startup_items.startup_alerts([_event("path-program", f"{home}/.local/bin/git", now)], rows)
    assert alert["severity"] == "critical" and "written by Codex in s4-own" in alert["text"]


def test_a_tool_call_outside_the_window_or_naming_another_file_is_not_the_writer(home):
    now = time.time()
    path = f"{home}/.ssh/authorized_keys"
    late = [_agent_call(home, "echo k >> ~/.ssh/authorized_keys", now - startup_items.WINDOW_SECONDS - 60)]
    other = [_agent_call(home, "cat ~/.ssh/known_hosts", now - 2)]
    for rows in (late, other):
        [alert] = startup_items.startup_alerts([_event("ssh-login", path, now)], rows)
        assert alert["severity"] == "medium" and "written by" not in alert["text"]


def test_a_brew_upgrade_relinking_hundreds_of_programs_is_a_few_lines_not_a_flood(home):
    now = time.time()
    events = [_event("path-program", f"/opt/homebrew/bin/tool{n}", now + n * 0.01, kind="persistence-changed") for n in range(300)]
    alerts = startup_items.startup_alerts(events, [])
    assert len(alerts) == startup_items.BUDGET + 1
    [fold] = [alert for alert in alerts if alert["kind"] == "persistence-many"]
    assert fold["count"] == 300 - startup_items.BUDGET and fold["text"] == f"… and {fold['count']} more changes in /opt/homebrew/bin."


def test_an_agent_written_entry_is_never_folded_into_the_budget(home):
    now = time.time()
    events = [_event("path-program", f"/opt/homebrew/bin/tool{n}", now + n, kind="persistence-changed") for n in range(10)]
    events.append(_event("path-program", "/opt/homebrew/bin/ls", now + 20))
    rows = [_agent_call(home, "ln -sf /tmp/x /opt/homebrew/bin/ls", now + 19)]
    alerts = startup_items.startup_alerts(events, rows)
    assert any(alert["severity"] == "critical" and "“ls”" in alert["text"] for alert in alerts)


def test_the_helpers_run_later_events_are_accepted_and_reach_the_shields_alerts(home, monkeypatch):
    now = time.time()
    report = system_report.validate({"watching": False, "events": [
        _event("shell-startup", f"{home}/.zshrc", now - 1, kind="persistence-changed"),
        _event("at-job", "/private/var/at/jobs/a0001", now - 1),
        _event("path-program", f"{home}/.local/bin/pip-tool", now - 1)]}, now)
    system_report.record(report)
    monkeypatch.setattr(audit, "read_audit", lambda limit=100, offset=0: [])
    texts = {alert["text"]: alert["severity"] for alert in system_alerts.alerts(20)}
    assert texts == {"Startup item changed: Shell startup file “.zshrc”.": "info",
                     "New startup item: Scheduled job (at) “a0001”.": "medium",
                     f"New program on your PATH: “pip-tool” in {home}/.local/bin.": "info"}
