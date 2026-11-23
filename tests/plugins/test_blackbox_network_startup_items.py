"""The persistence watch: every new startup item or PATH program is shown plainly, critical when an
AI agent wrote it, quiet when the person's own tools did, and never a flood.

Founder direction (2026-11-23, after security round 4's finding
``2026-11-23-agent-sandbox-launchagents-opt-homebrew-``): watch, not only block, every place
something starts from by itself or runs later — launchd jobs, login items, cron/at, the shell
startup files, OpenSSH's login files, Homebrew's and the person's program folders — for an entry
from ANY process, attribute it to an agent instance when Blackbox's records say so, and budget
per source so a ``brew upgrade`` is one line. The helper's scan is proven by its own unit tests
(helper ``observe/run_later.rs``); here, the report it sends and the alerts a person sees.

KI-615 (security round 5, bb-sec-r5, raw/a1-claude-batch.txt CASE persist + raw/a9-persist-shell.txt):
every agent-written entry appeared twice (attributed, and again under the image's /Users/runner ->
/Users/admin link), one ``at`` job raised three alerts (.SEQ, .lockfile, the job), a plain-shell
append to ~/.ssh/authorized_keys five minutes after Claude Code's own was reported "written by
Claude Code", and a broker install was titled "New startup item". An entry is now reported once (its
resolved path + content mark), and attributed only when it was written during the naming call.
"""

from __future__ import annotations

import os
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


def _event(kind_of_item: str, path: str, ts: float, kind: str = "persistence-new", program: str = "", label: str = "",
           written: float = 0.0, content: str = "ab12cd34") -> dict:
    """A helper event; *written*: the entry's write time, carried in its mark (``size:mtime:hash``)."""
    return {"kind": kind, "item_kind": kind_of_item, "id": path, "label": label or path.rsplit("/", 1)[-1], "program": program, "ts": ts,
            **({"mark": f"120:{int(written)}:{content}"} if written else {})}


def _agent_call(home, command: str, ts: float, agent: str = "claude-code") -> dict:
    return {"ts": ts, "event": "pre_tool_call", "framework": agent, "workspace": str(home / "camp" / "s4-own"),
            "detail": {"session_id": f"{agent}:abc", "tool_name": "terminal", "args": {"command": command}}}


def test_a_launch_agent_an_ai_agent_wrote_is_critical_and_names_the_agent_and_project(home):
    now = time.time()
    plist = f"{home}/Library/LaunchAgents/com.evil.plist"
    rows = [_agent_call(home, "cat > ~/Library/LaunchAgents/com.evil.plist <<'EOF'\n<plist/>\nEOF", now - 3)]
    [alert] = startup_items.startup_alerts([_event("user-agent", plist, now, program="/tmp/payload", label="com.evil", written=now - 2)],
                                           rows)
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
    [alert] = startup_items.startup_alerts([_event("path-program", f"{home}/.local/bin/git", now, written=now - 29)], rows)
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
    events.append(_event("path-program", "/opt/homebrew/bin/ls", now + 20, written=now + 19))
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


def _shell_append_after(home, minutes: float):
    """Round 5: Claude Code appended to authorized_keys; *minutes* later a plain shell did too."""
    now = time.time()
    rows = [_agent_call(home, "echo 'ssh-ed25519 AAAA r5test' >> ~/.ssh/authorized_keys && echo wrote-authorized-keys",
                        now - minutes * 60 - 3)]
    rows[0]["detail"]["tool_call_id"] = "toolu_r5"
    rows.append({"ts": now - minutes * 60 - 2, "event": "post_tool_call", "framework": "claude-code",
                 "detail": {"session_id": "claude-code:abc", "tool_call_id": "toolu_r5"}})
    return now, rows


def test_a_later_write_by_someone_else_is_not_pinned_on_the_agent_that_named_the_file(home):
    now, rows = _shell_append_after(home, 5)
    event = _event("ssh-login", f"{home}/.ssh/authorized_keys", now, kind="persistence-changed", written=now - 1)
    [alert] = startup_items.startup_alerts([event], rows)
    assert alert["severity"] == "medium" and "agent" not in alert and "written by" not in alert["text"]
    assert alert["text"].endswith("— writer unknown (an AI agent's earlier command named this file).")
    # The agent's own append — written while its call ran — is still the agent's.
    own = _event("ssh-login", f"{home}/.ssh/authorized_keys", now - 300, kind="persistence-changed", written=now - 302.5)
    [alert] = startup_items.startup_alerts([own], rows)
    assert alert["severity"] == "critical" and "written by Claude Code in s4-own" in alert["text"]


def test_an_entry_without_a_write_time_is_never_attributed(home):
    now = time.time()
    rows = [_agent_call(home, "echo k >> ~/.ssh/authorized_keys", now - 2)]
    [alert] = startup_items.startup_alerts([_event("ssh-login", f"{home}/.ssh/authorized_keys", now)], rows)
    assert "agent" not in alert and "written by" not in alert["text"]


def test_one_entry_seen_through_a_linked_home_is_one_alert(home):
    """/Users/runner -> /Users/admin on the round-5 image: the same LaunchAgent twice, one attributed."""
    (home / "admin" / "Library" / "LaunchAgents").mkdir(parents=True)
    os.symlink(home / "admin", home / "runner")
    now = time.time()
    real, linked = (f"{home}/{who}/Library/LaunchAgents/ai.r5test.h.plist" for who in ("admin", "runner"))
    rows = [_agent_call(home, f"printf '<plist/>' > {real}", now - 3)]
    events = [_event("user-agent", real, now, label="ai.r5test.h", program="/usr/bin/true", written=now - 2),
              _event("user-agent", linked, now, label="ai.r5test.h", program="/usr/bin/true", written=now - 2)]
    [alert] = startup_items.startup_alerts(events, rows)
    assert alert["severity"] == "critical" and "written by Claude Code" in alert["text"]
    changed = _event("user-agent", real, now + 60, kind="persistence-new", label="ai.r5test.h", written=now + 59, content="ffff0000")
    assert len(startup_items.startup_alerts([*events, changed], rows)) == 2   # new content is a new report


def test_ats_own_bookkeeping_files_are_not_jobs(home):
    now = time.time()
    events = [_event("at-job", f"/private/var/at/jobs/{name}", now, written=now - 1) for name in (".SEQ", ".lockfile", "a0000101c89af8")]
    [alert] = startup_items.startup_alerts(events, [])
    assert "a0000101c89af8" in alert["text"]


def test_an_agent_written_program_in_a_path_folder_the_person_owns_is_critical(home):
    """Founder decision 2026-11-23 (b): ~/.local/bin stays writable, and every new program an agent
    writes there raises a CRITICAL alert naming it (round 5: s5-persh's r5test-local-h)."""
    now = time.time()
    rows = [_agent_call(home, "mkdir -p ~/.local/bin && printf '#!/bin/sh\\n' > ~/.local/bin/r5test-local-h && "
                              "chmod +x ~/.local/bin/r5test-local-h && echo wrote-local-bin", now - 4)]
    [alert] = startup_items.startup_alerts([_event("path-program", f"{home}/.local/bin/r5test-local-h", now, written=now - 3)], rows)
    assert alert["severity"] == "critical" and "written by Claude Code in s4-own" in alert["text"]


def test_a_new_program_on_the_path_is_titled_as_one(home, monkeypatch):
    from plugins.blackbox.shields.network import api, notices
    now = time.time()
    monkeypatch.setattr(api, "alerts", lambda *a, **k: startup_items.startup_alerts(
        [_event("path-program", "/opt/homebrew/bin/hello", now, program="/opt/homebrew/Cellar/hello/2.12/bin/hello")], []))
    monkeypatch.setattr(notices.system_report, "snapshot", dict)
    [notice] = notices.shield_alerts()
    assert notice.title == "Network Shield · New program on your PATH"
