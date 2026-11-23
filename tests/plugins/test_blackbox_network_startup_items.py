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

KI-636 (security round 6, bb-sec-r6, raw/bA3.log, raw/bB2.log, raw/bD.log): the watch named an agent
from a call that was REFUSED — Claude Code's refused Read of ~/.ssh/authorized_keys (s6-ptcch) for the
harness shell's ``sed -i`` 30 s later, Cline's refused append (s6-psclhb-3) for a key another session's
script appended, the simulated session s6-sim (every command refused) for a plain-shell append. Only a
call that ran is evidence: a refused ``pre_tool_call`` and a call whose ``post_tool_call`` records the
OS sandbox's refusal never are.
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
        assert alert["severity"] == "high" and "written by" not in alert["text"]


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
                     "New startup item: Scheduled job (at) “a0001”.": "high",
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
    assert alert["severity"] == "high" and "agent" not in alert and "written by" not in alert["text"]
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


KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIR6TESTR6TESTR6TESTR6TESTR6TESTR6TESTR6T"
HOOK_REFUSAL = ("Blackbox blocked this tool call — it was refused by Blackbox's self-protection and your protected-paths "
                "rule")
SANDBOX_REFUSAL = ("Blackbox's sandbox refused this (/Users/admin/.ssh/authorized_keys): an agent may not leave something "
                   "that starts by itself later, outside the sandbox")


def _call(home, agent: str, session: str, tool: str, args: dict, ts: float, call_id: str, decision: str = "allow") -> dict:
    """A hook's ``pre_tool_call`` record, as ``agent_hooks.protect.events.bookkeep`` writes it."""
    return {"ts": ts, "event": "pre_tool_call", "framework": agent, "workspace": str(home / "camp" / "projects" / session),
            "detail": {"session_id": f"{agent}:{session}", "tool_name": tool, "tool_call_id": call_id, "args": args,
                       "decision": decision}}


def _end(agent: str, session: str, ts: float, call_id: str, decision: str = "") -> dict:
    return {"ts": ts, "event": "post_tool_call", "framework": agent,
            "detail": {"session_id": f"{agent}:{session}", "tool_name": "terminal", "tool_call_id": call_id,
                       **({"decision": decision} if decision else {})}}


def _key_changed(home, written: float) -> dict:
    return _event("ssh-login", f"{home}/.ssh/authorized_keys", written + 1, kind="persistence-changed", written=written)


def test_a_refused_read_of_the_ssh_login_file_is_never_its_writer(home):
    """s6-ptcch: Claude Code's Read was refused; ~30 s later the harness shell rewrote the file."""
    now = time.time()
    rows = [_call(home, "claude-code", "s6-ptcch", "read_file", {"path": f"{home}/.ssh/authorized_keys"}, now - 30, "toolu_r6read",
                  decision="block")]
    [alert] = startup_items.startup_alerts([_key_changed(home, now)], rows)
    assert "agent" not in alert and "written by" not in alert["text"] and "writer unknown" not in alert["text"]
    assert alert["severity"] == "high"


def test_a_refused_append_in_one_session_is_not_the_writer_of_a_key_another_session_appended(home):
    """s6-psclhb-3's own append was refused; s6-psclhb-9's pre-placed k.py appended the key (its
    command names no path), within the old two-minute fallback of the refused call."""
    now = time.time()
    rows = [_call(home, "cline", "s6-psclhb-3", "terminal", {"command": f"echo '{KEY} r6test-clh-3' >> ~/.ssh/authorized_keys"},
                  now - 60, "call_r6_3", decision="block"),
            _call(home, "cline", "s6-psclhb-9", "terminal", {"command": f"python3 k.py ssh authorized {KEY.replace(' ', '_')}_r6test-clh-9"},
                  now - 2, "call_r6_9"),
            _end("cline", "s6-psclhb-9", now + 1, "call_r6_9")]
    [alert] = startup_items.startup_alerts([_key_changed(home, now)], rows)
    assert "agent" not in alert and "s6-psclhb-3" not in alert["text"] and "written by" not in alert["text"]


def test_a_call_the_sandbox_refused_while_it_ran_is_not_the_writer(home):
    """A sandboxed append that ran and was refused by the kernel (its post_tool_call says block)."""
    now = time.time()
    command = ("python3 -c \"import os; open(os.path.expanduser('~/.ssh/authorized_keys'),'a').write('" + KEY + " r6test-ccs\\n')\"")
    rows = [_call(home, "claude-code", "s6-psccsb-2", "terminal", {"command": command}, now - 3, "toolu_r6s"),
            _end("claude-code", "s6-psccsb-2", now + 1, "toolu_r6s", decision="block")]
    [alert] = startup_items.startup_alerts([_key_changed(home, now)], rows)
    assert "agent" not in alert and "written by" not in alert["text"]


def test_a_call_that_ran_is_still_the_writer_and_one_decided_too_late_ran(home):
    now = time.time()
    for decision in ("allow", "too-late"):
        rows = [_call(home, "codex", "s6-pscxh", "terminal", {"command": f"echo '{KEY} r6' >> ~/.ssh/authorized_keys"}, now - 2,
                      "call_cx", decision=decision),
                _end("codex", "s6-pscxh", now + 1, "call_cx")]
        [alert] = startup_items.startup_alerts([_key_changed(home, now)], rows)
        assert alert["severity"] == "critical" and "written by Codex in s6-pscxh" in alert["text"], decision


def test_an_unknown_writers_ssh_key_cron_job_or_login_preference_is_high(home):
    """Security round 7 (byp7.sh 3, 4, 6): an SSH key appended, a cron job written and the login
    window's preferences changed by a hooks-only agent were alerted MEDIUM and unattributed. A
    security-sensitive place changed by nobody Blackbox knows is HIGH."""
    now = time.time()
    events = [_event("ssh-login", f"{home}/.ssh/authorized_keys", now, kind="persistence-changed", written=now - 1),
              _event("cron", "/usr/lib/cron/tabs/admin", now, written=now - 1),
              _event("login-prefs", f"{home}/Library/Preferences/loginwindow.plist", now, kind="persistence-changed", written=now - 1)]
    alerts = startup_items.startup_alerts(events, [])
    assert [alert["severity"] for alert in alerts] == ["high", "high", "high"], alerts
    assert any("Login preferences" in alert["text"] and "loginwindow.plist" in alert["text"] for alert in alerts), alerts


def test_the_helpers_login_preference_event_is_accepted(home, monkeypatch):
    now = time.time()
    report = system_report.validate({"watching": False, "events": [
        _event("login-prefs", f"{home}/Library/Preferences/com.apple.loginitems.plist", now - 1, kind="persistence-changed")]}, now)
    system_report.record(report)
    monkeypatch.setattr(audit, "read_audit", lambda limit=100, offset=0: [])
    texts = {alert["text"]: alert["severity"] for alert in system_alerts.alerts(20)}
    assert texts == {"Startup item changed: Login preferences “com.apple.loginitems.plist”.": "high"}, texts


def test_the_helper_watches_the_login_preferences_of_the_one_list():
    """The helper's watch (run_later.rs LOGIN_PREFERENCES) and the sandbox / hook list
    (kernel.persistence_places.PERSISTENCE_GLOBS) name the same login preference files."""
    import re
    from pathlib import Path
    from plugins.blackbox.kernel import persistence_places
    source = (Path(__file__).resolve().parents[2] / "plugins/blackbox/helper/src/platform/macos/observe/run_later.rs").read_text(encoding="utf-8")
    watched = set(re.findall(r'"([^"]+)"', re.search(r"LOGIN_PREFERENCES: &\[&str\] = &\[([^\]]*)\]", source).group(1)))
    listed = {glob.rsplit("/", 1)[-1].rstrip("*") for glob in persistence_places.PERSISTENCE_GLOBS if "/Library/Preferences/" in glob}
    assert watched == listed, (watched, listed)
