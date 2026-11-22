"""A program an AI agent started that runs as root is seen, recorded once and shown (Amos,
2026-11-22: "Blackbox Desktop needs to alert when an agent has obtained sudo access").

Contracts: a root process (real AND effective user 0) anywhere under a live session's process is
recorded on that session — timeline entry, `root` on the live row, one local finding; a setuid
tool and a `sudo` still asking for its password are not; it is recorded once however often the
list is read; `root` clears when the process ends; nothing is concluded when users cannot be read.
"""

from __future__ import annotations

import time

import pytest

from plugins.blackbox import agent_hooks, audit
from plugins.blackbox.agent_hooks import observe, root_watch, tracking
from plugins.blackbox.agent_hooks.instances import store, views
from plugins.blackbox.agent_hooks.instances.model import Instance

NOW = time.time()


def _proc(pid, ppid, command):
    return observe.Proc(pid, ppid, NOW - 60, command)


@pytest.fixture(autouse=True)
def _fresh(monkeypatch, tmp_path):
    store.reset()
    root_watch.reset()
    monkeypatch.setattr(agent_hooks, "_home", lambda: tmp_path)
    yield
    store.reset()
    root_watch.reset()


def _session(pid=100, key="claude-code:aaaaaaaaaaaaaaaa"):
    item = Instance(key=key, agent="claude-code", kind="session", started=NOW - 120, last=NOW, pid=pid, cwd="/Users/x/proj")
    store.put(item)
    return item


TABLE = {
    100: _proc(100, 1, "claude"),
    101: _proc(101, 100, "/bin/zsh -c sudo ./install.sh"),
    102: _proc(102, 101, "sudo ./install.sh"),
    103: _proc(103, 102, "/bin/bash ./install.sh"),
    104: _proc(104, 100, "/bin/ps -axo pid"),
    200: _proc(200, 1, "/usr/sbin/cfprefsd daemon"),
}
USERS = {100: (501, 501), 101: (501, 501), 102: (501, 0), 103: (0, 0), 104: (501, 0), 200: (0, 0)}


def test_a_root_program_under_an_agent_is_recorded_once_on_its_session():
    session = _session()
    new = root_watch.scan(TABLE, USERS, [session])
    assert [(run.pid, run.program, run.instance) for run in new] == [(103, "bash", session.key)]
    assert root_watch.scan(TABLE, USERS, [session]) == []          # the same process is not news twice
    kept = store.get(session.key)
    assert kept.root is True and kept.root_runs == 1 and kept.flagged == 1
    actions = store.actions(session.key)
    assert [(a.kind, a.what, a.verdict) for a in actions] == [("root", "bash", "flag")]
    assert "install.sh" not in actions[0].what                    # a program's name, never its arguments
    row = views.detail(session.key)["instance"]
    assert row["root"] is True and "running as root right now" in row["root_note"]
    assert views.live()["counts"]["root"] == 1


def test_a_setuid_tool_and_sudo_asking_for_a_password_are_not_root_runs():
    session = _session()
    table = {pid: proc for pid, proc in TABLE.items() if pid != 103}
    assert root_watch.scan(table, USERS, [session]) == []
    assert store.get(session.key).root is False


def test_root_clears_when_the_program_ends_and_sudo_is_noted_as_likely_still_unlocked():
    session = _session()
    root_watch.scan(TABLE, USERS, [session])
    after = {pid: proc for pid, proc in TABLE.items() if pid not in (101, 102, 103)}
    assert root_watch.scan(after, USERS, [store.get(session.key)]) == []
    kept = store.get(session.key)
    assert kept.root is False and kept.root_runs == 1
    assert "sudo usually stays unlocked" in views.root_note(kept)
    assert views.root_note(kept, now=kept.root_last + views.SUDO_CACHE_SECONDS + 1) == ""


def test_an_agent_that_itself_runs_as_root_is_recorded():
    session = _session()
    users = {**USERS, 100: (0, 0)}
    new = root_watch.scan({100: TABLE[100]}, users, [session])
    assert len(new) == 1 and new[0].itself is True
    assert store.actions(session.key)[0].what == "claude (the agent itself)"


def test_another_users_root_daemon_and_an_ended_session_are_ignored():
    session = _session()
    session.ended = NOW
    assert root_watch.scan(TABLE, USERS, [session]) == []
    assert root_watch.scan(TABLE, USERS, []) == []                 # pid 200 belongs to no agent


def test_nothing_is_concluded_when_users_cannot_be_read():
    session = _session()
    assert root_watch.scan(TABLE, {}, [session]) == []
    assert store.get(session.key).root is False


def test_the_finding_is_local_critical_and_names_the_agent():
    session = _session()
    root_watch.scan(TABLE, USERS, [session])
    rows = [row for row in audit.read_findings(limit=20) if row.get("identifier") == root_watch.ROOT_ID]
    assert len(rows) == 1
    assert rows[0]["severity"] == "critical" and rows[0]["source"] == "custom" and rows[0]["framework"] == "claude-code"
    assert rows[0]["fields"]["program"] == "bash"


def test_the_live_view_reads_users_and_records_a_root_run(monkeypatch):
    """Through tracking: one reading of the process list marks the session."""
    _session()
    lines = "\n".join(f"{p.pid} {p.ppid} Mon Nov 23 10:00:00 2026 {p.command}" for p in TABLE.values())
    monkeypatch.setattr(observe.platform, "process_table", lambda: lines)
    monkeypatch.setattr(observe.platform, "process_users", lambda: "\n".join(f"{pid} {r} {e}" for pid, (r, e) in USERS.items()))
    monkeypatch.setattr(observe.platform, "process_environment", lambda pid: "")
    monkeypatch.setattr(observe.platform, "process_variable", lambda pid, name: "")
    tracking._seen.update(at=0.0, table={}, running=[], pids=frozenset(), new_profiles=False)
    tree = tracking.live()
    rows = [row for product in tree["products"] for profile in product["profiles"] for row in profile["instances"]]
    assert rows and rows[0]["root"] is True
    assert tree["counts"]["root"] == 1
