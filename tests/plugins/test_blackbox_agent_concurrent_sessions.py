"""A session whose process is learned after the process list was read is not ended at once (KI-571).

Real Gemini CLI 0.70.0 on the test VM (2026-11-22): of two headless sessions started together, the
second was marked ended ``process-exit`` 4 ms after it started (pid 43929, last = start), and its
later events came in as late rows. Cause: the live view reuses a process list for a moment
(``tracking.TABLE_SECONDS``); the second session's process was learned from its hook's ancestry
AFTER that list was read, so it was not in it, and ``close_stale`` took "not in the list" for "its
process left". Contract, on a REAL process tree: such a session stays live; once a list read after
its latest event no longer holds its process, it ends ``process-exit``.
"""

from __future__ import annotations

import sys
import time

import pytest

from plugins.blackbox.agent_hooks import observe, tracking
from plugins.blackbox.agent_hooks.instances import store, views
from tests.plugins.test_blackbox_agent_process_ancestry import _agent_tree

macos_only = pytest.mark.skipif(sys.platform != "darwin", reason="the process observer reads processes on macOS only")
KEY = "gemini-cli:00000000000000b2"


@pytest.fixture(autouse=True)
def _fresh():
    store.reset()
    tracking._seen.update(at=0.0, read_at=0.0, table={}, running=[], pids=frozenset(), new_profiles=False)
    yield
    store.reset()


@macos_only
def test_a_second_session_learned_after_the_list_was_read_stays_live(tmp_path, monkeypatch):
    monkeypatch.setattr(tracking, "TABLE_SECONDS", 3600.0)
    tracking._snapshot()   # the list the live view reuses, read before the second session existed
    process, shell, leave = _agent_tree(tmp_path, "gemini")
    try:
        # Gemini CLI's real SessionStart payload, as the runner sends it (its hook's pid).
        tracking.track({"agent": "gemini-cli", "event": "session_start", "session": "rg-s2b", "cwd": str(tmp_path),
                        "pid": shell}, KEY)
        assert store.get(KEY).pid == process.pid
        tracking.live()
        assert store.get(KEY).ended is None, store.get(KEY).end_reason
    finally:
        leave.write_text("", encoding="utf-8")
        process.wait(timeout=10)
    assert views.close_stale(observe.read_table().keys()) == 1   # a list read after its last event
    assert store.get(KEY).end_reason == "process-exit"


def test_a_list_older_than_the_latest_event_never_ends_a_session():
    now = time.time()
    store.put(store.Instance(KEY, "gemini-cli", "session", started=now - 0.004, last=now, pid=43929))
    assert views.close_stale(alive=[1], read_at=now - 1) == 0 and store.get(KEY).ended is None
    assert views.close_stale(alive=[1], read_at=now + 1) == 1 and store.get(KEY).end_reason == "process-exit"
