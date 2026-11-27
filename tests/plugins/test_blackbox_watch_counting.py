"""A watch rule's verdict never depends on counting its hit (``watch.check`` / ``watch.state.count``;
review finding of 2026-11-26).

``check()`` counted each hit (a locked JSON write) BEFORE it returned the findings: when that write
failed — Blackbox's home is read-only inside the OS sandbox — the whole check raised, and an
``enforce`` rule's refusal was lost. A busy lock also held the call up to 2 s and then wrote
without the lock. Now the findings are built first and the count is best-effort: a short wait, a
count skipped (never written unlocked) when the lock is not held, never an error to the verdict.
"""

from __future__ import annotations

import contextlib
import time

import pytest

from plugins.blackbox import watch
from plugins.blackbox.watch import state

INSTALL = {"command": "npm install left-pad@1.3.0"}


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "blackbox"))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))
    (tmp_path / "hermes").mkdir()
    assert watch.add("package", "npm:left-pad")["ok"]
    assert watch.promote(watch.rule_id("package", "npm:left-pad"))["ok"]


def test_an_enforced_rule_still_reports_its_finding_when_the_hit_can_not_be_written(monkeypatch):
    def read_only(*_a, **_k):
        raise PermissionError("read-only file system")
    monkeypatch.setattr(state, "file_lock", read_only)
    found = watch.check("terminal", INSTALL, agent="codex")
    assert [f.severity for f in found] == ["critical"] and found[0].identifier.startswith("watch:")


def test_a_busy_lock_skips_the_count_quickly_and_never_writes_unlocked(monkeypatch):
    waited: list = []

    @contextlib.contextmanager
    def busy(_path, *, blocking=True, timeout_s=None):
        waited.append(timeout_s)
        yield False
    monkeypatch.setattr(state, "file_lock", busy)
    began = time.monotonic()
    assert watch.check("terminal", INSTALL, agent="codex")
    assert time.monotonic() - began < 1.0 and waited and waited[0] <= 0.25
    assert watch.hits() == {}     # not held: nothing written without the lock
