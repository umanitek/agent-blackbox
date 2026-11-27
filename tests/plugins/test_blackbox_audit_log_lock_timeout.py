"""A record written while another process holds the logs lock is never lost (review 2026-11-26, LOW-MED).

A hook waits at most ``_LOGS_LOCK_WAIT_S`` for the logs lock. Past that it used to append to the
live log without the lock — and a trim the lock holder was running then swapped its kept tail in
by rename, over the record. Now such a record goes to a side file no trim touches, and the next
writer that holds the lock moves it into the log. Contracts:

- a record written without the lock survives a trim that replaces the log meanwhile;
- it reaches the log at the next locked append, and its side file is gone afterwards;
- the hook still never waits longer than the bounded lock wait.
"""

from __future__ import annotations

import contextlib
from pathlib import Path

from plugins.blackbox.audit import log_store
from plugins.blackbox.kernel.bounded_files import atomic_write, read_jsonl


def _lock_busy(monkeypatch) -> None:
    """Every lock attempt times out, as when another process holds it past the wait."""
    @contextlib.contextmanager
    def busy(_path, **_kwargs):
        yield False
    monkeypatch.setattr(log_store, "file_lock", busy)


def test_a_record_written_without_the_lock_survives_a_trim_and_reaches_the_log(tmp_path, monkeypatch):
    log = tmp_path / "audit.jsonl"
    log_store._append_jsonl(log, {"n": 0})
    with monkeypatch.context() as patch:
        _lock_busy(patch)
        log_store._append_jsonl(log, {"n": 1})          # the lock holder is trimming right now…
    atomic_write(log, (log.read_bytes() if log.exists() else b"").split(b"\n")[0] + b"\n")   # …and swaps its tail in
    log_store._append_jsonl(log, {"n": 2})              # the next locked writer
    assert sorted(row["n"] for row in read_jsonl(log)) == [0, 1, 2]
    leftovers = [path for path in tmp_path.rglob("*") if path.is_file() and path.name not in {"audit.jsonl", ".logs.lock"}]
    assert leftovers == []


def test_the_hook_does_not_wait_beyond_the_bounded_lock_wait(tmp_path, monkeypatch):
    waits: list[float] = []

    @contextlib.contextmanager
    def timed(_path, **kwargs):
        waits.append(kwargs.get("timeout_s"))
        yield False
    monkeypatch.setattr(log_store, "file_lock", timed)
    log_store._append_jsonl(tmp_path / "audit.jsonl", {"n": 1})
    assert waits and all(wait is not None and wait <= log_store._LOGS_LOCK_WAIT_S for wait in waits)


def test_side_files_of_another_log_are_left_for_that_log(tmp_path, monkeypatch):
    with monkeypatch.context() as patch:
        _lock_busy(patch)
        log_store._append_jsonl(tmp_path / "findings.jsonl", {"kind": "finding"})
    log_store._append_jsonl(tmp_path / "audit.jsonl", {"kind": "audit"})
    assert [row["kind"] for row in read_jsonl(tmp_path / "audit.jsonl")] == ["audit"]
    log_store._append_jsonl(tmp_path / "findings.jsonl", {"kind": "later"})
    assert [row["kind"] for row in read_jsonl(Path(tmp_path / "findings.jsonl"))] == ["finding", "later"]
