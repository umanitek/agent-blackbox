"""The audit logs lose no record and show no torn file when several agents write them.

Several agent processes share one ``$BLACKBOX_HOME`` and append to the same ``audit.jsonl``
and ``findings.jsonl``. When a log passed its cap, the trim read the tail and rewrote the
live file in place, guarded only by an in-process lock: a record another process appended
in between was lost, and a reader at that moment saw a truncated file. The append and the
trim now run under one cross-process lock and the trim swaps the kept tail in by rename.
"""

from __future__ import annotations

import json
import multiprocessing
from pathlib import Path

import pytest

from plugins.blackbox.audit import log_store

WRITERS = 4
RECORDS_EACH = 300


def _write(log: str, writer: int) -> None:
    """One agent process: append RECORDS_EACH numbered records to a log with a tiny cap."""
    from plugins.blackbox.audit import log_store as store
    store._LOG_MAX_BYTES, store._LOG_KEEP_BYTES = 6_000, 3_000        # trim every few dozen records
    for number in range(RECORDS_EACH):
        store._append_jsonl(Path(log), {"writer": writer, "n": number, "pad": "x" * 60})


def _append_one(log: str, about_to_append) -> None:
    """Another agent process: say it is ready, then append one record the ordinary way."""
    from plugins.blackbox.audit import log_store as store
    about_to_append.set()
    store._append_jsonl(Path(log), {"from": "the other process"})


def test_a_record_another_process_appends_during_a_trim_is_kept(tmp_path, monkeypatch):
    """The lost record, made to happen: while this process is between reading the tail and
    swapping it in, another process appends. It must wait for the trim and land after it."""
    log = tmp_path / "audit.jsonl"
    monkeypatch.setattr(log_store, "_LOG_MAX_BYTES", 2_000)
    monkeypatch.setattr(log_store, "_LOG_KEEP_BYTES", 1_000)
    context = multiprocessing.get_context("spawn")
    others: list = []
    real_write = log_store.atomic_write

    def write_after_the_other_process_had_its_chance(path, data, **kwargs):
        about_to_append = context.Event()
        other = context.Process(target=_append_one, args=(str(log), about_to_append))
        other.start()
        others.append(other)
        assert about_to_append.wait(30)
        other.join(0.2)            # unlocked, its append lands here — in the file about to be replaced
        real_write(path, data, **kwargs)
    monkeypatch.setattr(log_store, "atomic_write", write_after_the_other_process_had_its_chance)

    for number in range(40):       # enough to pass the cap once
        log_store._append_jsonl(log, {"n": number, "pad": "x" * 60})
        if others:
            break
    for other in others:
        other.join(30)
        assert other.exitcode == 0

    assert len(others) == 1, "the log never reached its cap"
    assert {"from": "the other process"} in log_store.read_jsonl(log)


def test_many_writers_leave_whole_lines_and_an_unbroken_end_for_each(tmp_path):
    log = tmp_path / "audit.jsonl"
    context = multiprocessing.get_context("spawn")
    writers = [context.Process(target=_write, args=(str(log), writer)) for writer in range(WRITERS)]
    for process in writers:
        process.start()
    for process in writers:
        process.join(120)
        assert process.exitcode == 0

    lines = log.read_text(encoding="utf-8").splitlines()
    rows = [json.loads(line) for line in lines]                       # every line is whole
    assert rows and log.stat().st_size <= 6_000 + 200                 # and the cap held
    for writer in range(WRITERS):
        kept = [row["n"] for row in rows if row["writer"] == writer]
        # A trim drops the OLDEST records: what is left of each writer is the unbroken end of what it wrote.
        assert kept == list(range(RECORDS_EACH - len(kept), RECORDS_EACH)), f"writer {writer} lost a record"


def test_a_log_under_its_cap_is_left_alone(tmp_path, monkeypatch):
    log = tmp_path / "audit.jsonl"
    for number in range(5):
        log_store._append_jsonl(log, {"n": number})

    assert [row["n"] for row in log_store.read_jsonl(log)] == [0, 1, 2, 3, 4]


def test_a_record_is_written_even_when_the_lock_cannot_be_used(tmp_path, monkeypatch):
    log = tmp_path / "audit.jsonl"

    def no_lock(*args, **kwargs):
        raise OSError("read-only folder")
    monkeypatch.setattr(log_store, "file_lock", no_lock)

    log_store._append_jsonl(log, {"n": 1})

    assert log_store.read_jsonl(log) == [{"n": 1}]


def test_a_busy_lock_delays_the_trim_but_never_the_record(tmp_path, monkeypatch):
    from plugins.blackbox.kernel.bounded_files import file_lock
    log = tmp_path / "audit.jsonl"
    monkeypatch.setattr(log_store, "_LOG_MAX_BYTES", 200)
    monkeypatch.setattr(log_store, "_LOG_KEEP_BYTES", 100)
    monkeypatch.setattr(log_store, "_LOGS_LOCK_WAIT_S", 0.05)

    with file_lock(log.with_name(log_store._LOGS_LOCK_FILE)):          # another process is mid-trim
        for number in range(10):
            log_store._append_jsonl(log, {"n": number, "pad": "x" * 40})
        assert len(log_store.read_jsonl(log)) == 10                    # all written, none trimmed
    log_store._append_jsonl(log, {"n": 10, "pad": "x" * 40})

    assert log.stat().st_size <= 200 and log_store.read_jsonl(log)[-1]["n"] == 10


@pytest.mark.parametrize("data", [b"\xe2\x82\xac raw bytes\r\n\n", "text \u20ac"])
def test_the_kernel_write_takes_bytes_as_they_are(tmp_path, data):
    from plugins.blackbox.kernel.bounded_files import atomic_write
    atomic_write(tmp_path / "out", data)

    assert (tmp_path / "out").read_bytes() == (data if isinstance(data, bytes) else data.encode("utf-8"))
