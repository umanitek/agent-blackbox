"""One torn-free write for the whole plugin (2026-10-22).

31 files hand-rolled "temp file + os.replace" in three spellings, one of them
creating the file 0600 and the others not, with no single place to fix. Now
``kernel.bounded_files.atomic_write`` is the one implementation, and a guard
names the few files still allowed to call ``os.replace`` themselves (the ones
that also fsync, and the standalone installer helper).
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from plugins.blackbox.kernel.bounded_files import atomic_write, read_json_object
from plugins.blackbox.kernel.health import days_between, today_utc

PLUGIN = Path(__file__).resolve().parents[2] / "plugins" / "blackbox"

#: Files that may call os.replace themselves: the implementation, and the two that run
#: standalone without the plugin on their path (the node launcher's limits file, the
#: installer helper). Writers that fsync use ``atomic_write(..., durable=True)``.
MAY_REPLACE = {
    "kernel/bounded_files/atomic_write.py",
    "sync/process_limits.py",
    "setup/blackbox-dkg-runtime-fingerprint.py",
}


def test_a_write_lands_whole_and_creates_its_folder(tmp_path):
    target = tmp_path / "deep" / "state.json"

    atomic_write(target, '{"a": 1}')
    atomic_write(target, '{"a": 2}')

    assert target.read_text(encoding="utf-8") == '{"a": 2}'
    assert [p.name for p in target.parent.iterdir()] == ["state.json"]   # no temp file left behind


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_a_secret_is_created_0600_from_the_start(tmp_path):
    target = tmp_path / "key.pem"

    atomic_write(target, "secret", mode=0o600)

    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert target.read_text(encoding="utf-8") == "secret"


def test_a_durable_write_is_flushed_to_the_disk_before_the_rename(tmp_path, monkeypatch):
    order: list[str] = []
    real_fsync, real_replace = os.fsync, os.replace
    monkeypatch.setattr(os, "fsync", lambda fd: (order.append("fsync"), real_fsync(fd))[1])
    monkeypatch.setattr(os, "replace", lambda src, dst: (order.append("replace"), real_replace(src, dst))[1])

    atomic_write(tmp_path / "counter.json", "{}", mode=0o600, durable=True)
    atomic_write(tmp_path / "plain.json", "{}")

    assert order == ["fsync", "replace", "replace"]          # only the durable write syncs, and before its rename


def test_a_failed_write_leaves_no_temp_file_and_keeps_the_old_content(tmp_path, monkeypatch):
    target = tmp_path / "state.json"
    atomic_write(target, "old")

    def refuse(src, dst):
        raise OSError("disk full")
    monkeypatch.setattr(os, "replace", refuse)

    with pytest.raises(OSError):
        atomic_write(target, "new")

    assert target.read_text(encoding="utf-8") == "old"
    assert not [p.name for p in tmp_path.iterdir() if ".tmp." in p.name]


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_a_plain_write_keeps_the_process_default_permissions(tmp_path):
    old = os.umask(0o022)
    try:
        atomic_write(tmp_path / "state.json", "{}")
    finally:
        os.umask(old)

    assert stat.S_IMODE((tmp_path / "state.json").stat().st_mode) == 0o644


def test_a_json_object_file_reads_back_as_its_object(tmp_path):
    target = tmp_path / "state.json"
    atomic_write(target, '{"a": 1, "nested": {"b": [1, 2]}}')

    assert read_json_object(target) == {"a": 1, "nested": {"b": [1, 2]}}


def test_a_byte_order_mark_is_dropped(tmp_path):
    target = tmp_path / "state.json"
    target.write_bytes(b"\xef\xbb\xbf" + b'{"a": 1}')      # what Windows Notepad saves

    assert read_json_object(target) == {"a": 1}


@pytest.mark.parametrize("content", [None, b"", b"{not json", b"[1, 2]", b'"text"', b"null", b"\xff\xfe\x00", b"[" * 100_000])
def test_anything_that_is_not_a_readable_json_object_is_none_never_an_error(tmp_path, content):
    target = tmp_path / "state.json"
    if content is not None:                                   # None: the file does not exist
        target.write_bytes(content)

    assert read_json_object(target) is None


def test_a_folder_in_the_files_place_is_none(tmp_path):
    assert read_json_object(tmp_path) is None


def test_no_module_rolls_its_own_replace():
    offenders = sorted(
        str(path.relative_to(PLUGIN))
        for path in PLUGIN.rglob("*.py")
        if "os.replace(" in path.read_text(encoding="utf-8-sig")
        and str(path.relative_to(PLUGIN)) not in MAY_REPLACE
    )
    assert offenders == [], f"use kernel.bounded_files.atomic_write instead: {offenders}"


def test_days_between_reads_iso_days_and_never_raises():
    assert days_between("2026-10-01", "2026-10-22") == 21
    assert days_between("2026-10-22", "2026-10-01") == -21
    assert days_between("not a day", "2026-10-22") == 0
    assert len(today_utc()) == 10 and today_utc()[4] == "-"


# --- the one log-file append and read (kernel/bounded_files/jsonl.py) ---

def test_appended_lines_read_back_in_order_and_create_the_folder(tmp_path):
    from plugins.blackbox.kernel.bounded_files import append_line, read_jsonl
    log = tmp_path / "deep" / "audit.jsonl"

    append_line(log, '{"n": 1}')
    append_line(log, '{"n": 2, "text": "café"}')

    assert read_jsonl(log) == [{"n": 1}, {"n": 2, "text": "café"}]
    assert log.read_text(encoding="utf-8").endswith("\n")


def test_a_damaged_blank_or_non_object_line_is_skipped_not_fatal(tmp_path):
    from plugins.blackbox.kernel.bounded_files import read_jsonl
    log = tmp_path / "audit.jsonl"
    log.write_text('{"n": 1}\n\n{broken\n[1, 2]\n"text"\n7\n   \n{"n": 2}\n', encoding="utf-8")

    assert read_jsonl(log) == [{"n": 1}, {"n": 2}]


def test_a_missing_log_is_an_empty_log(tmp_path):
    from plugins.blackbox.kernel.bounded_files import read_jsonl
    assert read_jsonl(tmp_path / "nothing.jsonl") == [] and read_jsonl(tmp_path) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_a_private_log_is_created_0600_and_a_plain_one_is_not(tmp_path):
    from plugins.blackbox.kernel.bounded_files import append_line
    old = os.umask(0o022)
    try:
        append_line(tmp_path / "private.jsonl", "{}", mode=0o600)
        append_line(tmp_path / "plain.jsonl", "{}")
    finally:
        os.umask(old)

    assert stat.S_IMODE((tmp_path / "private.jsonl").stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "plain.jsonl").stat().st_mode) == 0o644


def test_a_durable_append_is_flushed_to_the_disk(tmp_path, monkeypatch):
    from plugins.blackbox.kernel.bounded_files import append_line
    synced: list[int] = []
    real_fsync = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (synced.append(fd), real_fsync(fd))[1])

    append_line(tmp_path / "ledger.jsonl", "{}", mode=0o600, durable=True)
    append_line(tmp_path / "plain.jsonl", "{}")

    assert len(synced) == 1


def test_the_audit_reader_survives_a_line_that_is_json_but_not_an_object(tmp_path):
    """The audit reader used to raise on such a line (`"event" not in 7`)."""
    from plugins.blackbox.audit import log_store
    log = tmp_path / "file_access.jsonl"
    log.write_text('{"path": "a"}\n7\n[1]\n{"path": "b", "event": "seen"}\n', encoding="utf-8")

    assert log_store._load_jsonl(log, "file_access") == [{"path": "a", "event": "file_access"},
                                                          {"path": "b", "event": "seen"}]


# --- the one cross-process lock (kernel/bounded_files/locking.py) ---

def test_a_second_holder_is_refused_until_the_first_lets_go(tmp_path):
    from plugins.blackbox.kernel.bounded_files import file_lock
    lock = tmp_path / "deep" / "work.lock"

    with file_lock(lock) as first:
        with file_lock(lock, blocking=False) as second:      # another open file: the same as another process
            assert (first, second) == (True, False)
    with file_lock(lock, blocking=False) as again:
        assert again is True


def test_a_bounded_wait_gives_up_after_its_time(tmp_path):
    import time
    from plugins.blackbox.kernel.bounded_files import file_lock
    lock = tmp_path / "work.lock"

    with file_lock(lock):
        started = time.monotonic()
        with file_lock(lock, timeout_s=0.15) as waited:
            elapsed = time.monotonic() - started

    assert waited is False and 0.1 <= elapsed < 2.0


def test_the_lock_is_released_when_the_work_raises(tmp_path):
    from plugins.blackbox.kernel.bounded_files import file_lock
    lock = tmp_path / "work.lock"

    with pytest.raises(RuntimeError):
        with file_lock(lock):
            raise RuntimeError("the work failed")
    with file_lock(lock, blocking=False) as again:
        assert again is True


def test_a_lock_file_that_cannot_be_opened_is_an_error_for_the_caller_to_decide(tmp_path):
    from plugins.blackbox.kernel.bounded_files import file_lock
    (tmp_path / "in-the-way").write_text("a file, not a folder", encoding="utf-8")

    with pytest.raises(OSError):
        with file_lock(tmp_path / "in-the-way" / "work.lock"):
            pass


# --- create a secret file once (kernel/bounded_files.create_once) ---

@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_a_new_secret_is_written_whole_private_and_leaves_no_temp_file(tmp_path):
    from plugins.blackbox.kernel.bounded_files import create_once
    target = tmp_path / "deep" / "key.pem"

    assert create_once(target, b"the key") is True

    assert target.read_bytes() == b"the key" and stat.S_IMODE(target.stat().st_mode) == 0o600
    assert [p.name for p in target.parent.iterdir()] == ["key.pem"]


def test_an_existing_secret_is_never_replaced(tmp_path):
    from plugins.blackbox.kernel.bounded_files import create_once
    target = tmp_path / "key.pem"
    create_once(target, b"first")

    assert create_once(target, b"second") is False

    assert target.read_bytes() == b"first"
    assert not [p.name for p in tmp_path.iterdir() if ".tmp." in p.name]


def test_a_crash_while_writing_leaves_no_file_rather_than_an_empty_one(tmp_path, monkeypatch):
    from plugins.blackbox.kernel.bounded_files import create_once
    target = tmp_path / "key.pem"

    def crash(fd, data):
        raise OSError("power cut")
    monkeypatch.setattr(os, "write", crash)

    with pytest.raises(OSError):
        create_once(target, b"the key")

    assert not target.exists()
    assert not [p.name for p in tmp_path.iterdir() if ".tmp." in p.name]


def test_the_reputation_index_key_is_never_left_empty_and_two_creators_agree(tmp_path, monkeypatch):
    """The old creation opened the key file, then wrote: a crash in between left an empty
    file that read as malformed for good, and the reputation ledger could never be saved."""
    from plugins.blackbox.community.reputation import sealed_index
    path = tmp_path / "index.key"
    real_write = os.write

    def crash(fd, data):
        raise OSError("power cut")
    monkeypatch.setattr(os, "write", crash)
    with pytest.raises(OSError):
        sealed_index.load_or_create_key(path)
    assert not path.exists()                        # nothing half-made: the next use starts clean

    monkeypatch.setattr(os, "write", real_write)
    first = sealed_index.load_or_create_key(path)
    assert first is not None and len(first) == 32
    assert sealed_index.load_or_create_key(path) == first


# --- UTC day helpers (kernel/health/days.py) ---

def test_an_epoch_time_reads_as_its_utc_day_whatever_the_machines_time_zone(monkeypatch):
    import time
    from plugins.blackbox.kernel.health import utc_day, utc_day_or
    just_before_midnight_utc = 1_793_577_599      # 2026-11-01T23:59:59Z
    for zone in ("Pacific/Kiritimati", "America/Port_of_Spain", "UTC"):      # UTC+14, UTC-4, UTC
        monkeypatch.setenv("TZ", zone)
        if hasattr(time, "tzset"):
            time.tzset()
        assert utc_day(just_before_midnight_utc) == "2026-11-01"
        assert utc_day(just_before_midnight_utc + 1) == "2026-11-02"
    assert utc_day_or(just_before_midnight_utc, "fallback") == "2026-11-01"


@pytest.mark.parametrize("missing", [None, 0, "", "not a time", float("inf"), 1e30, [1]])
def test_an_absent_or_unreadable_time_gives_the_fallback_day(missing):
    from plugins.blackbox.kernel.health import utc_day_or
    assert utc_day_or(missing, "2026-11-10") == "2026-11-10"


def test_a_child_hermes_is_this_process_python_running_hermes_entry_module():
    """One spelling for every child ``hermes …`` process: this Python, Hermes' entry module."""
    import sys

    from plugins.blackbox.kernel.host_command import hermes_argv

    assert hermes_argv() == [sys.executable, "-m", "hermes_cli.main"]
    assert hermes_argv("blackbox", "setup") == [sys.executable, "-m", "hermes_cli.main", "blackbox", "setup"]


def test_the_dashboard_port_default_is_named_once():
    """Config, uninstall and the dashboard's own start all take the default from the kernel."""
    import inspect

    from plugins.blackbox.dashboard import server
    from plugins.blackbox.kernel import constants
    from plugins.blackbox.kernel.config import BlackboxConfig
    from plugins.blackbox.setup import uninstall

    assert constants.DEFAULT_DASHBOARD_PORT == 9700
    assert BlackboxConfig().dashboard_port == constants.DEFAULT_DASHBOARD_PORT
    assert inspect.signature(server.start_dashboard).parameters["port"].default == constants.DEFAULT_DASHBOARD_PORT
    assert uninstall.UninstallPlan.__dataclass_fields__["dashboard_port"].default == constants.DEFAULT_DASHBOARD_PORT


def test_a_json_state_file_is_saved_whole_or_a_warning_says_it_was_not(tmp_path, caplog):
    import logging

    from plugins.blackbox.kernel.bounded_files import read_json_object, write_json_object

    path = tmp_path / "deep" / "state.json"
    assert write_json_object(path, {"pending": [1, 2]}, what="the test queue") is True
    assert read_json_object(path) == {"pending": [1, 2]}
    blocked = tmp_path / "a-file"
    blocked.write_text("x", encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        assert write_json_object(blocked / "state.json", {}, what="the test queue") is False
    assert "could not save the test queue" in caplog.text
