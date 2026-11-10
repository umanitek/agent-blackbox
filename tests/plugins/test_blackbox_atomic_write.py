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
