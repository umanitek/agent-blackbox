"""``blackbox uninstall`` ends a running notifier before its folder goes, and a companion app's
cookie file is removable (KI-635, security round 6).

* Round 6 saw ``blackbox-notify request`` (opened with ``open -n -g … --args request``, which waits
  on the person's answer) and its launchd job ``application.ai.umanitek.blackbox.notifier.*``
  still running from the deleted ``~/.hermes/blackbox`` after uninstall. The notifier's removal
  now ends every instance running from THIS Blackbox's folder first — and nothing else.
* The add-on cleanup accepted only ``~/Library/HTTPStorages/<app_id>``, so the
  ``<app_id>.binarycookies`` file macOS keeps beside it stayed after a drag to the Trash. That
  exact name is now allowed under the same strict rules; any other name stays refused.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from plugins.blackbox.notify.platform import macos as notifier
from plugins.blackbox.setup import addon_cleanup

APP = "com.example.companion"


class _Process:
    """A process as psutil shows it: its pid and the program it runs."""

    def __init__(self, pid: int, exe: str) -> None:
        self.pid, self._exe, self.terminated = pid, exe, False

    def exe(self) -> str:
        return self._exe

    def terminate(self) -> None:
        self.terminated = True


def test_removing_the_notifier_ends_its_running_instances_and_nothing_else(tmp_path, monkeypatch):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    program = notifier.home() / "Blackbox.app" / "Contents" / "MacOS" / "blackbox-notify"
    program.parent.mkdir(parents=True)
    program.write_bytes(b"binary")
    ours, other = _Process(4101, str(program)), _Process(4102, "/Applications/Other.app/Contents/MacOS/blackbox-notify")
    processes = {process.pid: process for process in (ours, other)}
    monkeypatch.setattr(notifier.psutil, "process_iter", lambda *a, **k: list(processes.values()))
    monkeypatch.setattr(notifier.psutil, "Process", lambda pid: processes[pid])
    monkeypatch.setattr(notifier.psutil, "wait_procs", lambda procs, timeout=None: (procs, []))
    listing = (f"PID\tStatus\tLabel\n4101\t0\t{notifier.JOB_PREFIX}1.2\n4102\t0\t{notifier.JOB_PREFIX}3.4\n"
               "-\t0\tcom.example.unrelated\n")
    ran: list[list[str]] = []

    def fake_run(argv, **_kwargs):
        ran.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, stdout=listing if argv[1:] == ["list"] else "", stderr="")
    monkeypatch.setattr(notifier.subprocess, "run", fake_run)
    notifier.remove()
    assert [notifier.LAUNCHCTL, "remove", f"{notifier.JOB_PREFIX}1.2"] in ran          # this notifier's job
    assert not any(argv[-1] == f"{notifier.JOB_PREFIX}3.4" for argv in ran)        # another folder's: never
    assert ours.terminated and not other.terminated
    assert not notifier.home().exists()


def _checked(home: Path, raw: str):
    (home / "Library" / "HTTPStorages").mkdir(parents=True, exist_ok=True)
    return addon_cleanup._checked_path(raw, APP, home)


def test_the_companion_apps_cookie_file_beside_its_http_storage_is_allowed(tmp_path):
    path, why = _checked(tmp_path, str(tmp_path / "Library" / "HTTPStorages" / f"{APP}.binarycookies"))
    assert why == "" and path is not None and path.name == f"{APP}.binarycookies"


@pytest.mark.parametrize("name", [f"{APP}.binarycookies.bak", "com.example.other.binarycookies", f"x{APP}.binarycookies"])
def test_any_other_cookie_file_name_is_refused(tmp_path, name):
    path, why = _checked(tmp_path, str(tmp_path / "Library" / "HTTPStorages" / name))
    assert path is None and "not named after" in why


def test_the_cookie_name_is_allowed_only_under_http_storages(tmp_path):
    (tmp_path / "Library" / "Caches").mkdir(parents=True)
    path, why = addon_cleanup._checked_path(str(tmp_path / "Library" / "Caches" / f"{APP}.binarycookies"), APP, tmp_path)
    assert path is None and "not named after" in why


def test_uninstall_ends_the_notifier_it_finds(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from plugins.blackbox import notify
    from plugins.blackbox.setup import uninstall
    order: list[str] = []
    monkeypatch.setattr(notify, "remove_notifier", lambda: order.append("notifier"))
    (tmp_path / "bb" / "notifier").mkdir(parents=True)
    report: list[str] = []
    uninstall._stop_notifier(SimpleNamespace(blackbox_home=tmp_path / "bb"), report)
    assert order == ["notifier"] and report == ["stopped and removed Blackbox's notifier"]
