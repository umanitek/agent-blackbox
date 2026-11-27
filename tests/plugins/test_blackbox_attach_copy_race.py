"""Two writers of one agent's plugin folder never leave it missing (review 2026-11-26, HIGH; LES-167).

``copy_plugin_tree`` builds the new copy aside and swaps it in by rename. Its staging folders were
named by process id, so two writers in one process (the dashboard's rescan and its "protect every
agent" route) shared them, and the last step removed every writer's staging folder: in a probe 7 of
15 trials left ``plugins/blackbox`` missing. These contracts hold:

- two writers copying into one destination at once always leave a complete copy there;
- a staging folder of another writer is never removed;
- when the final swap fails, the previous copy is put back;
- every attach path runs under the one attach lock (``attach.ATTACH_LOCK``).
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

from plugins.blackbox import attach
from plugins.blackbox.attach import plugin_copy


@pytest.fixture
def source(tmp_path, monkeypatch):
    monkeypatch.setattr(plugin_copy, "_bundle_openclaw_plugin", lambda _src, _dest: None)
    src = tmp_path / "src" / "plugins" / "blackbox"
    (src / "kernel").mkdir(parents=True)
    (src / "__init__.py").write_text("# plugin\n", encoding="utf-8")
    for index in range(30):
        (src / "kernel" / f"m{index}.py").write_text("x = 1\n", encoding="utf-8")
    return src


def test_two_writers_at_once_always_leave_a_complete_copy(source, tmp_path):
    dest = tmp_path / "home" / "plugins" / "blackbox"
    errors: list[BaseException] = []
    for _trial in range(15):
        start = threading.Barrier(2)

        def writer() -> None:
            start.wait()
            try:
                plugin_copy.copy_plugin_tree(source, dest)
            except BaseException as exc:   # collected: the assertion below names it
                errors.append(exc)

        threads = [threading.Thread(target=writer) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert (dest / "__init__.py").is_file() and len(list((dest / "kernel").iterdir())) == 30
    assert errors == []


def test_another_writers_staging_folder_is_left_alone(source, tmp_path):
    dest = tmp_path / "home" / "plugins" / "blackbox"
    other = tmp_path / "home" / ".blackbox-attach-copy" / f"new-{os.getpid()}-someone-else"
    other.mkdir(parents=True)
    plugin_copy.copy_plugin_tree(source, dest)
    assert other.is_dir() and (dest / "__init__.py").is_file()


def test_a_failed_swap_puts_the_previous_copy_back(source, tmp_path, monkeypatch):
    dest = tmp_path / "home" / "plugins" / "blackbox"
    plugin_copy.copy_plugin_tree(source, dest)
    (dest / "previous.txt").write_text("old copy", encoding="utf-8")
    real_rename = os.rename

    def failing_rename(src, dst):
        if Path(dst) == dest and "new-" in Path(src).name:
            raise OSError("disk full")
        return real_rename(src, dst)

    monkeypatch.setattr(plugin_copy.os, "rename", failing_rename)
    with pytest.raises(OSError):
        plugin_copy.copy_plugin_tree(source, dest)
    assert (dest / "previous.txt").read_text(encoding="utf-8") == "old copy"


def test_every_attach_path_holds_the_one_attach_lock(tmp_path, monkeypatch):
    """A writer that holds ``attach.ATTACH_LOCK`` keeps another thread's attach waiting."""
    home = tmp_path / "agent"
    home.mkdir()
    entered = threading.Event()
    monkeypatch.setattr(plugin_copy, "_needs_copy", lambda _dest: False)

    def other_attach() -> None:
        attach.attach_hermes(home)
        entered.set()

    with attach.ATTACH_LOCK:
        thread = threading.Thread(target=other_attach)
        thread.start()
        assert not entered.wait(0.3)   # still waiting on the lock
    thread.join()
    assert entered.is_set()
