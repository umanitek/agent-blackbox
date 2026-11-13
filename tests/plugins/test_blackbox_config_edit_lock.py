"""Every Blackbox change to a config.yaml happens under one lock.

A change is read, change, write back. A dashboard settings save held a lock for
that; attach, detach, the chat profile, setup and uninstall did not. The
dashboard runs automatic attach in the same process as its saves, so one could
read the file, the other write it, and the first then write its older copy
back over the change. Now every such function is marked ``edits_config`` and
they all wait for each other.
"""

from __future__ import annotations

import ast
import threading
from pathlib import Path

from plugins.blackbox.kernel import settings, yaml_files

PLUGIN = Path(yaml_files.__file__).resolve().parents[1]
#: Calls that write a whole config file back.
WRITE_CALLS = {"dump_yaml", "save_config"}


def _decorator_names(function: ast.AST) -> set[str]:
    names = set()
    for decorator in getattr(function, "decorator_list", []):
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        names.add(target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", ""))
    return names


def _unlocked_writers() -> list[str]:
    """``file::function`` for every function that writes a config back without the lock."""
    found = []
    for path in sorted(PLUGIN.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for function in ast.walk(tree):
            if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)) or function.name in WRITE_CALLS:
                continue
            writes = any(isinstance(node, ast.Call)
                         and (getattr(node.func, "attr", "") or getattr(node.func, "id", "")) in WRITE_CALLS
                         for node in ast.walk(function))
            if writes and "edits_config" not in _decorator_names(function):
                found.append(f"{path.relative_to(PLUGIN)}::{function.name}")
    return found


def test_every_function_that_writes_a_config_back_holds_the_edit_lock():
    assert _unlocked_writers() == []


def test_a_settings_save_waits_for_another_config_edit_in_this_process(monkeypatch):
    inside, release, saved = threading.Event(), threading.Event(), threading.Event()

    @yaml_files.edits_config
    def slow_edit() -> None:
        inside.set()
        assert release.wait(10)

    monkeypatch.setattr(settings, "_persist_locked", lambda updates: saved.set() or True)
    editor = threading.Thread(target=slow_edit)
    editor.start()
    assert inside.wait(10)
    saver = threading.Thread(target=settings._persist, args=({"mode": "block"},))
    saver.start()
    assert not saved.wait(0.3)          # the save is held while the other edit is in progress
    release.set()
    editor.join(10)
    assert saved.wait(10)               # and goes through once it ends
    saver.join(10)


def test_an_edit_may_call_another_edit_on_the_same_thread():
    @yaml_files.edits_config
    def inner() -> str:
        return "done"

    @yaml_files.edits_config
    def outer() -> str:
        return inner()

    assert outer() == "done"
