"""What an add-on asks ``blackbox uninstall`` to remove for it: the files, Keychain items and
preferences a companion app keeps — declared in its manifest, checked here, removed with Blackbox.

A companion app dragged to the Trash gets no word from the operating system, so it can not clean up
after itself; its add-on's manifest (``blackbox-addon.json``, ``kernel.addons``) may say what it
leaves, per operating system::

    {"extends": "blackbox",
     "cleanup": {"macos": {"app_id": "com.example.companion",
                           "paths": ["~/Library/Caches/com.example.companion", …],
                           "keychain": [{"service": "com.example.companion", "account": "token"}],
                           "preferences_domain": "com.example.companion"}}}

Read while the plan is built, BEFORE the add-on folders are deleted, and never trusted: every item
is checked and anything that fails is skipped and named in the plan —

* ``app_id`` must be a reverse-DNS name (``com.example.companion``), never in Apple's own namespace;
* a path only directly under ``~/Library/{Application Support, Caches, WebKit, HTTPStorages,
  Preferences, Saved Application State, Logs}/`` and named exactly after ``app_id`` (a
  ``Preferences`` file ``<app_id>.plist``, a ``Saved Application State`` folder
  ``<app_id>.savedState``); no ``..``, no wildcard, and no link on the way or at the end;
* a Keychain item only when its service is ``app_id``; the preferences domain only ``app_id``.

The items are shown in the plan and in ``--dry-run``, then each is removed; a failure is reported
and the next one is still tried. Keychain items and preferences go through the system's own tools
(``setup/platform``).

Usage::

    plan = cleanup_for([folder, …])        # CleanupPlan: items, skipped (with why)
    lines = describe(plan); report = []
    remove(plan, run, report)
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Optional, Sequence

from ..kernel import addons, os_layout
from ..kernel.bounded_files import read_small_text
from . import platform

#: The folders under ``~/Library`` a companion app's data may be in, and how its entry is named there.
LIBRARY_FOLDERS = {"Application Support": "{id}", "Caches": "{id}", "WebKit": "{id}", "HTTPStorages": "{id}",
                   "Preferences": "{id}.plist", "Saved Application State": "{id}.savedState", "Logs": "{id}"}
_REVERSE_DNS = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")
#: Never another vendor's own namespace (an app of the system itself).
_FOREIGN = ("com.apple.",)
#: The most items of each kind one manifest may ask for.
MAX_ITEMS = 20
Runner = Callable[[Sequence[str]], int]


@dataclass(frozen=True)
class CleanupItem:
    """One thing to remove: ``kind`` ``path`` | ``keychain`` | ``preferences``, and what it names."""

    kind: str
    target: str
    account: str = ""

    def words(self) -> str:
        if self.kind == "keychain":
            return f"the Keychain item {self.target} / {self.account}"
        if self.kind == "preferences":
            return f"the preferences {self.target}"
        return self.target


@dataclass(frozen=True)
class CleanupPlan:
    """What the add-ons asked to have removed, checked: ``items`` to remove, ``skipped`` with why."""

    items: tuple[CleanupItem, ...] = ()
    skipped: tuple[str, ...] = ()


def _manifest(folder: Path) -> dict[str, Any]:
    text = read_small_text(str(folder / addons.MANIFEST), addons.MAX_MANIFEST_BYTES, nofollow=True)
    try:
        data = json.loads(text) if text else {}
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _checked_path(raw: Any, app_id: str, home: Path) -> tuple[Optional[Path], str]:
    """``(path, "")`` when *raw* is an allowed place for *app_id*, else ``(None, why)``."""
    text = str(raw or "")
    if not text or any(mark in text for mark in "*?[") or ".." in Path(text).parts:
        return None, f"{text!r}: no wildcards or '..'"
    path = Path(os.path.expanduser(text)) if text.startswith("~") else Path(text)
    library = home / "Library"
    if path.parent.parent != library or path.parent.name not in LIBRARY_FOLDERS:
        return None, f"{text}: only directly under ~/Library/{{{', '.join(LIBRARY_FOLDERS)}}}"
    if path.name != LIBRARY_FOLDERS[path.parent.name].format(id=app_id):
        return None, f"{text}: not named after {app_id}"
    if os.path.realpath(path.parent) != os.path.join(os.path.realpath(library), path.parent.name) or path.is_symlink():
        return None, f"{text}: a link leads out of ~/Library"
    return path, ""


def _from(folder: Path, home: Path) -> tuple[list[CleanupItem], list[str]]:
    """The checked items one add-on's manifest asks for, and what was skipped."""
    block = (_manifest(folder).get("cleanup") or {})
    block = block.get(os_layout.os_folder()) if isinstance(block, dict) else None
    if not isinstance(block, dict):
        return [], []
    app_id = str(block.get("app_id") or "")
    if not _REVERSE_DNS.match(app_id) or app_id.startswith(_FOREIGN):
        return [], [f"{folder.name}: app_id {app_id!r} is not a reverse-DNS name of its own — nothing of it removed"]
    items, skipped = [], []
    for raw in list(block.get("paths") or [])[:MAX_ITEMS]:
        path, why = _checked_path(raw, app_id, home)
        (items.append(CleanupItem("path", str(path))) if path else skipped.append(f"{folder.name}: {why}"))
    for entry in list(block.get("keychain") or [])[:MAX_ITEMS]:
        service = str(entry.get("service") or "") if isinstance(entry, dict) else ""
        account = str(entry.get("account") or "") if isinstance(entry, dict) else ""
        if service != app_id or not account or "\0" in account:
            skipped.append(f"{folder.name}: Keychain item {service!r}: only the service {app_id}")
            continue
        items.append(CleanupItem("keychain", service, account))
    domain = block.get("preferences_domain")
    if domain:
        (items.append(CleanupItem("preferences", app_id)) if domain == app_id
         else skipped.append(f"{folder.name}: preferences {domain!r}: only {app_id}"))
    return items, skipped


def cleanup_for(folders: Iterable[Path], home: Optional[Path] = None) -> CleanupPlan:
    """What every add-on in *folders* asks to have removed, checked (see the module doc)."""
    home = Path(os.path.normpath(home or Path.home()))
    items: list[CleanupItem] = []
    skipped: list[str] = []
    for folder in folders:
        found, refused = _from(Path(folder), home)
        items += [item for item in found if item not in items]
        skipped += refused
    return CleanupPlan(tuple(items), tuple(skipped))


def describe(plan: CleanupPlan) -> list[str]:
    """The plan's lines for an add-on's leftovers."""
    lines = [f"  - remove what an add-on left: {item.words()}" for item in plan.items]
    return lines + [f"  - NOT removed (the add-on's manifest asked for more than it may): {why}" for why in plan.skipped]


def remove(plan: CleanupPlan, run: Runner, report: list[str]) -> None:
    """Removes each item; a failure is reported and the next one still tried."""
    import shutil
    for item in plan.items:
        try:
            if item.kind == "keychain":
                done = platform.delete_keychain_item(item.target, item.account, run)
            elif item.kind == "preferences":
                done = platform.delete_preferences(item.target, run)
            else:
                path = Path(item.target)
                if path.is_symlink() or not path.exists():
                    continue   # gone already, or made a link since the plan: never followed
                shutil.rmtree(path) if path.is_dir() else path.unlink()
                done = True
        except OSError as error:
            report.append(f"could not remove {item.words()}: {error.strerror or error}")
            continue
        report.append(f"removed {item.words()}" if done else f"could not remove {item.words()}")


__all__ = ["LIBRARY_FOLDERS", "CleanupItem", "CleanupPlan", "cleanup_for", "describe", "remove"]
