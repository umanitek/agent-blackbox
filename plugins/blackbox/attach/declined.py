"""The agents the operator switched protection OFF for — so no automatic sweep switches it back on.

Blackbox re-attaches every agent it finds, on a timer, as a self-heal: the dashboard's background
rescan (every minute), its manual refresh, and the guard's periodic auto-attach. Without a record of
the operator's choice, unticking an agent in the dashboard's Local agents window (or running
``blackbox detach``) was undone within a minute. This file is that record.

The rule, in one place:

* a successful ``detach_hermes`` / ``detach_openclaw`` ADDS its target (the operator said no);
* a successful ``attach_hermes`` / ``attach_openclaw`` REMOVES it (the operator said yes again —
  the dashboard toggle, or ``blackbox attach``);
* every AUTOMATIC sweep skips listed targets (:func:`is_declined`); an explicit command does not.

Stored as ``$BLACKBOX_HOME/attach_declined.json`` (``{"targets": ["hermes:/path", …]}``), written
atomically. Fail-open: an unreadable file reads as "nothing declined" and is logged once — the
worst case is the old behaviour (a re-attach), never an agent left unprotected by mistake.

Pattern: Global Object (one module-level store; one lock serialises this process's
read-modify-write; a write from another process between our read and write can lose one entry,
which the next detach or attach rewrites).

Usage::

    from . import declined

    @declined.remembers("hermes", switched_off=True)    # a successful detach records the switch-off
    def detach_hermes(home, *, dry_run=False, ...): ...

    if declined.is_declined("openclaw", workspace): ...   # an automatic sweep skips it
"""

from __future__ import annotations

import functools
import json
import logging
import threading
from pathlib import Path
from typing import Any, Callable

from ..kernel import constants
from ..kernel.yaml_files import atomic_write

logger = logging.getLogger(__name__)

#: The file's name under ``$BLACKBOX_HOME``.
FILE_NAME = "attach_declined.json"
_lock = threading.Lock()


def same_path(path: str | Path) -> str:
    """One spelling per folder, so ``~/x``, ``/home/me/x/`` and a symlink to it compare equal."""
    path = Path(str(path)).expanduser()
    try:
        return str(path.resolve())
    except OSError:
        return str(path)


def _key(kind: str, target: str | Path) -> str:
    """One spelling per target: the kind, then the folder as :func:`same_path` spells it."""
    return f"{str(kind).lower()}:{same_path(target)}"


def _keys(kind: str, target: str | Path) -> set[str]:
    """Every spelling a record of *target* may be stored under: :func:`_key`, and the one records
    were written in before it (``~`` expanded only) — a switch-off recorded then must still hold."""
    return {_key(kind, target), f"{str(kind).lower()}:{Path(str(target)).expanduser()}"}


def _path() -> Path:
    return constants.blackbox_home() / FILE_NAME


def _read() -> set[str]:
    try:
        data = json.loads(_path().read_text(encoding="utf-8-sig"))
    except FileNotFoundError:
        return set()
    except (OSError, ValueError):
        logger.warning("blackbox.attach: %s could not be read; treating no agent as switched off", FILE_NAME,
                       exc_info=True)
        return set()
    targets = data.get("targets") if isinstance(data, dict) else None
    return {str(item) for item in targets} if isinstance(targets, list) else set()


def _write(keys: set[str]) -> None:
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(path, json.dumps({"targets": sorted(keys)}, indent=1) + "\n")


def is_declined(kind: str, target: str | Path) -> bool:
    """Whether the operator switched protection off for this target (automatic sweeps skip it)."""
    with _lock:
        return bool(_keys(kind, target) & _read())


def _change(kind: str, target: str | Path, *, present: bool) -> None:
    """Record (*present*) or forget the operator's switch-off. Logged, never raised, on a write error."""
    spellings = _keys(kind, target)
    with _lock:
        keys = _read()
        if bool(spellings & keys) == present:
            return
        keys = keys | {_key(kind, target)} if present else keys - spellings
        try:
            _write(keys)
        except OSError:
            logger.warning("blackbox.attach: could not save %s", FILE_NAME, exc_info=True)


def remembers(kind: str, *, switched_off: bool) -> Callable[[Callable[..., dict[str, Any]]], Callable[..., dict[str, Any]]]:
    """Decorate an attach (``switched_off=False``) or detach (``switched_off=True``) of one
    target: after a real (not ``dry_run``) call whose report says ``ok``, record or forget the
    operator's switch-off for that target. The wrapped function's first argument is the target."""
    def wrap(function: Callable[..., dict[str, Any]]) -> Callable[..., dict[str, Any]]:
        @functools.wraps(function)
        def recorded(target: Path, *args: Any, dry_run: bool = False, **kwargs: Any) -> dict[str, Any]:
            report = function(target, *args, dry_run=dry_run, **kwargs)
            if not dry_run and report.get("ok"):
                _change(kind, target, present=switched_off)
            return report
        return recorded
    return wrap
