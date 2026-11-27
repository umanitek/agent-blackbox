"""The one attach lock: in one process, only one writer changes agents' plugin folders and configs at a time.

Every path that attaches or detaches (the dashboard's background rescan and its manual refresh, its
per-agent switch, "protect every agent", ``blackbox attach``, the guard's auto-attach) writes the same
``plugins/blackbox`` folders and ``config.yaml`` files. Two of them at once used to race on the plugin
copy's staging folders and left an agent's plugin folder missing (review 2026-11-26, LES-167). Each
public writer of this package takes :data:`ATTACH_LOCK`; a caller that must decide and act as one
step (the rescan: discover, choose, attach) takes it around the whole step. It is re-entrant, so a
writer that calls another writer does not deadlock.

Other processes (a CLI ``blackbox attach`` next to the dashboard) are not held by it; the plugin
copy's unique staging names and its roll-back keep those safe (:mod:`.plugin_copy`).

Usage::

    from . import serial

    @serial.serialized
    def attach_hermes(home, *, dry_run=False): ...

    with attach.ATTACH_LOCK:        # the dashboard's rescan: one decision, one write
        ...
"""

from __future__ import annotations

import functools
import threading
from typing import Callable, TypeVar

T = TypeVar("T")

#: Held by every attach / detach writer in this process (re-entrant).
ATTACH_LOCK = threading.RLock()


def serialized(function: Callable[..., T]) -> Callable[..., T]:
    """Run *function* while holding :data:`ATTACH_LOCK`."""
    @functools.wraps(function)
    def locked(*args, **kwargs) -> T:
        with ATTACH_LOCK:
            return function(*args, **kwargs)
    return locked
