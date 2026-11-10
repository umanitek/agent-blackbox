"""One ruleset refresh at a time, across threads and across agent processes.

``_ruleset_refresh_lock`` guarantees one refresh at a time across every agent
process sharing a ``$BLACKBOX_HOME``; ``_refresh_lock`` is the in-process half.
The cross-process half is the kernel's one file lock (``kernel.bounded_files.file_lock``).
"""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
import os
import threading
from typing import Iterator
from ..kernel.bounded_files import file_lock
from . import disk_cache

_refresh_lock = threading.Lock()


@contextmanager
def _ruleset_refresh_lock(*, blocking: bool) -> Iterator[bool]:
    """Serialize expensive VM reads across threads and Blackbox processes.

    Yields whether the caller may refresh. Where the lock FILE cannot be used (not
    writable, no usable lock) a POSIX system keeps the in-process guard alone — refreshes
    are fail-open by design — and Windows answers False, as before."""
    if not _refresh_lock.acquire(blocking=blocking):
        yield False
        return
    try:
        with ExitStack() as held_lock:
            try:
                held = held_lock.enter_context(file_lock(disk_cache._lock_path(), blocking=blocking))
            except Exception:   # health: allow BLE001 -- no usable lock file: POSIX keeps the in-process guard (fail-open)
                held = os.name != "nt"
            yield held
    finally:
        _refresh_lock.release()
