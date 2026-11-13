"""One cross-process file lock — the platform branches, written once.

Several agent processes share one ``$BLACKBOX_HOME``. Work that must happen in one of them
at a time (a ruleset refresh, a sync, trimming a log) holds an exclusive lock on a small
lock file: ``fcntl.flock`` on POSIX, a one-byte ``msvcrt`` lock on Windows. Two modules
each wrote those branches by hand and already disagreed about Windows (one retried for a
bounded time, the other tried once).

:func:`file_lock` is a context manager that yields whether the lock is held:

* ``True`` — this process holds it until the block ends;
* ``False`` — another process holds it and waiting was not asked for, or ran out.

A lock file that cannot be opened, or a platform that cannot lock, raises ``OSError``: the
caller decides whether its work fails open (go on, unlocked) or closed (stop).

The lock is tied to the open file, so the system releases it when the process dies; a
crashed holder never blocks the others.

Usage::

    with file_lock(home / "sync-window.lock", blocking=False) as held:
        if not held:
            return "already running"
        ...
    with file_lock(path, timeout_s=0.5) as held:      # wait, but never for long
        ...
"""

from __future__ import annotations

import errno
import os
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

#: How long a blocking Windows lock keeps trying when no *timeout_s* is given (Windows has no
#: blocking byte lock that waits indefinitely without raising).
WINDOWS_LOCK_TIMEOUT_S = 30.0
#: The pause between attempts while waiting.
LOCK_POLL_S = 0.05
#: ``locking()`` errors that mean "someone else holds it" (anything else: not acquired, no retry).
_CONTENDED = frozenset({errno.EACCES, errno.EAGAIN, errno.EDEADLK})


def _is_windows() -> bool:
    return os.name == "nt"


@contextmanager
def file_lock(path: Path, *, blocking: bool = True, timeout_s: Optional[float] = None) -> Iterator[bool]:
    """Hold the exclusive cross-process lock on *path* (created with its folders) for the block.

    *blocking* False tries once. *blocking* True waits: forever on POSIX when *timeout_s* is
    None, otherwise at most *timeout_s* seconds (Windows: :data:`WINDOWS_LOCK_TIMEOUT_S` when
    None). Yields whether the lock is held. Raises ``OSError`` when the lock file cannot be
    opened or locked for a reason other than another holder.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(path, "a+b")  # windows-footgun: ok - a binary lock file, never text
    held = False
    try:
        if _is_windows():
            if path.stat().st_size == 0:      # a byte lock needs a byte to lock
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            held = acquire_windows_lock(handle, blocking=blocking,
                                        timeout_s=WINDOWS_LOCK_TIMEOUT_S if timeout_s is None else timeout_s)
        else:
            held = _acquire_posix_lock(handle, blocking=blocking, timeout_s=timeout_s)
        yield held
    finally:
        try:
            if held:
                _release(handle)
        finally:
            handle.close()


def _acquire_posix_lock(handle: Any, *, blocking: bool, timeout_s: Optional[float]) -> bool:
    import fcntl

    if blocking and timeout_s is None:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        return True
    deadline = time.monotonic() + max(0.0, timeout_s or 0.0)
    while True:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            remaining = deadline - time.monotonic()
            if not blocking or remaining <= 0:
                return False
            time.sleep(min(LOCK_POLL_S, remaining))


def acquire_windows_lock(
    handle: Any,
    *,
    blocking: bool,
    msvcrt_module: Any = None,
    timeout_s: float = WINDOWS_LOCK_TIMEOUT_S,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> bool:
    """Acquire one Windows byte lock within a bounded contention window (*msvcrt_module*,
    *monotonic* and *sleep* are injectable for tests on other platforms)."""
    if msvcrt_module is None:  # pragma: no cover - imported only on Windows
        import msvcrt as msvcrt_module

    deadline = monotonic() + max(0.0, timeout_s)
    while True:
        handle.seek(0)
        try:
            msvcrt_module.locking(handle.fileno(), msvcrt_module.LK_NBLCK, 1)
            return True
        except OSError as exc:
            if not blocking or exc.errno not in _CONTENDED:
                return False
            remaining = deadline - monotonic()
            if remaining <= 0:
                return False
            sleep(min(LOCK_POLL_S, remaining))


def _release(handle: Any) -> None:
    if _is_windows():  # pragma: no cover - exercised on Windows
        import msvcrt

        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
