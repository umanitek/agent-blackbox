"""Reading a small settings file safely on the hot path — one bounded reader.

A detector that reads a settings file (the Solana CLI's ``config.yml``, a Firefox
profile's ``prefs.js``) runs inside the pre-tool hook, so the read must always
come back quickly. A plain ``open()`` cannot promise that for a path that is not
a regular file, and a size checked before opening may no longer describe what
gets opened. :func:`read_small_text` asks the open descriptor itself:

* it opens with ``O_RDONLY | O_NONBLOCK`` (so opening never waits), plus
  ``O_NOFOLLOW`` when the caller asks and the platform has it (the last path
  part may then not be a symlink — for paths built from names in an agent's call);
* it checks ``fstat(...)`` is a regular file on that same descriptor;
* it reads at most ``max_bytes + 1`` bytes, and anything longer is refused.

Every failure (missing, unreadable, not a regular file, too large) answers None
and is logged at DEBUG — never raised. Windows has no named pipes in the file
system and no ``O_NONBLOCK``; there the call is the plain bounded read with the
regular-file check.

Usage::

    text = read_small_text(prefs_path, 8 * 1024 * 1024, nofollow=True)
    if text is None:
        ...   # could not read it: the caller decides what "could not tell" means
"""

from __future__ import annotations

import logging
import os
import stat
from typing import Optional

logger = logging.getLogger(__name__)

_BASE_FLAGS = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)


def read_small_text(path: str, max_bytes: int, *, nofollow: bool = False) -> Optional[str]:
    """The text of the regular file at *path* (UTF-8, a leading BOM dropped, bad bytes
    replaced), or None when it is missing, unreadable, not a regular file, a symlink
    under *nofollow*, or longer than *max_bytes*."""
    flags = _BASE_FLAGS | (getattr(os, "O_NOFOLLOW", 0) if nofollow else 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        logger.debug("blackbox: cannot open %s: %s", path, exc)
        return None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            logger.debug("blackbox: %s is not a regular file; not read", path)
            return None
        data = _read_up_to(descriptor, max_bytes + 1)
    except OSError as exc:
        logger.debug("blackbox: cannot read %s: %s", path, exc)
        return None
    finally:
        os.close(descriptor)
    if len(data) > max_bytes:
        logger.debug("blackbox: %s is larger than %d bytes; not read", path, max_bytes)
        return None
    return data.decode("utf-8-sig", errors="replace")


def _read_up_to(descriptor: int, limit: int) -> bytes:
    """At most *limit* bytes from *descriptor* (``os.read`` may return fewer per call)."""
    chunks: list[bytes] = []
    remaining = limit
    while remaining > 0:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


from .probe_stamp import ProbeStamp   # the stamp shares this package: a small file read on the hot path
from .atomic_write import atomic_write, create_once   # and the one torn-free write, and the create-if-absent for secrets
from .json_files import read_json_object   # and the one "a JSON object, or nothing" read
from .jsonl import append_line, read_jsonl   # and the one log-file append and read
from .locking import file_lock   # and the one cross-process lock
__all__ = ["ProbeStamp", "append_line", "atomic_write", "create_once", "file_lock", "read_json_object", "read_jsonl", "read_small_text"]   # the surface other modules may import
