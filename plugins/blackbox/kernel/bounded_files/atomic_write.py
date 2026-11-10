"""Write a small file so a reader never sees a torn one — the one implementation.

``os.replace`` is atomic on the same filesystem: the text goes to a sibling temp
file (unique per process and call) and is renamed over *path*, so a concurrent
reader — another agent process, the dashboard — sees either the old or the new
complete file, never a half-written one. 31 files carried their own copy of this
(three spellings, one with 0600) before 2026-10-22; now they share this one.

Usage::

    atomic_write(path, json.dumps(state))              # a plain file
    atomic_write(path, text, mode=0o600)               # a secret: created 0600, never world-readable
    atomic_write(path, text, mode=0o600, durable=True) # …and on the disk before the rename (fsync)
"""

from __future__ import annotations

import contextlib
import os
import secrets
from pathlib import Path
from typing import Optional

#: What ``open(path, "w")`` asks for; the process umask still applies.
_DEFAULT_MODE = 0o666


def atomic_write(path: Path, text: str, *, mode: Optional[int] = None, durable: bool = False) -> None:
    """Write *text* (UTF-8) to *path* via temp file + rename; parent folders are created.

    *mode* — the permission bits the file is created with from the start (``0o600`` for a
    secret); None keeps the process default. *durable* — also flush the bytes to the disk
    before the rename, for a record that must survive a power cut (a key, a signing counter).
    The temp file is new every call (``O_EXCL``) and is removed when the write fails.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}.{secrets.token_hex(6)}")
    try:
        descriptor = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _DEFAULT_MODE if mode is None else mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            if durable:
                handle.flush()
                os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
