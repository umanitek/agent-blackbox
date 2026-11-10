"""Line-per-record log files (JSONL) — the one append and the one read.

Blackbox keeps its audit trail, its findings and several curator logs as one JSON
object per line. Five modules each wrote "open for append, write one line" and "read
the lines back, skip the damaged ones", with different choices: only one flushed to
the disk, the curator logs were 0600 and the audit logs were not, and one reader
crashed on a line that was valid JSON but not an object.

* :func:`append_line` adds one line. ``O_APPEND`` makes a single short write land
  whole even when several agent processes write the same log. The caller serialises
  the record, because the logs differ in how (key order, non-ASCII text).
* :func:`read_jsonl` returns every line that is a JSON object, oldest first. A blank,
  damaged or non-object line is skipped; a missing or unreadable file is an empty log.

Usage::

    append_line(path, json.dumps(row, sort_keys=True), mode=0o600)   # a private log
    append_line(path, text, mode=0o600, durable=True)                # …that must survive a power cut
    for row in read_jsonl(path):
        ...
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional

#: What ``open(path, "a")`` asks for; the process umask still applies.
_DEFAULT_MODE = 0o666


def append_line(path: Path, line: str, *, mode: Optional[int] = None, durable: bool = False) -> None:
    """Append *line* and a newline to *path* (UTF-8); parent folders are created.

    *mode* — the permission bits when the file is created (``0o600`` for a private log);
    None keeps the process default. *durable* — flush the bytes to the disk before
    returning. Raises ``OSError`` when the line cannot be written.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, _DEFAULT_MODE if mode is None else mode)
    with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
        handle.write(line + "\n")
        if durable:
            handle.flush()
            os.fsync(handle.fileno())


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Every line of *path* that is a JSON object, in file order. Never raises: a missing or
    unreadable file is ``[]``; a blank, damaged or non-object line is skipped."""
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except (OSError, ValueError):
        return []
    rows: list[dict[str, Any]] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows
