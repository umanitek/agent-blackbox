"""Read a small JSON state file — the one reader for "an object, or nothing".

Most of Blackbox's own state files hold one JSON object, and most readers treat a
missing file, an unreadable one and one that is not an object the same way: there is
no usable state. Ten modules spelled that out by hand (try / decode / isinstance), with
small differences in which errors they caught. :func:`read_json_object` is that rule once.

NOT for a store that must tell a damaged file from an absent one (the curator's roster,
the root signer, the lab's attempt counter): those fail closed on damage and keep their
own read.

Usage::

    state = read_json_object(path) or {}       # nothing saved and unreadable mean the same
    record = read_json_object(path)            # None: no readable record
    if record is None:
        ...
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional


def read_json_object(path: Path) -> Optional[dict[str, Any]]:
    """The JSON object stored in *path* (UTF-8, a leading BOM dropped), or None when the file
    is missing, unreadable, not JSON, or JSON that is not an object. Never raises."""
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError, RecursionError):
        return None
    return data if isinstance(data, dict) else None
