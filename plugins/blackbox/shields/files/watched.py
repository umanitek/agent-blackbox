"""What a watched folder's scan found, reported by whoever scans it, worded by File Shield.

Blackbox Desktop's add-on fingerprints the files of the person's WATCHED folders (not protected
ones: those are refused, see :mod:`.protect`) and finds two kinds of news: a new file arrived, and
a file the verified threat graph lists as known-bad. It reports each as a typed :class:`WatchedFile`
through :func:`report`; File Shield turns them into alerts in its own words (:mod:`.alerts`), and
``notify`` shows them like every other notice. The add-on never words a notification itself
(engine rule, Amos 2026-11-22: every notification comes from the core; Desktop only delivers).

Kept in memory, newest first, bounded (:data:`MAX_KEPT`): the reporter and the notifier run in the
same dashboard process, and the notifier reads every couple of seconds. A dashboard restart drops
what was not yet read — the add-on's own records keep the file list.

Usage (by a scanner)::

    from plugins.blackbox.shields.files import watched
    watched.report([watched.WatchedFile(kind="file-new", ts=now, path="/Users/me/Downloads/x.dmg")])
    watched.recent(50)       # newest first
"""

from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass
from typing import Iterable

#: A new file in a watched folder, and a file the verified graph lists as known-bad.
KINDS = ("file-new", "file-known-bad")
MAX_KEPT = 200
MAX_PATH_CHARS = 1024
_SHA256_CHARS = 64


@dataclass(frozen=True)
class WatchedFile:
    """One scan finding. *path*: the file's full path (shown inside the app only, never on the
    lock screen). *sha256*: its fingerprint, for a known-bad file."""

    kind: str
    ts: float
    path: str
    sha256: str = ""


_lock = threading.Lock()
_kept: deque[WatchedFile] = deque(maxlen=MAX_KEPT)


def _valid(item: WatchedFile) -> bool:
    sha = item.sha256
    return (item.kind in KINDS and isinstance(item.ts, (int, float)) and item.ts > 0
            and isinstance(item.path, str) and 0 < len(item.path) <= MAX_PATH_CHARS and "\x00" not in item.path
            and (not sha or (len(sha) == _SHA256_CHARS and all(c in "0123456789abcdef" for c in sha))))


def report(items: Iterable[WatchedFile]) -> int:
    """Keeps each valid *item* (an invalid one is dropped: a scanner's mistake costs only that
    item). Answers how many were kept."""
    kept = [item for item in items if isinstance(item, WatchedFile) and _valid(item)]
    with _lock:
        for item in sorted(kept, key=lambda found: found.ts):
            _kept.appendleft(item)
    return len(kept)


def recent(limit: int = 50) -> list[WatchedFile]:
    """The newest findings first."""
    with _lock:
        return list(_kept)[:max(0, limit)]


def reset() -> None:
    """Forget everything (tests)."""
    with _lock:
        _kept.clear()
