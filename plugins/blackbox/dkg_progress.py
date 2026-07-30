"""Read durable-sync progress emitted by the managed DKG daemon."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional


_DURABLE_PROGRESS_RE = re.compile(
    r'Rootless durable progress for "(?P<graph>[^"]+)".*?'
    r'safe offset (?P<previous>\d+)->(?P<current>\d+) of (?P<expected>\d+)'
    r' \(raw (?P<raw>\d+)\)'
)


@dataclass(frozen=True)
class DurableProgressCursor:
    """A stable boundary in the managed daemon log."""

    device: int
    inode: int
    offset: int


def capture_durable_progress_cursor(dkg_home: str) -> Optional[DurableProgressCursor]:
    """Capture the current end of the daemon log, if it exists."""
    path = Path(dkg_home) / "daemon.log"
    try:
        stat = path.stat()
    except OSError:
        return None
    return DurableProgressCursor(
        device=stat.st_dev,
        inode=stat.st_ino,
        offset=stat.st_size,
    )


def read_durable_progress(
    dkg_home: str,
    context_graph_id: str,
    *,
    after: Optional[DurableProgressCursor] = None,
) -> Dict[str, Any]:
    """Return the latest rootless durable-sync window for ``context_graph_id``.

    ``current_triples`` is transfer progress and may include the raw tail of an
    incomplete exact graph. ``safe_current_triples`` contains only complete,
    verified graph boundaries and is therefore the completion signal callers
    should use after a successful catch-up response. When ``after`` is given,
    only progress emitted after that cursor is considered; a rotated log starts
    a fresh window.
    """
    path = Path(dkg_home) / "daemon.log"
    try:
        with path.open("rb") as handle:
            stat = path.stat()
            start = max(0, stat.st_size - 4_000_000)
            if after is not None and (
                stat.st_dev == after.device and stat.st_ino == after.inode
            ):
                # A smaller file was truncated in place and therefore starts a
                # new log generation. Otherwise exclude all pre-request lines.
                if stat.st_size >= after.offset:
                    start = max(start, after.offset)
            handle.seek(start)
            text = handle.read().decode("utf-8", errors="replace")
    except OSError:
        return {}

    matches = []
    for match in _DURABLE_PROGRESS_RE.finditer(text):
        if match.group("graph") != context_graph_id:
            continue
        # A previous implementation reset only on 0->0. Real bounded passes
        # begin 0->positive, so retaining earlier matches made a restarted
        # transfer look permanently 100% complete.
        if int(match.group("previous")) == 0:
            matches = []
        matches.append(match)
    if not matches:
        return {}

    expected = int(matches[-1].group("expected"))
    if expected <= 0:
        return {}
    same_manifest = [
        match for match in matches if int(match.group("expected")) == expected
    ]
    safe_current = max(int(match.group("current")) for match in same_manifest)
    raw_current = max(int(match.group("raw")) for match in same_manifest)
    safe_current = max(0, min(safe_current, expected))
    current = max(0, min(max(safe_current, raw_current), expected))
    return {
        "current_triples": current,
        "safe_current_triples": safe_current,
        "expected_triples": expected,
        "progress_percent": round((current / expected) * 100, 1),
        "snapshot_complete": safe_current >= expected,
    }
