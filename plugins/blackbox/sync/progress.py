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
) -> dict[str, Any]:
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



def apply_completion_contract(durable_progress: dict, result: dict) -> None:
    """Let the node's own completion answer decide ``snapshot_complete`` in *durable_progress*.

    Newer DKG releases report a recovery request's completion contract directly
    (``durableComplete`` in *result*); :func:`read_durable_progress`'s log parsing is
    the compatibility fallback for 10.0.9, used only when the node does not say.
    Apply it to the read scoped to THIS invocation (``after=`` the cursor): completion is
    decided there, never from the whole log, whose lines may come from an earlier run.
    """
    if result.get("durableComplete") is True:
        durable_progress["snapshot_complete"] = True
    elif result.get("durableComplete") is False:
        durable_progress["snapshot_complete"] = False

_RECONCILE_PASS_RE = re.compile(
    r'^(?P<logged_at>\S+ \S+) .*VM reconcile pass timing for "(?P<graph>[^"]+)".*\bpending=(?P<pending>\d+)',
    re.MULTILINE,
)
# Beside each pass the node logs the graph's on-chain size: ``reconcile <graph>: watermark A -> B
# (head=N, …, pending=M)``. After a restart the node re-checks assets it already holds, so
# ``pending`` then counts held assets too; ``head`` is the graph's real size.
_RECONCILE_HEAD_RE = re.compile(r"^\S+ \S+ .*\breconcile (?P<graph>.+?): watermark \d+ -> \d+ \(head=(?P<head>\d+)", re.MULTILINE)
# The node logs one reconcile pass every minute or two; the last megabyte of
# its log always holds the newest one without reading a multi-GB file.
_RECONCILE_TAIL_BYTES = 1_000_000


@dataclass(frozen=True)
class RecoveryBacklog:
    """The node's own count of verified assets it knows exist on chain but
    has not yet downloaded, from its newest reconcile pass.

    ``pending`` — the pass's reconcile backlog; ``logged_at`` — the node's timestamp
    of that pass (``YYYY-MM-DD HH:MM:SS``), so callers can show its age; ``head`` — the
    graph's on-chain size from the same pass, None when the log does not state it.
    """

    pending: int
    logged_at: str
    head: Optional[int] = None

    def to_fetch(self, held: int) -> int:
        """Assets still missing when the node holds *held*: ``head - held`` when the size is
        known (a re-check of held assets after a restart is not missing data), else ``pending``."""
        return max(0, self.head - held) if self.head is not None else self.pending


def read_recovery_backlog(dkg_home: str, context_graph_id: str) -> Optional[RecoveryBacklog]:
    """Return the newest reconcile pass's backlog for ``context_graph_id``.

    DKG 10.0.21's native VM recovery logs ``VM reconcile pass timing for
    "<graph>": … pending=N`` after each pass — the only place the node states
    how many verified assets exist that it has not downloaded yet (no API
    exposes the on-chain total). Downloaded + pending = the graph's full size.
    None when the log is missing or holds no pass for this graph ("could not
    tell" — never read as zero pending).
    """
    path = Path(dkg_home) / "daemon.log"
    try:
        with path.open("rb") as handle:
            handle.seek(max(0, path.stat().st_size - _RECONCILE_TAIL_BYTES))
            text = handle.read().decode("utf-8", errors="replace")
    except OSError:
        return None
    newest = None
    for match in _RECONCILE_PASS_RE.finditer(text):
        if match.group("graph") == context_graph_id:
            newest = match
    if newest is None:
        return None
    heads = [int(match.group("head")) for match in _RECONCILE_HEAD_RE.finditer(text) if match.group("graph") == context_graph_id]
    return RecoveryBacklog(pending=int(newest.group("pending")), logged_at=newest.group("logged_at"),
                           head=heads[-1] if heads else None)
